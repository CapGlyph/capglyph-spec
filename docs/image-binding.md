# Image Binding — Geometry, Lattice, and Normalization

**Spec:** 1.0.0 · **Track:** Image Binding (CTX-0041)

---

## 1. Goal

Bind the credential payload to a specific **cover image** and a **carrier lattice** so that:

- detection is image-specific (no cross-image replay of the same lattice bits — `K_embed` mixing)
- extraction is robust to distribution transforms (`JPEG`, `blur`, `scale 0.7×`)
- geometric distortions require explicit registration rather than silent mis-decode

## 2. Image normalization (decode)

1. Decode bytes to `RGB8` via the reference pipeline (`image 0.25`, features `png`+`jpeg`).
2. `PNG` → lossless `u8` buffer; `JPEG` → YCbCr→RGB via `image`'s decoder (no color-management, no ICC).
3. `RGBA` → `RGB` by compositing alpha against white (`255,255,255`) unless `carrier == Alpha`, in which case `capglyph_core::signal::SignalMetrics` operates on the `RgbaImage` buffer.
4. Dimensions are taken from the decoded buffer; no re-orientation from EXIF is applied in v1.

Vectors in `images/` are `PNG` to avoid encode/decode ambiguity; `JPEG q75/q50/q30` robustness is measured with synthetic covers in the core ladder, not with vector PNGs.

## 3. Cover identity & image binding hash

Each cover has a `cover_id` (UUID) and a `sha256` of the `PNG` bytes. For the lattice, a `u64` image-binding hash is derived:

- `stable_seed` — `FNV-1a` of the first `4096` bytes mixed with a `16×16` quantized luminance hash, providing a PRNG seed stable across `PNG→PNG` re-encode but sensitive to content change.
- `prng_seed` (in `GeometryFile`) — stored `u64` for solid-color fallback so verification can reconstruct the same pseudorandom block set without re-hashing a modified image.
- `geometry_hash` — `GeometryFile::compute_geometry_hash()` over sorted path endpoints (first/last point of each Chaikin-smoothed polyline), for family matching.

Cover-family matching is: `stable_seed` → `cover_id` (`HybridMatch` over `OrbRansacRegister` + quantized hash), then original-assisted verification on the selected cover.

## 4. Geometry extraction (placement hint)

Optional and non-authoritative — geometry is a _hint_ for where to place coefficients, not a secret.

- Pipeline (when available): `vectomancy-raster` `Sobel → Otsu → Zhang-Suen → endpoint/loop tracing → RDP → Chaikin` → `GeometryFile { original_width, original_height, analysis_params, paths, prng_seed?, blocks? }`.
- `AnalysisParams { detail: u8, min_path_len: usize, chaikin_iters: usize, color: bool }` tunes density.
- `GeometryFile.blocks: Option<Vec<(u32,u32)>>` — exact sorted `8×8` block coordinates used during `DCT` embed; when present, `extract` uses them directly instead of re-deriving blocks from `paths` (avoids post-watermark drift).
- Solid-color fallback: `paths == []`, `prng_seed` is set, lattice is pure PRNG (`Prng`).

## 5. Placement

`capglyph_core::placement::Placement`:

- `Skeleton` (default) — blocks along the skeleton path (`GeometryFile.paths` → Bresenham → eligible blocks).
- `Prng` — `RNG(stable_seed)` over the full block grid, budget-matched to `Skeleton` count for fair comparison.
- `Edge` — `Sobel ≥128`, rank-broken, budget-enforcing, fail-closed with `E_INSUFFICIENT_CAPACITY` when geometry is insufficient (`edge_blocks_with_budget`).

All three are implemented for `DCT`. **`DWT` currently ignores `_placement`** (dead code, `embed` is `Skeleton`-only and `Edge`/`Prng` are fail-closed) — this is a known wiring gap recorded in `capacity-robustness…` §4 and in spec §5.2. Policy: do not claim DWT placement benchmarks until wiring + `cargo test` coverage lands.

Intended default (post-v1.1) is `Adaptive eligible-map + keyed PRNG`:

```
image → perceptual cost / texture eligibility map → remove flat/unsafe regions
      → positions = PRF(K_embed, cover_id || token_id) inside eligible region
```

This will be more invisible than blind `Prng` and more unpredictable than fixed `Skeleton`.

## 6. Carrier lattice

### 6.1 DCT

- Block grid `N_DCT = floor(W/8) * floor(H/8)`.
- Presence: `F[2,3] += 16` (public layer).
- ID bits: differential `F[3,4]` `+64 / -64` per bit (`A+delta, B-delta`), `redundancy 8` + self-sync seed blocks (`SEED_MAGIC`, `512` blocks, `64 b × 8`).
- ID positions after the sync region are `RNG(stable_seed)` filtered to non-overlap with `SEED_MAGIC`; extraction recovers `stable_seed` from the sync blocks, reconstructs the RNG sequence, and reads the bits without geometry.

### 6.2 DWT

- Single-level 2D Haar, `LH` band (`W/2 × H/2` coefficients).
- Primary presence `+8.0` at geometry positions.
- ID: `±256` in textured regions, `±32` in flat (`FLAT_ID_EMBED_STRENGTH`) — prevents visible artifacts in flat regions at the cost of raw BER.
- Secret layer: `256` differential pairs `±8` at `HMAC(K_secret, stable_seed)` positions (`DctSecretLayer`/`DwtSecretLayer` semantics in `carrier.rs` — `verify_secret` mean signal ≈ `2·delta` for the right key, ≈ `0` for a wrong one).

### 6.3 Capacity invariants

Spec enforces the **fail-closed capacity check** — every embed `MUST` compute `blocks_needed = 512 + 8 * ecc_coded_bits` and return `E_INSUFFICIENT_CAPACITY` when `blocks_needed > N_DCT` (DCT) or `coeffs_needed > LH_size` (DWT). Vectors must include at least one `invalid` case exercising this.

Measured ceilings (math, not promise): `512×512` DCT `4096` blocks → `56 B` logical ceiling; `1024×1024` `16384` → `248 B` logical. Robust capacity after `54 B` sealed + ECC is in `capacity-robustness…` §3 (512 DCT `BCH t=3` FER `0.05/0.10` at `q75/q50`; `1024×` `FER 0.0` all `JPEG`).

## 7. Secret-layer binding

`K_embed` (from `KeyMaterial`) mixed with `stable_seed` via `prf_k_embed` yields the `u64` placement seed for the secret layer. The same image+key always yields the same positions; different images diverge even under the same key (image-hash mixing). This provides keyed attribution that survives 5-copy collusion median (secret layer `verify_secret` remains ≈ `2·delta`, while ID decoding fails — `capacity-robustness…` matrix) and defeats forgery without the key.

## 8. C2PA cross-binding (optional)

When `feature=c2pa` is enabled, a `C2PA` manifest with `com.capglyph.watermark {mode, recipient_id, keyed, cover_sha256, output_sha256, embed_profile}` `MUST` cross-reference the pixel carrier and the manifest hash. C2PA proves binding+integrity, not factual truth of `scope` claims.

## 9. References

- `capglyph_core::{geometry, placement, carrier, keying::prf_k_embed, registration}`
- `capglyph/src/{dct,dwt_embed,carrier}.rs` (facade over core trait)
- `research/media-credential/technology/pointer-and-stego.md` §§5–7
