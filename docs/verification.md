# Verification — Detection, Extraction, and Decision

**Spec:** 1.0.0 · **Track:** Verification (CTX-0041)

---

## 1. What verification does

Verification answers three questions:

1. **Present?** Does `image` carry a CapGlyph watermark above the declared `threshold`? (`verify`)
2. **Whose?** What `payload` (credential `token_id` / pointer `capability_id` / message ciphertext) was recovered? (`extract` → `framing::open`)
3. **Keyed attribution?** Does the image carry the `HMAC(key, image)`-derived secret layer for this `key`? (`verify_secret`)

The three are independent layers (public / ID / secret) per `mvp-spec.md` §1 — a valid presence signal does not imply a valid payload, and vice versa. All three `MUST` be fail-closed.

## 2. Metrics

Carriers expose `Metrics` via `Carrier::verify` / `Carrier::verify_original_assisted`. For v1:

- **DCT** — mean differential at `F[3,4]` over the recovered ID lattice (or `F[2,3]` for presence-only). `metrics.is_present(threshold)` uses `mean_signal` vs `threshold` (≈ `4.0` default; harness vectors pin the threshold per vector).
- **DWT** — `LH` band correlation at the known lattice; `verify_secret` computes differential-pair mean (≈ `16.0` for DWT `±8` pairs under the right key, ≈ `0` for a wrong key; Alpha `verify_secret` is not defined).
- **Learned** — `bit_accuracy ≥ 0.90` → `PRESENT` (TrustMark `61 b` fixed, `BCH_5` corrected) — only when `feature=learned` is compiled.

`Carrier::metrics_is_present` / `metrics_mean_signal` are the only threshold-touching entry points; callers `MUST NOT` hand-tune on the raw coefficient array.

## 3. Original-assisted extractor (strong path)

Spec mandates `registered-residual` extraction (CTX-0021) as the **strong** verifier:

```
original:  O (server vault, private)
submitted: S (holder-provided image, possibly JPEG/blur/scale/crop/rotate)
aligned:   S_aligned = Register::align(O, S)   // OrbRansacRegister + NCC Translation fallback
residual:  R = S_aligned - O                   // pixel-domain, then transform to coeff domain
signal:    collect lattice positions from (K_embed, cover_id, token_id) + SEED_MAGIC recovery
metrics:   correlation / matched filtering on R at those positions
payload:   ecc::decode(soft_bits(R)) → framing::open(sealed, K_mac) → token_id
```

`Register` is trait-pluggable (`HybridMatch` = `OrbRansac` + `NCC`); vectors mark whether they expect registration. Blind extractors `MUST` return `E_GEOMETRY_MISMATCH` when the image has been cropped/rotated and no `cover_id` is supplied.

## 4. Blind extractor (fallback / WASM path)

Blind extraction (`carrier::extract` without geometry) is geometry-free via self-sync (`DCT` `SEED_MAGIC` sync blocks) or `stable_seed` PRNG (`DWT` `LH`). It is `WASM`-reachable and uses only `HMAC`/`CBOR`/`ECC` — no filesystem, no `rayon`. For DWT, blind verification uses **median/MAD** statistics (`verify_v2`, `O(N log N)`) to avoid cover artifacts (see `dwt.rs`).

Blind `FER` is higher under lossy transforms; spec requires the harness to report both `blind` and `original-assisted` outcomes where applicable.

## 5. Three-layer decision table

| Layer  | Entry                | Present signal | Payload                                   | Keyed                  |
| ------ | -------------------- | -------------- | ----------------------------------------- | ---------------------- |
| Public | `verify`             | `is_present`   | —                                         | —                      |
| ID     | `extract` → `open`   | —              | `token_id` / `capability_id` / ciphertext | —                      |
| Secret | `verify_secret(key)` | —              | —                                         | differential-pair mean |

Vectors in `tampered/` flip `F[3,4]` bits or `LH` pairs; valid `HMAC` may still hold while lattice correlation drops — expected error `E_TAMPERED` (ECC uncorrectable / correlation below threshold) rather than `E_AUTH_FAILED`.

## 6. Thresholds & reporting

- Thresholds are **carrier + profile** specific; the vector manifest `MUST` pin `threshold` and `min_signal` per vector. Verifiers `MUST NOT` adapt thresholds per image outside the declared `embed_profile`.
- Verbose `verify` `MUST` emit `metrics` (mean signal, block count, `stable_seed`, `geometry_blocks`) for audit without leaking `K_mac`.
- `extract` returns raw `frame` bytes; `framing::open` is the only authenticated decode.

## 7. Error mapping (verification-specific)

- `E_AUTH_FAILED` — framing tag mismatch (frame-level auth).
- `E_TAMPERED` — tag ok but lattice correlation/ECC fails (signal-level tamper).
- `E_GEOMETRY_MISMATCH` — registration failed, cover not found, or `insufficient_geometry`.
- `E_MALFORMED_FRAME` — CBOR structure broken before correlation.
- See `error-semantics.md` for the precedence ladder (version → malformed → auth → policy → tampered).

## 8. References

- `capglyph_core::carrier::Carrier`, `registration::Register`, `signal::SignalMetrics`, `ecc::Profile`
- ladder `512 DCT BCH t=3` `FER 0.05` at `q75` / `0.10` at `q50`; `1024` all `0` (via `src/bin/ladder.rs`)
- `research/media-credential/technology/capacity-robustness-and-threats.md` §§2–4
