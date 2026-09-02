# CapGlyph Specification v1.0.1

**Date:** 2026-09-02
**Spec version:** `1.0.1` · **Protocol version:** `1` (wire `FrameHeader.version == 1`)
**Core version:** `capglyph-core` `0.1.0` · **Status:** Stable draft, normative for `CapGlyph/capglyph-core` and `capglyph-test-vectors`
**Editors:** CapGlyph Authors · **License:** Apache-2.0
**Repos:** `CapGlyph/capglyph-spec` (this spec) · `CapGlyph/capglyph-core` (reference impl) · `CapGlyph/capglyph-test-vectors` (fixtures)

---

## 1. Scope & conformance language

CapGlyph is **image-native credential + stego payload infrastructure** — a toolkit for embedding, transporting, extracting, and verifying cryptographically protected payloads through image carriers (DCT, DWT, learned). It is **not** a login system or access-control engine; it provides the bearer primitive that application policy consumes.

Keywords `MUST`, `MUST NOT`, `SHOULD`, `MAY` are RFC 2119. Fail-closed means any verification failure maps to a single `InvalidCredential` outcome with a structured error code (see §8); no partial success.

This spec normatively defines:

- canonical serialization (CBOR, key ordering, determinism)
- hash / MAC / signature algorithms (`HMAC-SHA256` v1, `Ed25519` reserved)
- image normalization (decode, geometry, lattice)
- payload encoding stack (CBOR → auth → ECC → interleave → modulate)
- version negotiation
- error semantics

Companion docs (`docs/*.md`) expand the CTX-0041 tracks: Protocol, Credential Format, Image Binding, Verification, Consumption, and Policy. `docs/interoperability-profile.md` freezes the exact v1 Credential bytes, key schedule, validation order, errors, and 1.0.0 migration.

---

## 2. Versioning

### 2.1 Spec version

Spec uses SemVer `MAJOR.MINOR.PATCH` (`1.0.1`). `MAJOR` bumps on wire-incompatible framing or carrier lattice change. `MINOR` adds optional `PayloadType`/`flags`/`kid` or a new `Profile` without breaking v1 decoders. `PATCH` includes normative errata that make an existing requirement executable without changing the outer wire discriminator. Version 1.0.1 resolves the contradictory 1.0.0 error precedence and fixture semantics; `FrameHeader.version` remains 1.

### 2.2 Wire version (`FrameHeader.version`)

Separate from spec SemVer. `FrameHeader.version` is the CBOR envelope discriminator:

- `1` — current, defined here (`HMAC-SHA256` framing, `PayloadType` 1..4, generic header `flags` 0..255, `payload_len` u16, `HMAC-SHA256` 32 B tag). The v1 Credential profile requires `flags = 0`.
- `2+` — reserved. Authenticated decoders `MUST` return `E_VERSION_UNSUPPORTED` only after the tag and deterministic outer frame validate. Unkeyed `validate_frame` MAY report syntax/version as preflight but MUST NOT present that result as authenticated verification.

Carrier lattice version is orthogonal and negotiated via `embed_profile` (`carrier` + `placement` + `ecc`), not via `FrameHeader.version`.

### 2.3 Version negotiation

Issuers advertise `supported_versions = [1]` (and later `[1,2]`). Verifiers announce `accepted_versions`. The issuer `MUST` seal under the highest mutually accepted version, defaulting to `1`. Negotiation is trusted request context and precedes envelope processing. Clients `MUST NOT` downgrade on tag failure. A tag-sized envelope with an invalid tag returns `E_AUTH_FAILED` even if its unauthenticated bytes appear to name v2; only a validly authenticated, canonical unsupported version returns `E_VERSION_UNSUPPORTED`.

Future v2 (`Ed25519` framing tag + `kid` in header) will define a new `FrameHeaderV2` with `kid` and `signature` fields; v1 decoders will treat it as `E_VERSION_UNSUPPORTED`.

---

## 3. Canonical serialization

### 3.1 Outer framing

Framing is **CBOR array, not map**. This eliminates map-key ordering ambiguity.

```
CborFrame := [ version: uint(0..255),
               payload_type: uint(1..4),
               flags: uint(0..255),
               payload_len: uint(0..65535),
               payload: bstr ]        ; 5 elements, deterministic
sealed    := CborFrame || HMAC_SHA256(K_mac, CborFrame)   ; 32 B tag appended
```

- Encoder `MUST` use **deterministic CBOR** (RFC 8949 §4.2.1 + §4.2.3): shortest-form integers, definite-length array (5), definite-length byte string for `payload`.
- Payload byte string `MUST` be encoded via `serde_bytes` (CBOR major type 2), not as an array of integers.
- `payload_len` `MUST` equal `payload.len()`. Decoders `MUST` enforce this and return `E_MALFORMED_FRAME` on mismatch.
- `payload_len` is an unsigned 16-bit domain. Encoders `MUST` reject payloads larger than 65535 bytes before narrowing, allocation, or MAC computation.
- Decoders `MUST` reject non-minimal integer or byte-string length forms, indefinite items, trailing bytes, negative/out-of-range fields, and unknown payload types as `E_MALFORMED_FRAME`.
- See `docs/canonical-serialization.md` for the exact `ciborium` serialization and the JSON→CBOR mapping.

### 3.2 CBOR key ordering (credential & pointer objects)

When a payload itself is CBOR (credential JSON → CBOR, pointer descriptor), map keys `MUST` be sorted in **bytewise lexicographic order of their deterministic CBOR encodings** (RFC 8949 §4.2.3). Implementations that originate credentials as JSON `MUST` translate via the CBOR integer-key table before sealing — JSON key order is not preserved.

The v1 Credential payload is not arbitrary bytes. It is exactly the 19-byte deterministic encoding of `{0: token_id}` where `token_id` is a 16-byte byte string, the map has one entry, and `flags = 0`. Empty payloads, raw 16-byte tokens, nonzero Credential flags, extra keys, wrong token lengths, and non-canonical inner CBOR return `E_PAYLOAD_INVALID`. See `docs/interoperability-profile.md`.

### 3.3 Determinism requirement

Two encoders given the same `(version, payload_type, flags, payload)` and the same `K_mac` `MUST` produce byte-identical `sealed` output. Test vectors in `CapGlyph/capglyph-test-vectors` are byte snapshots of this determinism (hex `sealed_hex` fields). Cross-language SDKs `MUST` pass the valid-vector suite before they claim spec compliance.

---

## 4. Hash / MAC / signature algorithms

### 4.1 V1 (normative)

| Purpose                | Algorithm                               | Input → output                        | Constant                      |
| ---------------------- | --------------------------------------- | ------------------------------------- | ----------------------------- |
| Framing authentication | `HMAC-SHA256`                           | `tag = HMAC_SHA256(K_mac, CborFrame)` | `32 B`                        |
| Key extraction         | RFC 5869 `HKDF-Extract-SHA256`          | `salt=cover_id[16], IKM → PRK`        | binary cover ID, not text     |
| Key expansion          | RFC 5869 `HKDF-Expand-SHA256`, `L=32`   | `PRK, info → K_embed/K_mac/K_object`  | exact info strings below      |
| Token hashing          | `SHA-256`                               | `token_hash = SHA256(token_id)`       | stored in DB, never raw token |
| Image binding hash     | `stable_seed` (FNV-1a + 16×16 quantize) | `u64` seed for PRNG lattice           | `SEED_MAGIC` sync blocks      |

The exact ASCII HKDF info strings are `capglyph/k-embed/v1`, `capglyph/k-mac/v1`, and `capglyph/k-object/v1`. There is no NUL or length prefix. Empty IKM is invalid. The frame tag uses `K_mac` directly over `CborFrame`; it does not add a second MAC-domain prefix. Explicit KMS keys bypass derivation but MUST preserve these three roles. Historical `sigil-k-*-v1` HMAC expansion is not the interoperable HKDF profile.

`HMAC-SHA256` `MUST` use constant-time verification. Authenticated open uses the exact order in `docs/interoperability-profile.md`: tag-length boundary → HMAC over opaque frame → deterministic outer decode → embedded version → payload semantics. Therefore `E_AUTH_FAILED` takes precedence over malformed/version errors whenever a complete but invalid tag is present.

### 4.2 Reserved / future (not v1)

| Algorithm                                | Status                                     | Wire impact                                                                                                       |
| ---------------------------------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| `Ed25519` (RFC 8032, `ed25519-dalek`)    | reserved v2 for offline-signed credentials | new `FrameHeader.version == 2` with `kid` + 64 B signature replacing the 32 B HMAC, or coexisting as `COSE_Sign1` |
| `ML-DSA` (Dilithium)                     | exploratory, post-quantum profile          | same negotiation via `version`/`kid`, never stacked with `Ed25519`                                                |
| `ChaCha20-Poly1305` / `AES-GCM` / `HPKE` | pointer/message AEAD (outside framing)     | payload `flags` bit signals encryption; framing tag still covers the ciphertext                                   |

**No stacking.** Spec explicitly forbids `AES → ChaCha20 → SM4` concatenation for "extra" security. Agility is via `version`/`kid` selection, one primitive per layer (see `cryptographic-security.md` normative rule "Complexity is attack surface").

---

## 5. Image normalization

Image handling `MUST` be deterministic across SDKs. `docs/image-binding.md` is normative; this section summarizes the invariants.

### 5.1 Decode

- Verifiers `MUST` decode `PNG` (lossless) and `JPEG` (lossy) to `RGB8` via the same pipeline as the reference `capglyph_core::carrier` (image `0.25`, `png`+`jpeg` features, no `gif`/`webp` in v1).
- `RGBA` inputs: alpha `MUST` be composited against white (or preserved only for `alpha` carrier; `alpha` carrier operates on `RgbaImage` per `capglyph_core::signal`).
- No gamma correction or color-profile application before coefficient extraction — coefficients are computed on the decoded `u8` byte buffer.

### 5.2 Geometry & lattice

- Geometry extraction `MAY` use `vectomancy-raster` (Sobel → Otsu → Zhang-Suen → endpoint tracing → RDP/Chaikin) for `Skeleton` placement; geometry is a hint, not a security root.
- DCT lattice: `8×8` blocks walked along the geometry path, coefficient placement depends on `Placement` (`Skeleton`/`Edge`/`Prng`). Modulations are `F[2,3] += 16` (presence) and `F[3,4] ±64` differential (ID bits). `SEED_MAGIC` self-sync blocks (512) precede the PRNG-derived ID positions (`stable_seed`); extraction is geometry-free via seed recovery.
- DWT lattice: single-level 2D Haar `LH` band, primary `+8.0`, ID `±256` (flat regions `±32`), 256 differential pairs `±8` for the secret layer at `HMAC(key, seed)` positions.
- `Placement` semantics are normative: `Skeleton` is the default; `Prng` is a budgeted baseline; `Edge` is `Sobel ≥128`, rank-broken and budgeted to `Skeleton` count. DWT currently supports only `Skeleton`; `Edge`/`Prng` MUST fail closed and are not conforming DWT placement arms until implemented and measured.

### 5.3 Resampling / registration

Lossy transforms (`JPEG`, blur, scale `0.7×`) are **expected** to degrade SNR; `ECC` (§6) and `DWT` `LH` robustness are the declared mitigations. Geometric distortions (crop, rotate, perspective) require **original-assisted registration** (`R = I_submitted^aligned - I_original`) via `capglyph_core::registration::Register` (ORB + RANSAC). Blind verifiers `MUST` return a soft-fail (`E_GEOMETRY_MISMATCH`) rather than attempt cover-dependent verification without a `cover_id`.

---

## 6. Payload encoding stack

```
payload bytes
  → CBOR frame [v, type, flags, len, payload]          (framing, §3.1)
  → sealed = frame || HMAC_SHA256(frame, K_mac)         (auth, §4.1)
  → ECC encode                                            (ecc::Profile)
      Repetition8  — 8× repetition, hard majority + LLR soft combine (default, robust at ≥1024)
      Bch{t}       — BCH(7,4) t=1 / (15,7) t=2 / (31,16) t=3 / (63,36) t=5 (512-safe)
      RsInterleaved{n,k,depth} — RS GF(256) + byte interleave (burst/crop, correction deferred)
  → interleave (depth)                                    (interleave.rs, burst resilience)
  → modulate (±delta at carrier lattice)                (DctCarrier/DwtCarrier)
  → image (PNG/JPEG)
```

Decoding is the exact inverse; `decode` `MUST` use soft bits `LLR = 2·y/σ²` with `σ` via MAD when available (`ecc::SoftBit::from_coeff`, `estimate_sigma`). Hard majority alone is not sufficient for `JPEG q50` targets at `Repetition8`.

Logical sealing: canonical v1 Credential payload `{0:bstr16}` is 19 B → outer CBOR overhead 6 B + 32 B tag → `sealed 57 B`. It therefore exceeds the measured `512×512` DCT `56 B` logical ceiling even before ECC; implementations MUST fail closed or use a larger/profile-appropriate carrier. Existing 54-byte raw-token measurements are legacy framing experiments, not v1 Credential conformance evidence. At `1024×1024`, capacity and robustness remain profile-specific measured claims.

Pointer/message payloads follow the same stack; when `flags & 0x01 != 0` the payload is `AEAD` ciphertext and the CBOR payload is the ciphertext descriptor (`object_id`, `key_handle`, `ciphertext_hash`).

---

## 7. Version negotiation (normative flow)

1. Client `GET /v1/version` or `POST /v1/credentials/verify` with `Accept-CapGlyph-Version: 1` (or an ordered list).
2. Server responds with `X-CapGlyph-Version: 1` and, if `Ed25519` is configured, `X-CapGlyph-Supported: 1,2`.
3. Issuer seals under the highest mutually supported version. No mutual version returns `E_VERSION_UNSUPPORTED` before envelope processing.
4. `kid` rotation is orthogonal to `version`: `K_mac` `MUST` be looked up by `key_id` (`kid`) from trusted request/DB context. Unknown keys return `E_KEY_NOT_FOUND`; zero-key fallback is forbidden.
5. For sealed bytes, an invalid tag is always `E_AUTH_FAILED`. Only after successful authentication and deterministic decode may the embedded version produce `E_VERSION_UNSUPPORTED`. Authentication failure MUST NOT trigger downgrade.

See `docs/protocol.md` for the full HTTP surface and `docs/policy.md` for rotation.

---

## 8. Error semantics (summary)

All errors are **fail-closed**: no partial credential, no quota burn, no side effect. `docs/error-semantics.md` tabulates the codes; the wire code list is:

| Code                      | Category | Wire signal                                                                            | Retryable                                 |
| ------------------------- | -------- | -------------------------------------------------------------------------------------- | ----------------------------------------- |
| `E_VERSION_UNSUPPORTED`   | version  | no mutual negotiated version, or authenticated canonical frame has `version != 1`      | no — upgrade client                       |
| `E_KEY_NOT_FOUND`         | keying   | trusted `kid`/`key_id` cannot resolve; no zero-key fallback                            | no                                        |
| `E_MALFORMED_FRAME`       | framing  | missing tag boundary or deterministic outer CBOR/shape/range/type/length failure       | no                                        |
| `E_AUTH_FAILED`           | crypto   | constant-time `HMAC` mismatch before CBOR decode                                       | no                                        |
| `E_PAYLOAD_INVALID`       | payload  | authenticated canonical frame violates type profile, including Credential map/flags    | no                                        |
| `E_INSUFFICIENT_CAPACITY` | carrier  | sealed+ECC exceeds block budget                                                     | no — choose larger cover or `BCH`         |
| `E_EXPIRED`               | policy   | `now()` outside `[not_before, expires_at]`                                          | no                                        |
| `E_REVOKED`               | policy   | `revoked_at IS NOT NULL`                                                            | no                                        |
| `E_CONSUMED`              | policy   | `use_count >= max_uses` or atomic `UPDATE` returned 0 rows                          | no (success response carries `use_count`) |
| `E_TAMPERED`              | signal   | HMAC ok but ECC decode uncorrectable / residual correlation below threshold         | no                                        |
| `E_GEOMETRY_MISMATCH`     | image    | cover family not found, registration failed                                         | maybe — retry with original               |

The normative sealed-envelope precedence is `MALFORMED` only for a missing tag boundary, then `AUTH`, then deterministic `MALFORMED`, then authenticated `VERSION`, then `PAYLOAD`, then policy/carrier errors. `tampered/` expects `E_AUTH_FAILED` when a complete tag is invalid; semantic Credential negatives expect `E_PAYLOAD_INVALID` only after a valid tag and outer frame.

---

## 9. Carrier conformance (summary)

Implementations `MUST` satisfy:

- **Deterministic framing:** byte-identical `sealed` for the same inputs (vectors prove it).
- **WASM-clean core:** `cargo tree --target wasm32-unknown-unknown -p capglyph-core` contains no `clap/glob/trustmark/c2pa/tracing-subscriber`.
- **Constant-time MAC** and domain-separated `K_embed/K_mac/K_object`.
- **Geometry-free ID extraction** via `SEED_MAGIC` sync (DCT) / PRNG `stable_seed` (DWT).
- **Fail-closed on insufficient capacity** and on `Edge`/`Prng` for DWT until wiring is fixed.

See `docs/verification.md` for the correlation thresholds and `docs/image-binding.md` for the lattice invariants.

---

## 10. References

- RFC 8949 — Concise Binary Object Representation (CBOR)
- RFC 2104 — HMAC: Keyed-Hashing for Message Authentication
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA, Ed25519) — reserved v2
- `docs/interoperability-profile.md` — exact Credential bytes, key schedule, validation order, stable errors, migration
- `CapGlyph/capglyph-core` `src/{framing,keying,ecc,interleave,registration,geometry,carrier,placement,signal}.rs`
- `CapGlyph/capglyph-docs` `media-credential/{credential-design,pointer-and-stego,capacity-robustness-and-threats,cryptographic-security}`
- `CapGlyph/capglyph-test-vectors` — `vectors/{valid,invalid,expired,revoked,malformed,tampered,images}/` + `manifest.json`

---

_End of umbrella spec. Read `docs/*.md` for the CTX-0041 track breakdowns (Protocol, Credential Format, Image Binding, Verification, Consumption, Policy) and the canonical-serialization / error-semantics companions._
