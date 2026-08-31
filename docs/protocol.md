# Protocol — CapGlyph Credential & Stego Payload

**Spec:** 1.0.0 · **Track:** Protocol (CTX-0041) · **Core:** `capglyph-core` 0.1.0

---

## 1. Roles

| Role                                               | Owns                                                          | Example                                           |
| -------------------------------------------------- | ------------------------------------------------------------- | ------------------------------------------------- |
| Issuer (`capglyphd` / `capglyph credential issue`) | `KMS(kid)`, cover vault, `covers`/`credentials` DB, audit log | server                                            |
| Holder                                             | credential image `W = O + Δ`, token holder                    | end user, event attendee                          |
| Verifier                                           | may be issuer or a delegated RP; reads `W`                    | venue scanner, HTTP `POST /v1/credentials/verify` |
| Browser (`capglyph-wasm`)                          | public decode/validate only, no `K_mac`/`K_embed`             | WASM `validate_frame` preflight                   |

## 2. End-to-end flow (credential)

```
Issuer                           Holder                 Verifier / Consumer
  │  cover_id, embed_profile,       │                       │
  │  KMS(kid) → K_embed/K_mac       │                       │
  │  token_id = CSPRNG 128          │                       │
  │  payload = CBOR({0:token_id})   │                       │
  ├─ seal(payload, K_mac)           │                       │
  ├─ ecc.encode(sealed)             │                       │
  ├─ interleave → modulate → W ────▶│─── W (PNG/JPEG) ────▶│
  │  DB insert covers/credentials   │                       │─ blind locator → cover family
  │  audit issued                   │                       │─ registration → R = I_aligned - I_orig
  │                                 │                       │─ demodulate → deinterleave → ecc.decode
  │                                 │                       │─ open(sealed, K_mac) → CBOR → token_id
  │                                 │                       │─ SHA256(token_id) → atomic_consume()
  │                                 │                       │─ scope authorize → audit success
```

`verify` is read-only; `consume` is the only mutating path (see `consumption.md`).

## 3. Hybrid extractor

Production extraction is **hybrid**:

1. **Blind locator** — DCT `SEED_MAGIC` sync blocks (or learned 61-bit locator) identify the cover family without the original.
2. **Original-assisted strong verify** — `registration::Register::align` warps `submitted` to `original` coords, builds residual `R = I_submitted^aligned - I_original`, then matched filtering on the known keyed lattice (`K_embed` → PRNG positions). This is the measured `FER 0.0` path for `JPEG q50` at `1024` (see `capacity-robustness…`).

Pure blind extraction exists but has higher `FER` under lossy transforms; spec `MUST` document which path a vector exercises.

## 4. Endpoints (normative HTTP sketch)

| Method | Path                          | Effect                                                         | Idempotency                                                                  |
| ------ | ----------------------------- | -------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `POST` | `/v1/credentials`             | issue — returns `credential_id`, `token_id` (once), `W` sha256 | `Idempotency-Key` on the client request                                      |
| `POST` | `/v1/credentials/verify`      | read-only verify, returns `valid/invalid` + `metrics`          | no                                                                           |
| `POST` | `/v1/credentials/consume`     | atomic consume, increments `use_count` iff `live`              | `Idempotency-Key` required, uniqueness on `(credential_id, idempotency_key)` |
| `POST` | `/v1/credentials/{id}/revoke` | set `revoked_at = now()`                                       | idempotent                                                                   |
| `GET`  | `/v1/credentials/{id}`        | status (`ISSUED/CONSUMED/EXPIRED/REVOKED`)                     | no                                                                           |
| `GET`  | `/v1/version`                 | `supported_versions`, `kids`                                   | no                                                                           |

See `consumption.md` for the exact `UPDATE … RETURNING` and the `credential_consumptions` idempotency constraint.

## 5. Payload-type multiplexing

`FrameHeader.payload_type` discriminates (same stack, different semantics):

- `1 Credential` — opaque 128-bit `token_id` (default, recommended)
- `2 Pointer` — locator capability (`capability_id` → encrypted object in store)
- `3 Message` — small AEAD ciphertext (Beta, `1024+` carriers only)
- `4 Locator` — learned 61-bit locator (TrustMark, `BCH_5`)

## 6. Failure precedence

On `verify`/`consume`, check in order and return the first that fires (fail-closed):

1. `E_VERSION_UNSUPPORTED` (before any MAC)
2. `E_MALFORMED_FRAME` (CBOR structure, length, truncated tag)
3. `E_AUTH_FAILED` (HMAC mismatch)
4. policy (`E_EXPIRED`, `E_REVOKED`, `E_CONSUMED`) — requires DB lookup after crypto passes
5. `E_TAMPERED` (ECC uncorrectable, correlation below threshold)

## 7. Security properties explicitly provided / not provided

Provided: authenticity (MAC/sig), bearer replay bounded by `expiry×quota×revocation`, atomic double-spend prevention, audit, cover-aware residual verification.

Not provided in v1 (non-goals, see `capacity-robustness…`): screenshot/print-scan robustness, `known-cover-proof`, `AI-regeneration-proof`, undetectability against a detector benchmark. The carrier survives `JPEG q50`, `scale 0.7×`, `blur σ1` as measured; `img2img ≥0.3` destroys every pixel watermark (including learned) and is not claimed to be resisted.

## 8. References

- `docs/credential-format.md`, `image-binding.md`, `verification.md`, `consumption.md`, `policy.md`
- `capglyph_core::framing::{seal,open,cbor,auth}`, `keying::KeyMaterial`, `ecc::Profile`, `registration::Register`
