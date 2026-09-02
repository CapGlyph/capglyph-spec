# Error Semantics — Codes & Fail-Closed Behavior

**Spec:** 1.0.1 · **Track:** Error Semantics

---

## 1. Fail-closed invariant

Any verification failure `MUST` map to a single external outcome:

```
Err(InvalidCredential { code, message })   // no side effect, no quota burn
Ok((FrameHeader, payload))                 // only on full success
```

Partial decoding `MUST NOT` be returned to callers. Logs `MAY` record the structured `code`; they `MUST NOT` log raw `token_id` or `K_mac`.

## 2. Code table (normative)

| Code                    | Constant (`capglyph_core::error::Error`) | Category | When                                                                                                          | HTTP mapping                    | Retryable                  |
| ----------------------- | ---------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- | ------------------------------- | -------------------------- |
| `VERSION_UNSUPPORTED`   | `E_VERSION_UNSUPPORTED`                  | version  | no mutual negotiated version, or authenticated canonical frame has `FrameHeader.version != 1`                | `400` with `supported_versions` | no                         |
| `KEY_NOT_FOUND`         | `E_KEY_NOT_FOUND`                        | keying   | trusted `kid` / `key_id` does not resolve; zero-key fallback is forbidden                                    | `404`                           | no                         |
| `MALFORMED_FRAME`       | `E_MALFORMED_FRAME`                      | framing  | missing tag boundary or deterministic outer CBOR/shape/range/type/length failure                              | `400`                           | no                         |
| `AUTH_FAILED`           | `E_AUTH_FAILED`                          | crypto   | constant-time `HMAC_SHA256` mismatch before CBOR decode                                                       | `401`                           | no                         |
| `PAYLOAD_INVALID`       | `E_PAYLOAD_INVALID`                      | payload  | authenticated canonical frame violates type semantics; v1 Credential map/token/flags are not exact           | `422`                           | no                         |
| `INSUFFICIENT_CAPACITY` | `E_INSUFFICIENT_CAPACITY`                | carrier  | `512` blocks needed > `N_DCT` / `LH_size` (or BCH block mis-size)                                           | `413`                           | no — larger cover or `Bch` |
| `EXPIRED`               | `E_EXPIRED`                              | policy   | `now() ∉ [not_before, expires_at]`                                                                          | `410`                           | no                         |
| `REVOKED`               | `E_REVOKED`                              | policy   | `revoked_at IS NOT NULL`                                                                                    | `410`                           | no                         |
| `CONSUMED`              | `E_CONSUMED`                             | policy   | `use_count >= max_uses` or atomic `UPDATE` returned 0 rows for quota                                        | `409`                           | no                         |
| `TAMPERED`              | `E_TAMPERED`                             | signal   | tag ok but `ecc::decode` uncorrectable or lattice correlation below threshold                               | `422`                           | no                         |
| `GEOMETRY_MISMATCH`     | `E_GEOMETRY_MISMATCH`                    | image    | cover family not found, registration failed, `insufficient_geometry` on `Edge`                              | `422`                           | maybe with original        |

Wire JSON (HTTP) for errors:

```json
{
  "error": "AUTH_FAILED",
  "code": "E_AUTH_FAILED",
  "message": "frame authentication failed",
  "supported_versions": [1]
}
```

## 3. Precedence ladder

Trusted request context is checked first: negotiate a supported version, then
resolve `kid`/`key_id`. These produce `VERSION_UNSUPPORTED` or `KEY_NOT_FOUND`
without consulting untrusted frame bytes.

Authenticated open then checks in **this exact order** and returns the first
error:

1. `MALFORMED_FRAME` only when fewer than 32 bytes are available for the tag.
2. `AUTH_FAILED` for a constant-time HMAC mismatch over the still-opaque frame.
3. `MALFORMED_FRAME` for deterministic CBOR, five-field shape, ranges, known
   payload type, exact length, or trailing-data failure.
4. `VERSION_UNSUPPORTED` for an authenticated canonical embedded version other
   than 1.
5. `PAYLOAD_INVALID` for authenticated type semantics, including v1 Credential
   map/token/flags.
6. Policy (`EXPIRED`, `REVOKED`, `CONSUMED`).
7. `TAMPERED` / `GEOMETRY_MISMATCH`.

Unkeyed `validate_frame` MAY report syntax/version as preflight, but its result
is never authenticated verification. A complete invalid tag masks apparent
malformed/version content as `AUTH_FAILED`; valid-MAC malformed content is
`MALFORMED_FRAME`; valid-MAC canonical v2 is `VERSION_UNSUPPORTED`.

## 4. Mapping from Rust `anyhow` to `Error`

Reference `capglyph_core::framing::open` today uses `anyhow`. The conformance wrapper `MUST` classify errors as:

- `"unsupported version"` → `VERSION_UNSUPPORTED` only after authentication and canonical decode
- `"key_id not found"` / `"kid not found"` → `KEY_NOT_FOUND`
- `"unknown PayloadType"` → `MALFORMED_FRAME`
- `"payload length mismatch"` / `"CBOR frame decode failed"` / `"sealed frame too short"` → `MALFORMED_FRAME`
- `"frame authentication failed"` / `"HMAC verification failed"` → `AUTH_FAILED`
- Credential map/token/flag validation failures → `PAYLOAD_INVALID`
- ECC / correlation failures → `TAMPERED`
- `capglyph_server::Error::Expired / Revoked / Consumed` → `EXPIRED/REVOKED/CONSUMED`
- Capacity messages (`"insufficient DCT blocks"` etc.) → `INSUFFICIENT_CAPACITY`

## 5. Vectors

Each vector JSON has `expected_code` (`null` for success) and
`expected_success`. The harness MUST assert the exact code; category-level
equivalence is forbidden. The suite MUST include the authentication × outer
shape × embedded version cross-product and Credential semantic negatives from
`interoperability-profile.md`.

## 6. References

- `capglyph_core::framing::{open, cbor, auth}`, `capglyph_core::error` (new)
- `capglyph-test-vectors` `vectors/*/*.json` + `manifest.json`
- `docs/protocol.md` §6 (precedence), `docs/consumption.md` §4 (`E_CONSUMED` atomic), `docs/verification.md` §7
