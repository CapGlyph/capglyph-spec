# Error Semantics — Codes & Fail-Closed Behavior

**Spec:** 1.0.0 · **Track:** Error Semantics

---

## 1. Fail-closed invariant

Any verification failure `MUST` map to a single external outcome:

```
Err(InvalidCredential { code, message })   // no side effect, no quota burn
Ok((FrameHeader, payload))                 // only on full success
```

Partial decoding `MUST NOT` be returned to callers. Logs `MAY` record the structured `code`; they `MUST NOT` log raw `token_id` or `K_mac`.

## 2. Code table (normative)

| Code                    | Constant (`capglyph_core::error::Error`) | Category | When                                                                                                        | HTTP mapping                    | Retryable                  |
| ----------------------- | ---------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------- | -------------------------- |
| `VERSION_UNSUPPORTED`   | `E_VERSION_UNSUPPORTED`                  | version  | `FrameHeader.version != 1` (check before MAC)                                                               | `400` with `supported_versions` | no                         |
| `MALFORMED_FRAME`       | `E_MALFORMED_FRAME`                      | framing  | CBOR decode failed, `payload_len` mismatch, truncated < 32 B tag, unknown `PayloadType`, zero-length sealed | `400`                           | no                         |
| `AUTH_FAILED`           | `E_AUTH_FAILED`                          | crypto   | `HMAC_SHA256` mismatch (`open` tag verify)                                                                  | `401`                           | no                         |
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

On `verify`/`consume`, check in **this order** and return the first that fires (so callers see the root cause, not a downstream artifact):

1. `VERSION_UNSUPPORTED`
2. `MALFORMED_FRAME`
3. `AUTH_FAILED`
4. policy (`EXPIRED`, `REVOKED`, `CONSUMED`)
5. `TAMPERED` / `GEOMETRY_MISMATCH`

Example: a tampered valid frame that also has the wrong tag `MUST` return `AUTH_FAILED`, not `TAMPERED`.

## 4. Mapping from Rust `anyhow` to `Error`

Reference `capglyph_core::framing::open` today uses `anyhow`. The conformance wrapper `MUST` classify errors as:

- `"unsupported version"` / `"unknown PayloadType"` → `VERSION_UNSUPPORTED` / `MALFORMED_FRAME`
- `"payload length mismatch"` / `"CBOR frame decode failed"` / `"sealed frame too short"` → `MALFORMED_FRAME`
- `"frame authentication failed"` / `"HMAC verification failed"` → `AUTH_FAILED`
- ECC / correlation failures → `TAMPERED`
- `capglyph_server::Error::Expired / Revoked / Consumed` → `EXPIRED/REVOKED/CONSUMED`
- Capacity messages (`"insufficient DCT blocks"` etc.) → `INSUFFICIENT_CAPACITY`

## 5. Vectors

Each vector JSON has `expected_code` (`null` for `valid/` → success, otherwise one of the table codes) and `expected_success: bool`. The harness `MUST` assert that `valid/` vectors succeed and that every other category fails with the documented code (or at least the correct _category_ when multiple codes could apply — e.g. `tampered` that destroys the tag prefix is `AUTH_FAILED`, not `TAMPERED`).

Spec CTX-0041 harness is **byte-level compliant**: 256 duplicate vectors per category that vary payload/key/signal to reach 1024 total are valid — each `MUST` still carry the correct `expected_code`.

## 6. References

- `capglyph_core::framing::{open, cbor, auth}`, `capglyph_core::error` (new)
- `capglyph-test-vectors` `vectors/*/*.json` + `manifest.json`
- `docs/protocol.md` §6 (precedence), `docs/consumption.md` §4 (`E_CONSUMED` atomic), `docs/verification.md` §7
