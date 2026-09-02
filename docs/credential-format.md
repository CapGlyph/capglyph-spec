# Credential Format — CapGlyph Credential & Pointer Envelope

**Spec:** 1.0.1 · **Track:** Credential Format (CTX-0041)

---

## 1. Design principle: opaque bearer

The image carries **only the opaque bearer secret**, wrapped in the exact v1
Credential map; all mutable policy (`expiry`, `quota`, `revocation`, `scope`)
lives in the server DB (`covers`/`credentials` tables per
`credential-design.md`). This avoids split-brain between image claims and DB
truth. The resulting canonical sealed envelope is 57 bytes before ECC and does
not fit the measured `512×512` DCT 56-byte logical ceiling; see
`image-binding.md` §6.3.

Payload on the wire is therefore small and fixed-size:

```
16 B  token_id (128-bit CSPRNG, 16 bytes, base64url outside the carrier)
→ CBOR map {0: token_id}
→ framing CBOR array [1, Credential=1, flags=0, len, bstr(token_cbor)]
→ HMAC 32 B tag
```

## 2. CBOR credential map (inside the framed payload)

Integer keys (preferred) — bytewise CBOR-sorted, definite-length:

| Key | Field      | Type        | Notes                                                                                      |
| --- | ---------- | ----------- | ------------------------------------------------------------------------------------------ |
| `0` | `token_id` | `bstr` 16 B | `128-bit` CSPRNG, the only secret in the image. `token_hash = SHA256(token_id)` is stored. |

The v1 map has exactly this one field. Its deterministic encoding is 19 bytes:
`a1 00 50 || token_id`. Empty/opaque payloads, raw 16-byte token bytes, extra or
duplicate keys, text-key aliases, wrong token lengths, tagged/indefinite CBOR,
and non-minimal encodings are `E_PAYLOAD_INVALID`. Fields such as issuer,
not-before, expiry, and scope remain server policy; future offline profiles
require their own negotiated version/profile and MUST NOT extend v1 silently.

## 3. Framing header (outer envelope)

`FrameHeader` (see `spec.md` §3.1 and `capglyph_core::framing::FrameHeader`):

```rust
pub struct FrameHeader { pub version: u8, pub payload_type: PayloadType, pub flags: u8, pub payload_len: u16 }
pub enum PayloadType { Credential=1, Pointer=2, Message=3, Locator=4 }
```

| Field          | Width | v1 value                                         | Constraint                                       |
| -------------- | ----- | ------------------------------------------------ | ------------------------------------------------ |
| `version`      | 1 B   | `1`                                              | any other → `E_VERSION_UNSUPPORTED`              |
| `payload_type` | 1 B   | `1` (Credential) for this doc; `2` for pointer   | `1..4` else `E_MALFORMED_FRAME`                  |
| `flags`        | 1 B   | `0`                                              | any other Credential value → `E_PAYLOAD_INVALID` |
| `payload_len`  | 2 B   | `len(payload CBOR)`                              | `MUST == payload.len()` else `E_MALFORMED_FRAME` |

Sealed wire: `CborFrame || tag` where `CborFrame = CBOR([version, type, flags, payload_len, payload_bstr])` and `tag = HMAC_SHA256(K_mac, CborFrame)` (32 B). `ciborium` deterministic encoding (shortest int, definite lengths) is normative.

## 4. Pointer descriptor (payload type 2)

When `payload_type == 2` (Pointer), the CBOR payload is a pointer descriptor:

```cbor
{ 0: capability_id (16 B), 1: object_id (16 B), 2: wrapped_key_ref (tstr), 3: ciphertext_hash (32 B, SHA256) }
```

`capability_id` is the bearer secret (same generation as `token_id`). The server maps `capability_id → {object_id, wrapped_key, ciphertext_hash}` and enforces `expiry/revocation` on the capability row; the object store authorizes `object_id` via the capability, not via `object_id` alone (no IDOR). See `pointer-and-stego.md` for `pointer-online` (default) vs `pointer-offline` (dumb object store) trade-offs.

## 5. Message descriptor (payload type 3, Beta)

`Message` payloads are `AEAD` ciphertext (e.g. `ChaCha20-Poly1305` or `AES-256-GCM`) of `plaintext → compress → AEAD → ECC → carrier`. The CBOR payload is `ciphertext` plus a minimal header; spec marks `Message` as **Beta/research** — only short notes (`128–512 b`) on `1024+` textured carriers with `FER` measurement. Not for v1 GA.

## 6. Encoding example (valid vector)

Token `16 B` = `000102030405060708090a0b0c0d0e0f`; canonical payload is
`a10050000102030405060708090a0b0c0d0e0f` (hex).

```json
{
  "token_id_hex": "000102030405060708090a0b0c0d0e0f",
  "payload_hex": "a10050000102030405060708090a0b0c0d0e0f",
  "payload_type": "Credential",
  "flags": 0,
  "version": 1,
  "k_mac_hex": "42…42 (32×0x42)",
  "cbor_frame_hex": "850101001353a10050000102030405060708090a0b0c0d0e0f",
  "tag_hex": "HMAC_SHA256(k_mac, cbor_frame)",
  "sealed_hex": "cbor_frame || tag"
}
```

Valid vectors store `sealed_hex` and the decoder `MUST` reproduce it byte-for-byte, then `open` to `payload_hex` and classify as `valid`.

## 7. Policy & lifecycle fields (DB, not on-image)

The following are **never** embedded in v1; they are looked up via `SHA256(token_id)`:

- `issuer`, `scope` (`JSONB`, e.g. `["download:asset:42"]`), `cover_id`, `key_id` (`kid`), `embed_params` (carrier/placement/ecc), `output_sha256`, `not_before/expires_at`, `max_uses/use_count`, `revoked_at` (see `docs/consumption.md` schema).

Embedding them would waste capacity, create replay forks, and violate the opaque-bearer principle.

## 8. Future: offline-signed profile (v2, reserved)

At `1024+` the map `MUST` gain `exp/scope/nonce` plus an `Ed25519` signature over `SHA256(CborFrame)` keyed by `kid`. `payload_type` stays `1`, `version` becomes `2`, and `flags` bit `0x80` signals `signature` instead of `HMAC`. No stacking with `HMAC` — the verifier negotiates one. Not yet normative.

## 9. References

- `capglyph_core::framing::{Params, FrameHeader, seal, open, cbor, auth}`
- `capglyph-test-vectors` `vectors/valid/*.json` (+ `manifest.json`)
- `research/media-credential/usage/credential-design.md` §2 (opaque token) / §4 (DB schema)
