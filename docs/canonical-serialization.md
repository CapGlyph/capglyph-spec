# Canonical Serialization — Deterministic CBOR

**Spec:** 1.0.1 · **Track:** Canonical Serialization

---

## 1. CBOR profile

CapGlyph uses **deterministic CBOR** (RFC 8949 §4.2.1, §4.2.3):

- shortest-form integer encoding (no leading zeros, minimal byte length)
- definite-length arrays and byte strings (no indefinite lengths, no streaming)
- map keys bytewise sorted by deterministic encoding (only for inner payload maps — the outer framing is an array, not a map, so inner-map ordering is the only map surface)

## 2. Outer framing (array, not map)

```cbor
CborFrame = [ version: uint, payload_type: uint, flags: uint, payload_len: uint, payload: bstr ]
```

- 5 elements, definite-length array (`0x85`).
- `payload` is **byte string** (major type 2), via `serde_bytes` — never an array of integers. Encoding `payload = h'010203'` `MUST` be `0x43 010203`, not `0x83 0x01 0x02 0x03`.
- `payload_len` `MUST` equal the decoded byte-string length.
- Encoders `MUST` reject payloads larger than 65535 before narrowing. Decoders
  `MUST` reject non-minimal integers and byte-string lengths, indefinite items,
  trailing bytes, negative/out-of-range fields, and unknown payload types.

Reference implementation `capglyph_core::framing::cbor::encode` uses `ciborium::ser::into_writer(&CborFrame(…), &mut buf)` over this tuple struct; decoding is `ciborium::de::from_reader`. Vectors pin the exact `cbor_frame_hex`.

## 3. Inner credential / pointer maps (key ordering)

When the payload itself is CBOR, maps `MUST` be sorted by the **lexicographic order of the deterministic CBOR encodings of each key**. With integer keys `0,1,2…` this is simply numeric order; with mixed keys, the sorted byte encodings decide.

The v1 Credential profile is exactly `{0: token_id}`: a definite one-entry map,
shortest key `0`, and a definite 16-byte byte string. Its canonical payload is
19 bytes and begins `a10050`. Empty payloads, raw tokens, extra/duplicate keys,
and non-canonical inner encodings are `E_PAYLOAD_INVALID` after the outer frame
authenticates and validates.

JSON → CBOR translation `MUST` go through this integer-key table; JSON key order is not significant and `MUST NOT` leak into the wire.

## 4. Integer signing & length limits

- `version`, `payload_type`, `flags` have unsigned value domains `0..255`; the
  CBOR encoding occupies one byte only for values `0..23` and otherwise uses
  the shortest additional-information form. V1 Credential additionally
  requires `flags = 0`.
- `payload_len` is `u16` (`0..65535`, up to 2 bytes CBOR uint). Payloads larger than `65535` `MUST` be chunked via pointer mode (image holds a `capability_id` → object store holds the full ciphertext).
- Floating point, text chunks, and tagged CBOR (`tag 0` datetime etc.) `MUST NOT` appear in the outer frame.

## 5. Test vectors

`valid/` vectors include `cbor_frame_hex` (CBOR bytes) and `sealed_hex` (CBOR + 32 B tag). Conformance harness `MUST` assert byte equality against the reference encoder, then `open` and compare `payload_hex`.

## 6. Implementation notes

- `ciborium 0.2` is the normative library (Rust). SDK ports `MUST` use an RFC 8949 deterministic mode (e.g. Python `cbor2` with `canonical=True` + `value_sharing=False`, JS `cbor-x` with `useRecords:false` and sorted keys, Go `fxamacker/cbor` with `EncOptions{Sort: SortCanonical, ShortestFloat: ShortestFloat16, IndefLength: IndefLengthForbidden}`).
- The 32 B `HMAC-SHA256` tag is concatenated **outside** CBOR, not inside the array — so re-encoding the CBOR array reproduces the tag input exactly.

## 7. References

- RFC 8949, §4.2.1 (Core Deterministic Encoding Requirements), §4.2.3
- `capglyph_core::framing::{cbor, auth}`
- `docs/interoperability-profile.md`
