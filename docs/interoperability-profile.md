# V1 Interoperability Profile

**Spec:** 1.0.1 · **Wire version:** 1 · **Status:** Normative

This profile freezes the byte-level contract shared by CapGlyph Core, SDKs,
servers, and conformance vectors. It is a normative erratum to 1.0.0: it
removes contradictory validation precedence and makes the already documented
Credential map requirement executable. It does not introduce a new outer frame
or a new `FrameHeader.version`.

## 1. Exact Credential payload

For `payload_type = 1` and wire version 1, the decoded payload MUST be the
deterministic CBOR encoding of exactly this map:

```cbor
{ 0: h'000102030405060708090a0b0c0d0e0f' }
```

The general form is `{0: token_id}` where:

- the map has exactly one pair and uses the definite-length `0xa1` form;
- key `0` uses its shortest unsigned encoding (`0x00`);
- `token_id` is a definite-length byte string of exactly 16 bytes (`0x50`);
- no tag, duplicate key, extra key, text-key alias, indefinite item, or
  non-minimal integer/length encoding is permitted; and
- the canonical payload is therefore exactly 19 bytes.

An empty payload, a raw opaque 16-byte token, a map with extra fields, a token
of any other length, or any non-canonical encoding MUST fail with
`E_PAYLOAD_INVALID` after outer authentication and framing validation succeed.
V1 Credential frames MUST set `flags = 0`; any other Credential flag value is
`E_PAYLOAD_INVALID`. Reserved Credential fields and flags require a future
profile; they MUST NOT be accepted speculatively.

## 2. Outer deterministic CBOR

The outer frame remains:

```cbor
[version, payload_type, flags, payload_len, payload_bstr]
```

It MUST be a definite five-element array (`0x85`). Every unsigned integer and
byte-string length MUST use the shortest RFC 8949 encoding. The payload MUST be
a definite byte string. `payload_len` MUST equal the byte-string length and be
in `0..65535`; encoders MUST reject larger payloads before narrowing or
allocation. Trailing data, tags, indefinite items, negative values, values
outside their declared range, and unknown payload types are
`E_MALFORMED_FRAME`.

For the example token above, the canonical payload is:

```text
a10050000102030405060708090a0b0c0d0e0f
```

and the complete canonical outer frame is:

```text
850101001353a10050000102030405060708090a0b0c0d0e0f
```

The complete sealed Credential is 57 bytes: 6 bytes of outer CBOR overhead,
19 bytes of canonical inner payload, and a 32-byte HMAC tag.

## 3. Key schedule and MAC

Credential profiles that derive keys from input key material MUST use RFC 5869
HKDF-SHA256 exactly as follows:

```text
PRK      = HKDF-Extract(salt = cover_id[16], IKM)
K_embed  = HKDF-Expand(PRK, info = "capglyph/k-embed/v1",  L = 32)
K_mac    = HKDF-Expand(PRK, info = "capglyph/k-mac/v1",    L = 32)
K_object = HKDF-Expand(PRK, info = "capglyph/k-object/v1", L = 32)
tag      = HMAC-SHA256(K_mac, CborFrame)
```

`cover_id` is the exact 16-byte binary identifier, not hexadecimal or UUID
text. The three info strings are the exact ASCII bytes shown, with no NUL and
no length prefix. Empty IKM is invalid. No second `*-mac-tag-*` prefix is added
to the frame MAC. Explicit 32-byte keys supplied by a KMS bypass HKDF but retain
their roles; keys MUST NOT be substituted across roles. The historical
`sigil-k-*-v1` HMAC expansion is a compatibility implementation detail, not
this interoperable derivation profile.

## 4. Fixed validation order

There are two sources of input: trusted request context and untrusted sealed
bytes. Implementations MUST keep them separate.

Trusted context is checked first:

1. Reject an unsupported negotiated/requested version with
   `E_VERSION_UNSUPPORTED` and `supported_versions`.
2. Resolve `kid`/`key_id`; a missing key is `E_KEY_NOT_FOUND`. Never derive
   from a zero key and never infer a key from untrusted frame bytes.

Then process the sealed bytes in this exact order and stop at the first error:

1. If fewer than 32 bytes are available for the tag, return
   `E_MALFORMED_FRAME`.
2. Split the final 32 bytes as the tag without decoding CBOR.
3. Verify `HMAC-SHA256(K_mac, frame)` in constant time. On mismatch return
   `E_AUTH_FAILED`, regardless of any malformed or unsupported-version bytes
   inside the authenticated region.
4. Decode and re-encode the outer frame; enforce the deterministic CBOR,
   five-field shape, integer ranges, known payload type, exact length, and no
   trailing bytes. On failure return `E_MALFORMED_FRAME`.
5. If the authenticated, canonical `FrameHeader.version` is not 1, return
   `E_VERSION_UNSUPPORTED` with `supported_versions = [1]`.
6. Validate the payload-type profile. Credential violations from section 1
   return `E_PAYLOAD_INVALID`.
7. Only after cryptographic and semantic success may policy, quota,
   registration, or carrier decisions run.

Consequently, the cross-product contract is:

| Auth | Outer frame | Embedded version | Result |
| --- | --- | --- | --- |
| invalid | any tag-sized bytes | any | `E_AUTH_FAILED` |
| valid | malformed/non-canonical | any/unknown | `E_MALFORMED_FRAME` |
| valid | canonical | unsupported | `E_VERSION_UNSUPPORTED` |
| valid | canonical | 1, invalid Credential | `E_PAYLOAD_INVALID` |
| valid | canonical | 1, valid Credential | success |

## 5. Stable wire errors

Wire responses MUST use the string in `code`; HTTP status is transport
metadata and MUST NOT replace it.

| Code | Meaning |
| --- | --- |
| `E_VERSION_UNSUPPORTED` | trusted negotiation rejected, or authenticated canonical frame has unsupported version |
| `E_KEY_NOT_FOUND` | configured `kid`/`key_id` cannot be resolved |
| `E_MALFORMED_FRAME` | tag boundary, deterministic CBOR, outer shape/range/type/length failure |
| `E_AUTH_FAILED` | frame HMAC mismatch |
| `E_PAYLOAD_INVALID` | authenticated canonical frame violates its payload-type profile |

Existing carrier and policy codes remain defined by `error-semantics.md`.
Implementations MUST NOT collapse these strings to numeric HTTP codes.

## 6. Version negotiation

Wire version selection is out-of-band. An issuer and verifier exchange ordered
sets such as `supported_versions = [1]`; the issuer chooses the highest mutual
version. No mutual version is `E_VERSION_UNSUPPORTED`. Authentication failure
MUST NOT trigger downgrade. A v1 verifier MAY inspect an authenticated,
canonical v1-shaped test frame whose embedded version is higher only to return
`E_VERSION_UNSUPPORTED`; this is not permission to parse an unknown future
wire format before authentication.

## 7. Migration from the initial 1.0.0 fixtures

- Regenerate Credential fixtures with the 19-byte canonical inner map. Raw
  16-byte and empty Credential payloads move to semantic negative vectors.
- Reject nonzero Credential flags instead of treating them as opaque.
- Replace version-first harness logic with the fixed order in section 4 and
  add valid/invalid-MAC cross-products for canonical, malformed, and
  unsupported-version frames.
- Add shared HKDF fixtures for all three key roles. Existing deployments using
  historical `sigil-*` expansion need an explicit legacy profile or key
  migration; they MUST NOT silently label those bytes as this profile.
- Preserve `FrameHeader.version = 1`. The migration changes conformance and key
  derivation behavior, not the outer frame discriminator.
