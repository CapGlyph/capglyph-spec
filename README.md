# CapGlyph Specification

**Version:** 1.0.1 (2026-09-02) · **Wire:** `FrameHeader.version == 1` · **Core:** `capglyph-core` 0.1.0 · **Status:** Stable draft

Canonical specification for the CapGlyph image-native credential and stego-payload protocol.

- **Repository:** `CapGlyph/capglyph-spec` (this repo) — public, versioned
- **Core implementation:** `CapGlyph/capglyph-core` — `capglyph_core::framing`, `keying`, `ecc`, `carrier`, `registration`
- **Conformance vectors:** `CapGlyph/capglyph-test-vectors` — cross-language fixtures (valid/invalid/expired/revoked/malformed/tampered/images)
- **Harness:** `capglyph conformance test --vectors <path>` (in `CapGlyph/capglyph-cli`)

## Spec index

| Document          | Path                                                                     | Scope                                                                                                                            |
| ----------------- | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| Umbrella spec     | [`spec.md`](./spec.md)                                                   | version, canonical CBOR, hash/sig, image normalization, payload encoding, version negotiation, error semantics (normative index) |
| Protocol          | [`docs/protocol.md`](./docs/protocol.md)                                 | issuance / verification / consumption flow, hybrid blind→original-assisted extractor                                             |
| Credential Format | [`docs/credential-format.md`](./docs/credential-format.md)               | CBOR credential, token_id, CBOR array framing, field table                                                                       |
| Interoperability  | [`docs/interoperability-profile.md`](./docs/interoperability-profile.md) | exact v1 Credential bytes, HKDF domains, validation order, stable errors, migration                                              |
| Image Binding     | [`docs/image-binding.md`](./docs/image-binding.md)                       | cover binding, geometry, carrier lattice (DCT/DWT), image normalization                                                          |
| Verification      | [`docs/verification.md`](./docs/verification.md)                         | original-assisted `R = I_aligned - I_orig`, correlation, secret-layer differential pairs                                         |
| Consumption       | [`docs/consumption.md`](./docs/consumption.md)                           | atomic `UPDATE … RETURNING`, idempotency, audit                                                                                  |
| Policy            | [`docs/policy.md`](./docs/policy.md)                                     | scope language, expiry, revocation, key rotation (`kid`), WebAuthn binding                                                       |

Detailed companions:

- `docs/canonical-serialization.md` — deterministic CBOR rules
- `docs/error-semantics.md` — error codes & fail-closed behavior

## Maturity

Spec v1.0.1 preserves wire version 1 and fixes Credential semantics, RFC 5869 key domains and authenticated error precedence. Current Core and byte fixtures contain this alignment work. It does not establish conformance to every image, policy or service requirement. Read the [non-normative implementation reconciliation](docs/implementation-reconciliation.md) for concrete contradictions and uncovered gates; normative clauses are unchanged by that audit.

## Reading order

`spec.md` → `protocol.md` → `credential-format.md` → `image-binding.md` → `verification.md` → `consumption.md` → `policy.md`.

Security-economics documents in `capglyph-docs` are design/analysis companions, not additional normative protocol authority. Historical FER tables apply only to their named experiment and payload/profile.

## Conformance

```bash
capglyph conformance test --vectors ../capglyph-test-vectors/vectors
python3 ../capglyph-test-vectors/tools/conformance.py --vectors ../capglyph-test-vectors/vectors
```

Every fixture must match its declared success or exact error outcome. The current 1024 cases exercise bytes, key derivation and mocked policy, not actual image/ECC transport, database concurrency, or public HTTP clients. A passing byte suite is necessary evidence for that scope, not full system certification.

## License

Apache-2.0 — same as `CapGlyph/capglyph-core`.
