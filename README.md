# CapGlyph Specification

**Version:** 1.0.0 (2026-08-31) · **Core:** `capglyph-core` 0.1.0 · **Status:** Stable draft

Canonical specification for the CapGlyph image-native credential and stego-payload protocol.

- **Repository:** `CapGlyph/capglyph-spec` (this repo) — public, versioned
- **Core implementation:** `CapGlyph/capglyph-core` — `capglyph_core::framing`, `keying`, `ecc`, `carrier`, `registration`
- **Conformance vectors:** `CapGlyph/capglyph-test-vectors` — cross-language fixtures (valid/invalid/expired/revoked/malformed/tampered/images)
- **Harness:** `capglyph conformance test --vectors <path>` (in `CapGlyph/capglyph-cli`)

## Spec index

| Document          | Path                                                       | Scope                                                                                                                            |
| ----------------- | ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Umbrella spec     | [`spec.md`](./spec.md)                                     | version, canonical CBOR, hash/sig, image normalization, payload encoding, version negotiation, error semantics (normative index) |
| Protocol          | [`docs/protocol.md`](./docs/protocol.md)                   | issuance / verification / consumption flow, hybrid blind→original-assisted extractor                                             |
| Credential Format | [`docs/credential-format.md`](./docs/credential-format.md) | CBOR credential, token_id, CBOR array framing, field table                                                                       |
| Image Binding     | [`docs/image-binding.md`](./docs/image-binding.md)         | cover binding, geometry, carrier lattice (DCT/DWT), image normalization                                                          |
| Verification      | [`docs/verification.md`](./docs/verification.md)           | original-assisted `R = I_aligned - I_orig`, correlation, secret-layer differential pairs                                         |
| Consumption       | [`docs/consumption.md`](./docs/consumption.md)             | atomic `UPDATE … RETURNING`, idempotency, audit                                                                                  |
| Policy            | [`docs/policy.md`](./docs/policy.md)                       | scope language, expiry, revocation, key rotation (`kid`), WebAuthn binding                                                       |

Detailed companions:

- `docs/canonical-serialization.md` — deterministic CBOR rules
- `docs/error-semantics.md` — error codes & fail-closed behavior

## Maturity

Spec v1.0.0 corresponds to `capglyph-core` v0.1.0. Carrier v1 (`HMAC-SHA256` framing, `Repetition8`/`BCH` ECC, DCT `F[2,3]`/`F[3,4]` and DWT Haar `LH` lattice) is **stable**. `Ed25519`/`ML-DSA` signatures and `RS` full correction are **reserved** for v1.1 / v2 (never stacked, negotiated via `version`/`kid`).

## Reading order

`spec.md` → `protocol.md` → `credential-format.md` → `image-binding.md` → `verification.md` → `consumption.md` → `policy.md`.

For security economics (carrier ≠ security bits, five attacks Guess/Forge/Extract/Detect/Steal) see the companion `CapGlyph/capglyph-docs` `cryptographic-security.md` (normative) and `capacity-robustness-and-threats.md` (measured FER).

## Conformance

```bash
capglyph conformance test --vectors ../capglyph-test-vectors/vectors
python3 ../capglyph-test-vectors/scripts/conformance.py --vectors ../capglyph-test-vectors/vectors
```

All `valid/` vectors must `open` and verify; all other categories must fail with the documented error code.

## License

Apache-2.0 — same as `CapGlyph/capglyph-core`.
