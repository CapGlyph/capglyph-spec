# Policy — Scope, Revocation, Expiry, and Key Management

**Spec:** 1.0.1 · **Track:** Policy (CTX-0041)

---

## 1. Policy ≠ primitive

Per `infrastructure-positioning.md`, CapGlyph is **infrastructure** (Core/Security) like `OpenSSL` — it provides `embed/extract/verify/envelope/robustness`. Policy (expiry, quota, revocation, scope, transfer, MFA, recovery, risk) is **Application** and lives in the issuer/consumer, not in the carrier. Spec defines the wire and the DB invariants; deployments define the allowable `scope` vocabulary and the WebAuthn binding thresholds.

## 2. Scope language

- `scope` is `JSONB TEXT[]` in `credentials.scope` — e.g. `["download:asset:42"]`, `["event:venue:2026-09:01:entry"]`.
- Server `MUST` authorize via `authorize_scope(credential.scope, request)` after `atomic_consume` returns the row; scope failure is a post-consume but still fail-closed rejection (`E_SCOPE_DENIED`, optional code — treat as `E_AUTH_FAILED` for external callers to avoid oracle).
- Scopes are **declarative capabilities**, not ACL queries — the credential _is_ the authority.

## 3. Expiry

- Two columns: `not_before TIMESTAMPTZ` (nullable) and `expires_at TIMESTAMPTZ` (nullable).
- A credential is live iff `now()` ∈ `[not_before, expires_at]` (or the bound that exists). `E_EXPIRED` otherwise.
- Clock skew tolerance: verifiers `SHOULD` allow `±30 s` (configurable) on `not_before` to absorb client/server skew; they `MUST NOT` allow skew on `expires_at`.
- `verify` and `consume` both enforce expiry; `revoke` remains valid on an expired credential (to close the audit edge).

## 4. Revocation

- Single column `revoked_at TIMESTAMPTZ` (nullable). Set by `POST /v1/credentials/{id}/revoke` → `UPDATE credentials SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`.
- Any credential with `revoked_at IS NOT NULL` `MUST` fail both `verify` and `consume` with `E_REVOKED`, regardless of `use_count` or temporal window.
- Vectors: `vectors/revoked/` store `mock_revoke: true`; harness `MUST` treat the crypto-valid fixture as policy-revoked and assert `E_REVOKED` without touching the carrier.

## 5. Quota

- `max_uses BIGINT` (nullable → unlimited) and `use_count BIGINT NOT NULL DEFAULT 0`.
- Only `atomic_consume` (`UPDATE … RETURNING` with `use_count < max_uses`) mutates `use_count`. See `consumption.md` §4 for the exact SQL and idempotency.

## 6. Key rotation (`kid` / `key_id`)

- `credentials.key_id TEXT NOT NULL` (`kid`) references `KMS` key material (`K_embed`/`K_mac`/`K_object` split per `keying::KeyMaterial`). Rotation is **not** in-band in the image — the DB row selects the key; the image only carries `token_id`.
- When roles are derived, implementations `MUST` use the RFC 5869 schedule and exact domain strings in `interoperability-profile.md` §3. They `MUST NOT` substitute an all-zero key, reuse one role for another, or fall back to a process default when `kid` lookup fails; missing material is `E_KEY_NOT_FOUND` before envelope processing.
- Rotation flow: `KMS` generates new `kid` → new issuer config `kid = cred-2026-09` → new credentials seal with `K_mac(new_kid)` → verifiers `MUST` accept both old and new `kids` during the overlap window, looked up from the credential row (`kid` in `SELECT`).
- Wire future (v2): `FrameHeader` gains an explicit `kid` byte or CBOR string so offline verification can select the signing key without a DB hit. v1 has no wire `kid`; mix-up is prevented by the DB join.

## 7. WebAuthn binding (high-value scopes)

- Low-value (coupon/preview): `image possession → consume` suffices.
- High-value (recovery, wallet, admin, long-lived identity): `image possession → extract credential_id → server challenge → WebAuthn assertion → consume`. Stolen image alone is not sufficient.
- Spec does not mandate WebAuthn for v1 GA, but `policy` `MUST` declare for each `scope` whether WebAuthn is required, so auditors can reason about carrier theft (DC01 in `cryptographic-security.md` §3 — bearer copyability is not prevented by larger keys).

## 8. Cover hygiene

- `issuance_count` on `covers` and optional per-family cover variants (light deterministic crop/tonal/noise) mitigate multi-copy collusion averaging (median/mean of `C+Δ1, C+Δ2, …` leaks `C`).
- Verifiers that return confidence scores `MUST` rate-limit (`verify oracle` mitigates removal-tuning attacks).

## 9. References

- `research/media-credential/usage/credential-design.md` §2 (opaque token, why expiry/quota stay in DB)
- `research/media-credential/technology/cryptographic-security.md` §§2–5 (entropy, five attacks, complexity is attack surface)
- `research/media-credential/architecture/infrastructure-positioning.md` (Core vs Application)
- `capglyph-test-vectors` `vectors/{expired,revoked,valid}/`
