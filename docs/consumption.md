# Consumption — Atomic Consume, Idempotency, and Audit

**Spec:** 1.0.1 · **Track:** Consumption (CTX-0041) · **Normative for** `capglyphd` / `capglyph-server`

---

## 1. Principle: server is authoritative

The credential image is a **bearer** — copying the file copies possession. Damage is bounded by `scope × expiry × quota × revocation × audit × WebAuthn` (policy, not crypto), and the server is the only writer of `use_count` / `revoked_at` / `consumed_at`. The image's embedded `token_id` is an opaque locator (`SHA256(token_id)` is the DB key); the image never self-authorizes.

## 2. State machine

```
ISSUED ── verify (read-only) ──▶ ISSUED
  │  consume (atomic, mutating) │
  │  ┌─────────────────────────┘
  ├──▶ CONSUMED  (use_count >= max_uses or one-time spent)
  ├──▶ EXPIRED   (now() outside [not_before, expires_at])
  └──▶ REVOKED   (revoked_at IS NOT NULL)
```

Any terminal state is fail-closed: no consume, no re-issue of the same `token_id`. `verify` `MUST NOT` mutate `use_count`.

## 3. Schema (normative minimal, Postgres)

From `credential-design.md` §4:

```sql
CREATE TABLE covers (
    id              UUID PRIMARY KEY,
    sha256          BYTEA NOT NULL UNIQUE,
    object_uri      TEXT NOT NULL,
    width           INTEGER NOT NULL,
    height          INTEGER NOT NULL,
    format          TEXT NOT NULL,
    family_id       UUID,
    issuance_count  BIGINT NOT NULL DEFAULT 0,
    status          TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE credentials (
    id              UUID PRIMARY KEY,
    token_hash      BYTEA NOT NULL UNIQUE,   -- SHA256(token_id)
    cover_id        UUID NOT NULL REFERENCES covers(id),
    subject_id      UUID,
    scope           JSONB NOT NULL,
    mode            TEXT NOT NULL,
    schema_version  INTEGER NOT NULL,        -- framing version
    key_id          TEXT NOT NULL,           -- kid
    embed_params    JSONB NOT NULL,
    output_sha256   BYTEA NOT NULL,
    not_before      TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    max_uses        BIGINT,
    use_count       BIGINT NOT NULL DEFAULT 0,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE credential_consumptions (
    id              UUID PRIMARY KEY,
    credential_id   UUID NOT NULL REFERENCES credentials(id),
    idempotency_key TEXT NOT NULL,
    actor_id        UUID,
    consumed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    request_hash    BYTEA,
    outcome         TEXT NOT NULL,
    UNIQUE (credential_id, idempotency_key)
);

CREATE TABLE audit_events (
    id              UUID PRIMARY KEY,
    event_type      TEXT NOT NULL,
    object_id       UUID,
    actor_id        UUID,
    event_data      JSONB,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

`token_id` raw bytes `MUST NOT` appear in logs; only `token_hash` is logged.

## 4. Atomic consume (the one thing to get right)

```sql
BEGIN;

INSERT INTO credential_consumptions (id, credential_id, idempotency_key, actor_id, request_hash, outcome)
VALUES ($cid, $cred_id, $idempotency_key, $actor, $req_hash, 'attempt')
ON CONFLICT (credential_id, idempotency_key) DO NOTHING
RETURNING id;

-- If the insert was a no-op (duplicate idempotency_key), return the prior outcome without mutating.
-- Else:

UPDATE credentials
SET use_count = use_count + 1
WHERE id = $cred_id
  AND revoked_at IS NULL
  AND (not_before IS NULL OR not_before <= now())
  AND (expires_at IS NULL OR expires_at > now())
  AND (max_uses IS NULL OR use_count < max_uses)
RETURNING id, use_count, max_uses;

-- Only a returned row authorizes; emit audit_events and commit.
COMMIT;
```

Mapping to errors (fail-closed, no quota burn):

| `UPDATE` result                                      | Policy   | Spec error             |
| ---------------------------------------------------- | -------- | ---------------------- |
| 0 rows, `revoked_at IS NOT NULL`                     | revoked  | `E_REVOKED`            |
| 0 rows, `now() > expires_at` or `now() < not_before` | temporal | `E_EXPIRED`            |
| 0 rows, `use_count >= max_uses`                      | quota    | `E_CONSUMED`           |
| 1 row                                                | success  | — (return `use_count`) |

Concurrent `consume` callers `MUST` contend on the `UPDATE` row lock (`FOR UPDATE` is implicit in `UPDATE … RETURNING`); spec forbids `SELECT` then `UPDATE` (lost-update).

## 5. Idempotency

- `consume` `MUST` require `Idempotency-Key` (header or `request.idempotency_key`). The key is stored in `credential_consumptions` with `UNIQUE (credential_id, idempotency_key)`. Network retries with the same key replay the prior outcome without double-consuming.
- `issue` `MAY` also require `Idempotency-Key` so duplicate `issue` calls do not double-insert covert duplicate rows for the same logical credential.

## 6. Audit & forensics

Per credential, emit `audit_events` with at least:

```
{ event_type: "credential.consumed" | "credential.verify" | "credential.revoked" | "credential.expired",
  object_id: credential_id,
  actor_id,
  event_data: { cover_sha256, output_sha256, submitted_sha256, embed_profile, extraction_metrics,
                sigil_version, signer_certificate?, timestamp, request_hash },
  occurred_at }
```

For disputes, preserve the forensic package: `original_cover.sha256 + issued_image.sha256 + submitted_image.sha256 + credential_record.json + embed_profile.json + extraction_metrics + spec_version + signer_certificate? + timestamp + signed_audit_log`. Chinese electronic-data / e-signature rules mean `HMAC` alone is not a legal signature — pair with `Ed25519 / C2PA + trusted timestamp + custody chain` if court value is needed.

## 7. Vectors exercising consumption

`vectors/expired/` and `vectors/revoked/` in `capglyph-test-vectors` are **valid at the crypto layer** (`HMAC` + CBOR + ECC pass) but `expired`/`revoked` at the policy layer. The harness `MUST` validate them in two phases: (a) `framing::open` succeeds, (b) the mock policy check (`expires_at` / `revoked_at` in the fixture) maps to `E_EXPIRED`/`E_REVOKED` and never burns quota. `valid/` vectors are `ISSUED` and `live`; the harness also `MUST` demonstrate that two `consume` calls with the same `idempotency_key` yield one increment and an idempotent replay.

## 8. References

- `research/media-credential/usage/credential-design.md` §§3–6
- `CapGlyph/capglyph-cli` `crates/capglyph-server/src/{db,service}.rs` (reference `atomic_consume`)
- `capglyph-test-vectors` `vectors/{expired,revoked,valid}/` + `manifest.json`
