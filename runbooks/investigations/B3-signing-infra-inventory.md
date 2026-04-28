# B3 — Signing Infrastructure Inventory (Open Decision #14)

Resolves Open Decision #14 in `SECURITY_MITIGATION_PLAN.md`: build a separate
`enclava-platform/policy-templates` repo + an off-cluster signing service.

## What exists

**GitHub org: `enclava-ai`** (confirmed via remotes on `cap`,
`attestation-proxy`, `caddy-ingress`, `trustee`). `FlowForge-sh` org also in
play for `enclava-ops-manifests`.

**CI infra (GitHub Actions only):**
- `cap/.github/workflows/ci.yml` — fmt, clippy, test, doctest with PG service
- `cap/.github/workflows/release.yml` — multi-arch CLI release artifacts +
  SHA256SUMS, no signing
- `cap/.github/workflows/api-image.yml` — pushes `ghcr.io/enclava-ai/enclava-api`
  with `provenance: true` (SLSA build provenance) but no cosign signing step
- `attestation-proxy/.github/workflows/attestation-proxy-build.yml` — pushes
  `ghcr.io/enclava-ai/attestation-proxy:v2`, no signing
- `caddy-ingress/.github/workflows/image.yml` — same pattern
- `trustee/.github/workflows/*` — upstream's full CI (CodeQL, scorecard, release)

**Cosign in CAP (verifier only):** `cap/crates/enclava-api/src/cosign.rs`
**verifies** customer image signatures against
`COSIGN_PUBLIC_KEY_PATH` / `COSIGN_PUBLIC_KEY_PEM`. CAP itself never produces
cosign signatures. `SKIP_COSIGN_VERIFY` exists for dev only.

**Ed25519 signing primitive in CAP (runtime, not build-time):**
- `enclava-api/src/state.rs`, `auth/jwt.rs` — API holds an Ed25519 `SigningKey`
  for config JWTs (loaded from `pkcs8_der`, env var, or generated)
- `enclava-cli/src/commands/{app,ownership}.rs` — CLI generates per-app
  bootstrap keys and signs ownership challenges
- All `ed25519-dalek` v2 — same crate the signing service will need

**Existing Rego templates (legacy / not yet sovereign):**
- `cap/crates/enclava-engine/src/manifest/kbs_policy.rs`:
  `generate_kbs_policy_rego()` composes Rego strings inline in CAP. The plan
  mandates this code move out to the signing service.
- `enclava-tenant-manifests/infra/trustee-kbs-policy/*.rego` — three
  hand-maintained tenant-side policies (`attestation-policy-default_cpu.rego`,
  `resource-policy.rego`, `resource-policy_test.rego`).
- `trustee/kbs/sample_policies/*.rego` — upstream Trustee sample policies.

**No existing references to:** HSM, YubiKey, AWS KMS, GCP KMS in any CAP
source/docs. `trustee/kbs/docs/plugins/pkcs11.md` exists but is upstream
documentation, not platform infra.

## What is missing

1. The `enclava-platform/policy-templates` repo itself (does not exist anywhere
   under `confidential-infrastructure/`).
2. The signing service: no Rust crate, no Dockerfile, no deployment manifests.
   The plan describes it (`SECURITY_MITIGATION_PLAN.md` lines 81, 286, 304,
   438, 696) but no code.
3. Ed25519 signing keypair custody. CAP currently uses ad-hoc `SigningKey`s
   loaded from env. No CI secret, no HSM/KMS integration, no rotation policy.
4. `platform-release.json` artifact: signed bundle containing
   `policy_template_text` + `policy_template_sha256` referenced throughout
   rev13/rev14 — not produced by any current workflow.
5. Verify-pubkey ship path: nothing compiles a public key into `enclava-init`.
6. Bootstrap mechanism for the signing service's per-org `(org_id →
   owner_pubkey)` state (rev8 Finding #2 explicitly out-of-band).
7. Reference test vectors for Ed25519 over CE-v1 bytes (rev13 Finding #5).
8. Cosign image-signing step in any of the three image workflows
   (`api-image.yml`, `attestation-proxy-build.yml`, `image.yml`).

## Effort estimate — refute the "~1 week"

Plan line 1598 says ~1 week. **This is too low.** Realistic breakdown:

| Item | Days |
|---|---|
| New `policy-templates` repo: layout, canonical template text, SHA-256 self-check, test vectors | 1.5 |
| Signing-service Rust crate (axum, descriptor verifier, template loader, Ed25519 signer, persistent per-org owner-pubkey store, CE-v1 codec) | 3 |
| `platform-release.json` build pipeline + signing CI job | 1 |
| Key custody (CI secret minimum; GitHub OIDC + KMS preferred) + rotation runbook | 1 |
| Out-of-band per-org bootstrap CLI/admin endpoint | 1 |
| Embed verify-pubkey into `enclava-init` build | 0.5 |
| Cosign image signing for the service container | 0.5 |
| Integration tests against CAP API client (Phase 2 prerequisite) | 1.5 |

**Realistic: 2 weeks single engineer.** The "~1 week" assumes infra reuse that
does not exist. Two engineers can hit 1 week if work splits cleanly between
repo/CI and service crate.

## Recommended sequence

This work **gates Phases 2 and 3** (plan lines 32, 40, 688, 1619).

1. **Week -1 (parallel with Phase 0/1):**
   - Stand up `enclava-platform/policy-templates` repo with canonical Rego
     template extracted from `enclava-engine/src/manifest/kbs_policy.rs`.
   - Define CE-v1 test vectors (also unblocks `enclava-common` codec work).
   - Pick key-custody mode: minimum viable = GitHub Actions secret +
     environment protection rules; preferred = GitHub OIDC + Sigstore Fulcio
     keyless OR cloud KMS (no HSM hardware needed for v1).
2. **Week 0:** Build the signing service crate inside the policy-templates
   repo (or a sibling `signing-service` repo). Ship `platform-release.json`
   build job. Embed verify-pubkey constant into `enclava-init`.
3. **Phase 2 unlocks** once the service has a running `/sign` endpoint and CAP
   has an HTTP client. Phase 3 unlocks once Trustee-side signature
   verification (separate workstream) lands.

## Open questions for the platform team

1. Same-repo or separate repo for the signing-service code vs templates? Plan
   uses both phrasings. Recommendation: one repo, two crates.
2. Key custody target for v1 — GitHub OIDC + Sigstore? Cloud KMS? Plain CI
   secret with environment approval? (Plan says "CI/HSM" but lists no HSM.)
3. Where does the signing service run? Same k0s cluster (operator domain — bad)
   or a separate operator-trusted host? Plan implies "off-cluster" but never
   names the host.
4. How are per-org owner pubkeys bootstrapped in production? Manual admin
   endpoint? CLI `enclava org register` co-signed by maintainer?
5. Open Decision #8 ("GitHub Actions OIDC as default signer") — resolve
   together with #14 since they share key custody.
6. Plan mentions `policy_template_id` "kbs-release-policy-v3" suggesting v1/v2
   already exist. Confirm if this is forward-looking or references something
   already in `enclava-tenant-manifests/infra/trustee-kbs-policy/`.
