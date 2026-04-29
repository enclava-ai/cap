# External (non-CAP-repo) tracks gating M5

This file tracks platform/infra work that **is not in the `cap` repo** but
must land before the in-repo phases beyond M3 can ship. Owner is the
platform-eng / infra side, not the CAP application engineers. Created
2026-04-27 from `SECURITY_MITIGATION_PLAN.md` rev14 + the
`runbooks/investigations/B*` reports. Updated 2026-04-28 after the
cross-repo implementation pass, tenant TLS-ALPN cleanup, live Kata SNP LUKS
validation, cap-test01 signed-policy cutover, legacy namespace cleanup, and
Kata 3.28.0 genpolicy pinning.

The tracks below run **in parallel** with this repo's coding. PR #2, PR #3,
and PR #4 have landed in `cap`; these external tracks now gate production
cutover for Phase 0/2/3/6 and are required for the M5-strict claim.

---

## Track 1 — Off-cluster signing service + `enclava-platform/policy-templates` repo

**Why it exists.** Per D9 of the plan, CAP API is not allowed to compose
authoritative Trustee Rego under the threat model — an operator with cluster
root could swap the rendered Rego on the way to Trustee. The fix is an
off-cluster signing service that owns the Rego templates, owns its own
per-org owner-pubkey state, and signs reconstructed Rego with a key the
operator cannot reach.

**Gates:** Phase 2 (CAP signing-client + Kata fail-closed), Phase 3
(Trustee-side signed-policy enforcement), all of M1 and M5.

**Effort estimate:** coding v1 implemented; production deployment and key
custody remain platform work. cap-test01 currently points CAP at
`http://10.0.0.2:18080`; the off-cluster validation service behind that URL now
runs the public, keyless-signed `ghcr.io/enclava-ai/policy-signing-service`
digest with checksum-pinned Kata 3.28.0 `genpolicy` baked into the image. The
checked-in signing-service manifest is a scaffold and is not yet part of the
active cap-test01 kustomization because durable key custody and the deployment
target remain unresolved.

**What needs to happen, ordered:**

1. **Decide key custody.** No HSM exists in tooling today. Options ranked
   by fit:
   - **GitHub Actions OIDC + cosign keyless** — fits the existing
     `enclava-ai` GitHub org, no HSM purchase, key material is ephemeral
     per workflow run. **Recommended for v1.**
   - **GCP / AWS KMS** — adds a cloud dependency for key custody but
     standard tooling. ~2 days extra.
   - **Hardware HSM (YubiHSM, AWS CloudHSM)** — overkill for signing-only;
     add later if customers demand it.
2. **Create `enclava-platform/policy-templates` repo** with:
   - The per-platform-release Rego templates (one initial template
     committed; revisions bump `policy_template_id` + `policy_template_sha256`
     per the plan's rev13/rev14 fields).
   - `genpolicy` reference vectors (the plan uses
     kata-containers/genpolicy to render the agent policy from a customer's
     OCI runtime spec; pin a specific version per platform release).
   - CI that rebuilds the signing-service image on template change AND
     publishes the verify pubkey alongside each platform release.
   - Reference test vectors for the CE-v1 sign/verify path (per D11's
     reference-test-vector requirement).
   - **Status 2026-04-29:** done as sibling repo `../policy-templates` and
     pushed to `github.com/enclava-ai/policy-templates`. CI publishes and
     keyless-signs public `ghcr.io/enclava-ai/policy-signing-service` from
     `main`, with workflow-dispatch support and retrying cosign signing. The
     image verifies and extracts
     `kata-tools-static-3.28.0-amd64.tar.zst` at SHA256
     `825dbf929dc5fe3f77d1a473511fd8950f08b5f81b33803c79085dbc233ab94b`,
     and the service refuses `unconfigured` / `unpinned` genpolicy labels.
     Ownership model and production release publishing still need platform
     decisions.
3. **Write the signing service.** Small Rust HTTP service, separate Cargo
   project. Endpoints:
   - `POST /sign` — input `(app_id, deploy_id, customer_descriptor_blob,
     org_keyring_blob, platform_release_version)`; returns
     `SignedPolicyArtifact`. Verifies keyring owner-sig + descriptor sig
     against its own owner-pubkey table; renders Rego from the template;
     signs.
   - `POST /bootstrap-org` — accepts owner pubkey at org creation. URL
     bundled in CLI's `platform-release.json`, separate from CAP API.
   - `POST /rotate-owner` — accepts threshold-of-owners or recovery-contact
     directives per D10.
   - **Status 2026-04-28:** v1 implemented with descriptor/keyring
     verification, durable SQLite owner store, `/sign`, signed metadata,
     artifact verification, real genpolicy execution before signing, tests,
     and clippy.
   - **Manifest status 2026-04-29:** `../enclava-ops-manifests/overlays/cap-test01/policy-signing-service.yaml`
     exists but is not included in `overlays/cap-test01/kustomization.yaml`.
     Do not include it until key custody/deployment target are chosen; otherwise
     the rollout would move the signing key into the same trust boundary the
     plan is trying to remove.
4. **Decide deployment target.** Open question.
   - Separate cluster (highest isolation) — operationally heaviest.
   - Separate cloud account on the same K8s control plane —
     compromise.
   - On-prem hardware — fits if the platform already runs ops infra
     on-prem.
5. **Bootstrap publishing pipeline:**
   - Verify pubkey baked into each CAP release artifact (`platform-release.json`).
   - `enclava-init` compiles the verify pubkey in (or reads from the
     signed `platform-release.json`) — must already be present in the TEE
     when seed-release decisions happen.
6. **Bootstrap flow at org creation** (CLI side, requires Phase 7 full):
   - CLI generates owner keypair → POSTs pubkey directly to signing
     service URL.
   - Signing service records `(org_id, owner_pubkey, bootstrapped_at)` in
     its own DB.

**Deliverables:**
- `enclava-platform/policy-templates` repo with first Rego template + test
  vectors.
- Signing service deployed at a stable URL listed in
  `platform-release.json`.
- Verify pubkey published.
- Runbook for owner-pubkey bootstrap + rotation.

**Open questions for the platform leads:**
- Key custody choice (see #1 above).
- Deployment target (see #4).
- Who owns the signing-service repo / on-call rotation.

---

## Track 2 — Trustee upstream patches (6 of them)

**Why it exists.** The plan's M1 / M5 claim cannot be made on the unmodified
Trustee — `trustee/kbs/src/api_server.rs` accepts arbitrary policy bytes
from any admin-authorized caller and evaluates whatever's stored. Even with
CAP-side signing, an operator with cluster root could `curl` a malicious
policy directly to Trustee.

**Gates:** Phase 3 (signed-policy enforcement, M1 close-out), Phase 6
(workload-resource conditional writes + receipt-gated rekey/teardown).

**Effort estimate:** ~1.5 weeks for the patches themselves; **dominant
schedule risk is upstream maintainer coordination**, not engineering.

**Six patches, in dependency order:**

1. **SNP claim rename `init_data` → `init_data_hash`.** Currently
   `trustee/deps/verifier/src/snp/mod.rs:621-623` exposes the SNP
   `report.host_data` value as the JSON claim `init_data`. Plan's Rego
   templates reference `input.snp.init_data_hash` — currently undefined,
   silently evaluates to `false`. Half-day patch.
2. **Signed-policy enforcement at write + evaluation.** Add
   `KBS_REQUIRE_SIGNED_POLICY=true` flag. New code path in
   `api_server.rs::set_policy` parses the `SignedPolicyArtifact` envelope
   per D9, reconstructs the CE-v1 sign-input, calls `ed25519_verify`,
   rejects 400 if missing/invalid. Storage backend stores the full
   envelope; evaluator unwraps and verifies before passing Rego text to
   `regorus`. Negative tests: unsigned bytes rejected, tampered signature
   rejected, direct DB injection rejected at evaluation. ~3 days.
3. **Workload-attested `GET /resource-policy/<id>/body`.** Workload pods
   have no Trustee admin credentials, so `enclava-init` can't read the
   active policy via the existing `list_policies()` path. The new endpoint
   accepts the same SNP attestation token Trustee already uses for
   `GET /resource/...`, evaluates the resource's own Rego against the
   workload's claims, returns 403 if the workload wouldn't be authorized
   to *read* the resource. ~1.5 days.
4. **Conditional writes on `PUT /workload-resource/...`.** Add
   `If-Match: <expected-version>` and `If-None-Match: *` semantics
   backed by a version column in
   `trustee/kbs/src/plugins/implementations/resource/kv_storage.rs`.
   First-write-wins is `If-None-Match: *` returning 412 if the resource
   exists. Same patch adds DELETE conditional gating. ~2 days.
   **Local status 2026-04-28:** Trustee `If-None-Match`/`If-Match`
   existence prechecks are implemented, and local `../attestation-proxy`
   now sends the required create/replace/delete preconditions. A
   storage-level version/CAS column remains required before this is
   race-safe for production.
5. **Body inclusion in policy input + Rust receipt verification.** Extend
   `workload-resource` policy input from `{method, path, query}` to also
   include parsed body fields. Trustee Rust does the heavy lifting:
   parses JSON, extracts `body.receipt.{pubkey, payload_canonical_bytes,
   signature}`, computes `pubkey_hash_matches := sha256(receipt.pubkey)
   == report_data[32..64]`, computes `signature_valid := ed25519_verify(...)`,
   decodes CE-v1 records into typed fields, exposes booleans + structured
   fields to Rego. Rego becomes simple `==` comparisons (no
   `crypto.ed25519.verify` builtin needed). ~3 days.
   **Local status 2026-04-28:** Trustee parses receipt/body fields and
   attestation-proxy sends signed rekey/teardown envelopes with base64
   values. Attestation-proxy also rejects caller-supplied `runtime_data`,
   computes rev14 REPORT_DATA server-side, and binds
   `receipt_pubkey_sha256` into bytes 32..64. Focused and full
   attestation-proxy tests pass locally. The proxy now keeps internal HTTP
   on 8081 and serves external attested TLS on 8443; CAP/tenant Services
   keep `port: 8081` but target `8443` for the public attestation path.
6. **Attestation-verify callback `POST /kbs/v0/attestation/verify`.**
   For CAP API's workload-artifacts endpoint (rev14 finding #2). CAP API
   delegates token validation to this callback and receives back the
   parsed SNP claims including `init_data_claims.descriptor_core_hash`.
   Without this, the workload-attested artifacts endpoint can't be
   secured under the threat model. ~1 day.

**Two paths:**

- **Path A (preferred): upstream to `confidential-containers/trustee`.**
  Open coordination with maintainers. The B4 audit playbook can be shared
  to demonstrate concrete need. Schedule risk: maintainer review cycles.
- **Path B (transitional): fork `confidential-containers/trustee` as
  `enclava-ai/trustee` with a CAP-managed branch.** Apply patches, build
  + ship our own image. Loses upstream updates but unblocks immediately.
  Plan acknowledges this is acceptable only as transitional with M1/M5
  explicitly marked "not cryptographically enforced yet."

**Deliverables:**
- Either: 6 PRs landed upstream OR a maintained CAP fork branch. Changes
  exist in `../trustee`, and cap-test01 currently runs the forked validation
  image.
- Trustee container image rebuilt + published to a durable registry.
- CAP-side workload artifacts endpoint is implemented and gated by Trustee's
  attestation callback; CAP deploy-time signing-service client and artifact
  writes are implemented.
- Attestation-proxy image rebuilt + published with workload-resource
  preconditions and receipt envelopes.
- Tenant GitOps has stopped applying the historical Trustee resource-policy
  ConfigMap; signed-policy reconciliation now owns Trustee policy writes.
  cap-test01 has completed this handoff.

**Open questions:**
- Path A vs B (call before starting; affects calendar by weeks).
- Who owns the upstream relationship / fork maintenance.

---

## Track 3 — Kata SEV-SNP LUKS mount handoff

**Why it exists.** The original kernel-module hypothesis was wrong for the
current live runtime. `dm_mod` and `dm_crypt` are built into the Kata guest.
The actual sandbox blocker was a stale config path plus `[agent.kata]
kernel_modules`, which made kata-agent try to modprobe built-in-only features.
After fixing the actual config path and removing `kernel_modules`, base SNP
pods start and LUKS format/open/mount succeeds inside the guest.

**Gates:** Phase 5 integration design on real hardware.

**Effort estimate:** local v1 implemented and live validated.

**Current live finding:**

- Do not re-add `io.katacontainers.config.agent.kernel_modules` on the current
  runtime.
- Do use `/opt/kata/share/defaults/kata-containers/configuration-qemu-snp.toml`
  as the live handler config path.
- Do start workload containers first under a wait wrapper, then have the
  long-running mounter sidecar open/mount LUKS and mark ready. Creating a
  workload container after the mount already exists fails with `EINVAL`.

**Deliverables:**

- Updated `enclava-infra/ansible/` role/playbooks that remove stale
  `kernel_modules`, reject future module overrides, preflight built-in guest
  dm features, and validate the live app-starts-first + mounter-sidecar
  contract.
- Smoke test: 2-container pod where the verifier starts first, writes a
  sentinel, the mounter opens/mounts LUKS, marks ready, and the verifier
  confirms `/state` is the decrypted mount.

**Open questions:** none.

---

## Track 4 — Run the B4 Trustee policy audit against production

**Why it exists.** The plan's Phase 3 prerequisite (open decision #10)
calls for a production audit of current Trustee policy state to identify
operator-added rules outside CAP markers — those rules need to be either
folded into the rev14 template or documented for deprecation before
signed-policy enforcement is flipped on.

**Gates:** Phase 3 cutover (not Phase 3 coding).

**Effort estimate:** ~half day for an operator with KBS admin access.

**What to do:**

1. Read `runbooks/investigations/B4-trustee-policy-audit-playbook.md` — it
   has the runnable kubectl/curl/awk/psql commands.
2. Run against production. The CAP-managed Rego is bounded by these four
   verbatim sentinel comments (per `crates/enclava-api/src/kbs.rs:579-613`):
   - `# BEGIN CAP MANAGED TLS RESOURCE BINDINGS`
   - `# END CAP MANAGED TLS RESOURCE BINDINGS`
   - `# BEGIN CAP MANAGED OWNER BINDINGS`
   - `# END CAP MANAGED OWNER BINDINGS`
   Anything outside those four was operator-added.
3. **Also diff against** `enclava-tenant-manifests/infra/trustee-kbs-policy/resource-policy.rego`
   — the GitOps source-of-truth for the live ConfigMap, **not** just the
   live ConfigMap state. (B4 originally missed this; flagged afterwards.)
4. For each operator-added rule: classify as merge-into-template,
   drop-as-deprecated, or document-as-known-deviation. The B4 playbook has
   a 7-category risk register with recommended actions per category.

**Deliverables:**
- Audit report committed to the operator's runbook (not this repo).
- Each operator-added rule has a fate decision recorded.
- Sign-off that broader production cutover can keep signed-policy enforcement
  enabled without breaking existing tenant releases.

**Status 2026-04-28:** audit was run via `ssh control1.encl`; artifacts are
in `runbooks/audits/trustee-policy-audit-20260427T194217Z/`. The live
manifest cutover moved Trustee policy ownership out of tenant GitOps while
keeping the namespace managed: `../enclava-tenant-manifests/kustomization.yaml`
still includes `infra/trustee-kbs-policy`, but that sub-kustomization is now
ConfigMap-free. cap-test01 now runs the patched Trustee KBS image with
signed-policy enforcement enabled, and the live `resource-policy` ConfigMap is
a CAP-managed signed artifact. An unsigned raw-Rego negative test fails closed
at KBS startup. Full production M1 remains blocked by durable
Trustee/signing-service image rollout, key custody, upstream/fork ownership,
and fate decisions for the 1,156 lines of legacy/operator-owned policy.

**Open questions:**
- Fate decision owner for legacy/operator-owned policy lines.
- Sign-off threshold for promoting the cap-test01 signed-policy enforcement
  posture to broader production (one approver, two, infra lead).

---

## Track 5 — Tenant TLS-ALPN/no-DNS-plugin production cutover

**Why it exists.** CAP now renders tenant Caddy as TLS-ALPN-only and no
longer mounts tenant Cloudflare credentials, but production can still be
compromised by stale generated manifests or an old `caddy-ingress` image with
the Cloudflare DNS module.

**Gates:** Phase 0 item C and M0.

**Local status 2026-04-28:**
- `../caddy-ingress` Dockerfile builds Caddy without DNS-provider plugins and
  `scripts/smoke.sh` verifies the Cloudflare module is absent.
- `../enclava-tenant-manifests` confidential workload templates and generated
  instance kustomizations have TLS-ALPN-only Caddyfiles and no tenant
  `CF_API_TOKEN` mounts. Active overlays also route
  `/.well-known/confidential/*` to attestation-proxy. DNS-management jobs
  still use Cloudflare tokens for A/AAAA records and are not tenant pod
  secrets.
- The legacy `flowforge-1` static overlay was removed from root tenant GitOps
  in commit `4c28cf0` because its in-progress rewrite still contained
  placeholder cc-init-data and salt values. The live `flowforge-1` namespace
  and stale CAP-created test namespaces were deleted; validation now runs only
  through cap-test01 and CAP-generated manifests.
- CAP has `runbooks/ct-monitoring.sh` and `runbooks/ct-monitoring.md`.

**Production tasks:**
1. Publish CAA records with the production Let's Encrypt `accounturi` and
   `validationmethods=tls-alpn-01`.
2. Publish and deploy the no-DNS-plugin `caddy-ingress` image.
3. Reconcile CAP-generated tenant manifests so no future live tenant pod mounts
   a Cloudflare token.
4. Schedule CT monitoring and alert on unexpected issuers.

**Temporary rollout caveats:**
- cap-test01 has been promoted from `ttl.sh` validation refs to repo-owned GHCR
  digests for CAP API, enclava-init, attestation-proxy, caddy-ingress, and
  Trustee KBS. The remaining upstream images in the live Trustee pod are the
  Confidential Containers AS/RVPS images.
- cap-test01 sidecar provenance validation is active via GitHub Actions OIDC
  cosign policy over signed GHCR digest-pinned sidecar images. CAP now bundles
  a signed development `platform-release.json` carrying the cap-test01 sidecar
  image digests, signing-service pubkey, policy template text/hash, and
  Kata 3.28.0 genpolicy pin. CAP API consumes those signed anchors in
  signed-policy mode and refuses startup on env drift. The generated Kata agent
  policy is currently a signing-service gate; it still needs to become the
  `cc_init_data` policy body before this is a full Phase 2 production claim.
  The remaining blockers are generated-agent-policy wiring, production
  release-root custody, production release publishing, and signing-service
  deployment/key custody.
- `../policy-templates` publishes and signs public
  `ghcr.io/enclava-ai/policy-signing-service`, and the off-cluster validation
  Docker service on `control1.encl` has been promoted from `ttl.sh` to the
  signed GHCR digest while preserving its signing key env and owner DB mount.
  The live service now runs
  `ghcr.io/enclava-ai/policy-signing-service@sha256:e2fe819075b11155ab74770403bb439c200d58b0601fc4300378582ff040c2a4`;
  that image bakes the checksum-verified Kata tools archive and `/sign` runs
  `genpolicy` before signing the KBS artifact.
- Flux reconciliation is intentionally suspended and the Flux controllers are
  scaled to zero during manual rollout validation.
- The active ops overlay removed `kbs-resource-writer` and patches out the old
  writer token Secret. `overlays/cap-test01/kbs-resource-writer.yaml` remains
  as an unreferenced stale file and should be deleted by the ops owner.

---

## Cross-track dependency graph

```
[Track 1: signing service]    →    Phase 2  →  Phase 3  →  M1
[Track 2: Trustee patches]    ─────────────↗
                                         ↘
                                          Phase 6  →  M2
[Track 3: Kata kernel]        →    Phase 5 (integration test only)
[Track 4: Trustee audit]      →    Phase 3 cutover (gate)
[Track 5: Tenant TLS-ALPN]    →    Phase 0 cutover (gate)
```

Tracks 1 and 2 are the dominant critical path. Both have local v1 code; the
critical path has moved to durable signing-service key custody/deployment
target, production platform-release data, legacy policy fate decisions,
storage-level CAS, and the upstream-vs-fork decision for Trustee.

## Execution status

Last updated: 2026-04-29 by Codex external-track implementation pass, live Kata SNP validation, cap-test01 signed-policy cutover, legacy namespace cleanup, GHCR signed-image promotion, platform-release generator work, signing-service GHCR promotion, and Kata 3.28.0 genpolicy execution.

| Track | Owner | State | Started | ETA | Notes |
|---|---|---|---|---|---|
| 1 — Signing service | platform-eng | V1 + CAP-TEST01 SERVICE | 2026-04-27 | durable deployment TBD | `../policy-templates/signing-service` now has CE-v1 canonical bytes, descriptor/keyring verification, durable SQLite owner DB, `/sign`, signed metadata, artifact verification, real Kata 3.28.0 genpolicy execution, receipt-gated Rego rules, deterministic vector, docs, CI, tests, clippy, workflow-dispatch support, and a retrying GHCR publish/sign workflow. The latest successfully signed image digest is `sha256:e2fe819075b11155ab74770403bb439c200d58b0601fc4300378582ff040c2a4`, and anonymous pulls now work after the GHCR package was made public. CAP verifies returned policy artifacts against `SIGNING_SERVICE_PUBKEY_HEX` and writes the signed artifact to Trustee. cap-test01 currently points to the off-cluster validation service at `http://10.0.0.2:18080`; that Docker service now runs the signed GHCR digest with the same signing-key env and owner DB mount. CAP now rejects unsigned deploys and unlock-mode redeploys whenever signed-policy/signing-service infrastructure is configured, and the CLI sends customer-signed descriptor/keyring blobs for digest-pinned deploys plus auto-unlock mode transitions. CAP API now consumes the same signed development platform-release anchors in signed-policy mode. cap-test01 CAP API is live on `ghcr.io/enclava-ai/enclava-api@sha256:1dd80a03b0bff16605a613b02d2f35f8c953b0daed2eb13212b7f5c15193f67d`. `policy-signing-service.yaml` exists but is not included in the active kustomization because in-cluster deployment would move key custody into the cluster trust boundary. Remaining: wire generated Kata agent policy into `cc_init_data`/descriptor-hash flow, durable key custody or customer/CI-signed policy artifact replacement, deployment target, and production release publishing. |
| 2 — Trustee patches | platform-eng / Trustee maintainer | CAP-TEST01 LIVE VALIDATED | 2026-04-27 | upstream TBD | `../trustee` now has SNP `init_data_hash`, signed-policy write/evaluation enforcement, workload-attested policy body read, receipt/body policy inputs, required `If-None-Match`/`If-Match` preconditions, insert-if-absent storage writes, and attestation verify callback. cap-test01 runs the patched GHCR KBS image with signed-policy enforcement enabled, a signed CAP-managed `resource-policy` artifact, and KBS probes. Tenant GitOps keeps the namespace but no longer applies the historical resource-policy ConfigMap; CAP is configured with Trustee policy/body/artifact URLs and `TRUSTEE_POLICY_READ_AVAILABLE=true`. `../attestation-proxy` now binds receipt pubkey hash into REPORT_DATA, exposes external attested TLS on 8443 while preserving internal HTTP 8081, and publishes/signs its GHCR image from the repo workflow. `key-value-storage` tests pass locally; KBS/verifier focused tests are blocked in this workstation by missing Intel DCAP headers (`sgx_dcap_quoteverify.h`). Remaining: upstream-vs-fork decision, legacy-policy fate decisions, and per-resource version/ETag CAS. |
| 3 — Kata SNP LUKS handoff | infra / CAP | LIVE VALIDATED | 2026-04-27 | monitor per Kata bump | `../enclava-infra/ansible` now renders the actual Kata config paths, repairs shim aliases, removes stale `kernel_modules`, rejects future module overrides, and adds preflight/recover/validate playbooks. Syntax checks pass, host preflight passes on `worker-1`, and `runbooks/validate-kata-dm-crypt.yml` passes live. Verified contract: workload container starts first and waits, mounter sidecar opens/mounts LUKS, marks ready, and workload sees `/state` from `/dev/mapper/cap-smoke`. |
| 4 — Production audit | operator on-call | COMPLETED — FATE DECISIONS BLOCK FOR BROADER PROD | 2026-04-27 | fate decisions required | Ran via `ssh control1.encl`. Artifacts in `runbooks/audits/trustee-policy-audit-20260427T194217Z/`. The pre-cutover live ConfigMap and KBS-loaded policy matched except trailing newline; CAP DB keys matched CAP-managed Rego keys. cap-test01 now uses a signed CAP-managed policy artifact, so the legacy/operator policy is no longer live there. Fate decisions remain for 1,156 lines of legacy/operator-owned policy before durable template rollout. KBS admin metadata endpoint could not be queried because KBS admin is `DenyAll` (401). |
| 5 — Tenant TLS-ALPN cutover | platform-eng / CAP | CAP-TEST01 SIGNED GHCR ROLLOUT | 2026-04-28 | production DNS/platform-release TBD | `../caddy-ingress` now builds without DNS-provider plugins, smoke-tests absence of the Cloudflare module, publishes to GHCR, and signs the pushed digest through GitHub Actions OIDC. `../enclava-tenant-manifests` templates/generated instances no longer mount tenant Cloudflare tokens, render TLS-ALPN-only Caddyfiles, keep Caddy loopback proxying on HTTP 8081, and expose the public attestation Service port 8081 to attestation-proxy targetPort 8443. The legacy `flowforge-1` static overlay was removed from root GitOps and stale tenant/CAP namespaces were deleted, so no old tenant pod remains live. cap-test01 now uses repo-owned digest-pinned GHCR images for CAP/API and sidecars, with sidecar cosign verification pinned to the repo workflow identities. CAP has `runbooks/ct-monitoring.sh` and a signed development platform-release artifact for the cap-test01 sidecar/template/genpolicy anchors; CAP API consumes the same release anchors in signed-policy mode. Remaining: publish CAA records, reconcile future CAP-generated tenants, schedule CT alerting, and productionize platform-release signing-root custody. |

## Status field for each track

The execution table above is authoritative. The original creation-time status
table was removed after the local implementation pass to avoid stale
`NOT STARTED` entries conflicting with current cutover state.
