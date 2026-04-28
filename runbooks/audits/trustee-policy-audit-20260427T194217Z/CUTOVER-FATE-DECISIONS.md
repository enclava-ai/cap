# Trustee Policy Cutover Fate Decisions

Date: 2026-04-28
Source audit: `REPORT.md`

## Decision

Do not flip `KBS_REQUIRE_SIGNED_POLICY=true` against the current production
policy body as-is.

The CAP-managed bindings can move to the signed-template path, but the
operator-owned legacy surface must be split before cutover. The audit found
legacy rules that are both broader than M5-strict allows and not attributable
to CAP-signed descriptors.

## Fate Table

| Policy surface | Fate | Rationale | Cutover action |
|---|---|---|---|
| CAP-managed TLS bindings between `# BEGIN CAP MANAGED TLS RESOURCE BINDINGS` and `# END CAP MANAGED TLS RESOURCE BINDINGS` | Replace with signed artifacts | CAP now records non-empty image/init-data/signer binding data for future deployments. These rows belong in the signing-service artifact table, not in operator-edited Rego. | Backfill each active CAP app by requesting a signed policy artifact from `policy-templates` and writing the signed envelope to Trustee. |
| CAP-managed owner bindings between `# BEGIN CAP MANAGED OWNER BINDINGS` and `# END CAP MANAGED OWNER BINDINGS` | Replace with signed artifacts | Same ownership as above; do not keep text block mutation after Trustee signed-policy enforcement. | Backfill owner-resource artifacts after Trustee workload-resource receipt patches land. |
| `flowforge-storage`, `flowforge-tls`, `flowforge-{0,1,2}-enclava-{a,b}-{state,tls}`, `flowforge-1-auto-1-{state,tls}`, `flowforge-1-hermes-agent-4-{state,tls}` | Keep only as transitional signed legacy fixtures | These appear to be live FlowForge resources. They cannot remain as unsigned operator-authored Rego, but dropping them without app migration risks data loss. | Convert each to a signing-service `legacy_fixture` artifact with digest-only `allowed_images`, no mutable tag prefixes, explicit namespace/service-account, and the current `allowed_init_data_hashes`. |
| `zeroclaw-storage`, `postgresql-demo-storage`, `redis-demo-storage` | Keep only if owner confirms production use; otherwise drop | These are non-CAP/demo resources outside the CAP app DB. They are not part of M5-strict unless represented by signed descriptors or explicitly documented as non-M5 legacy. | Require owner sign-off. If retained, convert to signed `legacy_fixture` artifacts and remove mutable tag prefixes. |
| `flowforge-1-mini-canary-*` state/tls resources | Drop | Audit classifies them as stale canary resources. They should not block M5-strict cutover. | Remove from GitOps policy and do not generate signed artifacts unless an owner reclassifies them as live before cutover. |
| `flowforge-1-mini-canary-*` owner resources | Drop | Same stale-canary classification. | Remove from GitOps policy; no signed artifact. |
| `flowforge-1-ot-1-owner`, `flowforge-1-ot-2-owner` | Drop unless owner signs off | Audit classifies them as stale OT owner resources. | Default drop. Owner sign-off before cutover may reclassify them as transitional signed fixtures. |
| `allowed_image_tag_prefixes` and `binding_allows_mutable_image_tags` | Drop for M5-strict | Mutable tags let the policy authorize code not committed by a signed descriptor. | Signing-service templates must emit digest-pinned `allowed_images` only. Transitional fixtures may temporarily document mutable tags as non-M5 behavior, but cannot be used for M5-strict. |
| Generic helper rules (`requested_*`, `binding_*`, `owner_resource_*`, `allow if`) | Merge into the signing-service template only after review | The helpers are behavior, not data. They should be maintained as template source with tests, not as production-only drift. | Port the reviewed helper subset into `policy-templates/templates/trustee-resource-policy-v1.rego`; delete production-only copies after signed envelopes are deployed. |

## Required Cutover Steps

1. Build and publish the local `../trustee` Track 2 image with signed-policy
   enforcement, workload-attested policy body reads, attestation verify
   callback, and receipt/body policy inputs.
2. Build and publish the local `../policy-templates/signing-service` release
   that emits signed artifacts for CAP descriptors and, temporarily, approved
   `legacy_fixture` artifacts.
3. Backfill CAP app artifacts from the CAP DB. Every artifact must have a
   non-empty image digest and init-data hash binding.
4. Convert approved live non-CAP resources to signed `legacy_fixture` artifacts.
5. Remove stale canary/OT resources from the GitOps policy.
6. Remove all mutable tag-prefix authorization from the M5-strict policy path.
7. Re-run `runbooks/trustee-policy-audit.sh`; the expected result is:
   no policy body outside signed envelopes, no mutable tag-prefix path, no
   GitOps/live drift, and no CAP DB/Rego key drift.

## Current Blockers

- KBS admin metadata endpoint is still configured as `DenyAll`, so the audit
  script cannot query `/resource-policy` metadata directly.
- Owner sign-off is still needed for `zeroclaw-storage`,
  `postgresql-demo-storage`, `redis-demo-storage`, `flowforge-1-ot-1-owner`,
  and `flowforge-1-ot-2-owner`.
- Production cutover still depends on publishing/deploying the local Trustee
  and signing-service builds, wiring CAP deploy-time artifact backfill, and
  approving the legacy-resource fate table above.
