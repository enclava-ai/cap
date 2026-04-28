# Trustee Policy Audit Report

Date: 2026-04-27
Cluster access: `ssh control1.encl`

## Result

Phase 3 cutover is not ready.

The live ConfigMap and KBS-loaded policy agree except for a trailing newline,
and CAP DB binding keys match the CAP-managed Rego keys. The blocker is the
large legacy/operator-owned policy surface outside CAP markers.

## Checks

| Check | Result |
|---|---|
| Live ConfigMap captured | PASS |
| KBS loaded policy captured from container | PASS |
| KBS `/resource-policy` metadata endpoint | BLOCKED: KBS admin config is `DenyAll`; unauthenticated probe returned 401 |
| Live ConfigMap vs KBS loaded policy | PASS: only trailing newline drift |
| CAP DB binding keys vs CAP-managed Rego keys | PASS: empty diff |
| GitOps source vs live policy | FLAG: live production policy has substantial drift from `enclava-tenant-manifests` |
| Operator-owned rules outside CAP markers | BLOCK: 1,156 lines require fate decisions |

## Operator-Owned Rules

Legacy binding keys outside CAP markers:

- `flowforge-storage`, `flowforge-tls`
- `flowforge-0-enclava-a-{state,tls}`, `flowforge-0-enclava-b-{state,tls}`
- `flowforge-1-enclava-a-{state,tls}`, `flowforge-1-enclava-b-{state,tls}`
- `flowforge-1-auto-1-{state,tls}`, `flowforge-1-hermes-agent-4-{state,tls}`
- `flowforge-1-mini-canary-owner`, `flowforge-1-mini-canary-2-owner`, `flowforge-1-mini-canary-auto-owner`
- `flowforge-1-ot-1-owner`, `flowforge-1-ot-2-owner`
- `flowforge-2-enclava-a-{state,tls}`, `flowforge-2-enclava-b-{state,tls}`
- `zeroclaw-storage`
- `postgresql-demo-storage`
- `redis-demo-storage`

Recommended fate before signed-policy enforcement:

| Category | Keys / rules | Fate |
|---|---|---|
| Permanent non-CAP workloads | FlowForge, ZeroClaw, demo DB/Redis if still production | Merge into the rev14 signing-service template as explicit platform-release fixtures, or migrate them into CAP-managed app rows before cutover. |
| Stale canary/OT owner resources | `flowforge-1-mini-canary-*`, `flowforge-1-ot-*` | Drop unless an owner signs off that they are still live. |
| Mutable tag prefix acceptance | `allowed_image_tag_prefixes` and `binding_allows_mutable_image_tags` helper path | Drop for M5-strict, or document as transitional non-M5 behavior. Digest-pinned images should be the only signed-template path. |
| Generic helper/evaluation rules | `allow if`, `requested_*`, `binding_*`, `owner_resource_*` helper rules | Merge only after review against rev14 template. The current helpers are operator-authored legacy policy, not CAP marker data. |

## CAP-Managed Block Note

The CAP-managed TLS bindings match CAP DB rows, but each current TLS binding
has empty `allowed_images`, `allowed_image_tag_prefixes`, and
`allowed_init_data_hashes`. That is expected from the current CAP issue list,
but it is not acceptable for M1/M5. The CAP team working those issues still
needs to populate digest/init-data bindings or move those checks into the new
signed template path.

## Artifacts

- `live-policy.rego`
- `kbs-loaded-policy.rego`
- `live-configmap-vs-kbs-loaded.patch`
- `cap-db-keys.txt`
- `cap-rego-keys.txt`
- `cap-binding-key-diff.patch`
- `gitops-vs-live-policy.patch`
- `non-cap.rego`
- `cap-blocks.rego`
- `sha256sums.txt`

