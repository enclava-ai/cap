# B4 — Trustee Policy Audit Playbook

Closes OID-10 / rev14 Phase 3 prerequisite. Inventory every Rego byte in production Trustee, separate CAP-managed from operator-added, decide each rule's fate before `replace_bindings_block` is deleted and the signing service takes over. Run as Trustee admin with `kubectl`.

## 1. CAP-managed Rego shapes

CAP edits one Rego document, in two named blocks, period.

- **Document:** ConfigMap `resource-policy` (key `policy.rego`) in namespace `trustee-operator-system`. The Trustee operator reconciles it into KBS's `KBS_POLICY_ID`. Source: `crates/enclava-api/src/kbs.rs:225-251`. Override via `KBS_POLICY_NAMESPACE` / `KBS_POLICY_CONFIGMAP` / `KBS_TRUSTEE_DEPLOYMENT`.
- **CAP-owned blocks** (sentinel comments, see `kbs.rs:579-613, 681-731`):
  - `resource_bindings := { ... # BEGIN CAP MANAGED TLS RESOURCE BINDINGS ... # END CAP MANAGED TLS RESOURCE BINDINGS ... }`
  - `owner_resource_bindings := { ... # BEGIN CAP MANAGED OWNER BINDINGS ... # END CAP MANAGED OWNER BINDINGS ... }`
- **Inside each CAP block:** map entries keyed `"<namespace>-<app>-tls"` and `"<namespace>-<app>-owner"`, with the fixed shape from `crates/enclava-engine/src/manifest/kbs_policy.rs:13-40` (`repository`, `tag`/`allowed_tags`, `allowed_namespaces`, `allowed_service_accounts`, `allowed_identity_hashes`).
- **Everything else** — `package`, `import`, `default allow := false`, every `allow if` rule, helpers, map keys outside the markers — is operator-owned legacy text (OID-5 "frozen legacy resource_bindings").

After cutover the signing service emits the whole file from a canonical template; non-marker text must either move into that template or be dropped.

## 2. What "outside CAP markers" looks like

Grep targets for the live dump:

- Map entries inside `resource_bindings` / `owner_resource_bindings` that sit before `# BEGIN CAP MANAGED` or after `# END CAP MANAGED` — frozen legacy.
- Any `allow if`, `deny if`, or helper rule body. CAP only writes data.
- Extra top-level declarations (`some_map := { ... }`, `default foo := ...`).
- Imports other than `rego.v1`.
- Binding keys not matching `^[a-z0-9-]+-(owner|tls)$`.
- Bindings with empty or wildcard (`["*"]`) `allowed_*` arrays — CAP always writes one concrete value.

## 3. Step-by-step audit commands

```bash
# 0. Pick names — adjust if env vars override
NS=trustee-operator-system
CM=resource-policy
KEY=policy.rego  # confirm with: kubectl -n $NS get cm $CM -o jsonpath='{.data}' | jq 'keys'

# 1. Dump the live ConfigMap (source CAP edits)
kubectl -n $NS get cm $CM -o yaml > trustee-cm.snapshot.yaml
kubectl -n $NS get cm $CM -o jsonpath="{.data.${KEY}}" > live-policy.rego

# 2. Dump what KBS itself has loaded (in case the operator hasn't reconciled, or someone POSTed directly)
KBS_POD=$(kubectl -n $NS get pod -l app=kbs -o jsonpath='{.items[0].metadata.name}')
KBS_ADMIN_TOKEN=...   # from the admin-keypair Secret (see runbooks/launch-readiness)
kubectl -n $NS exec "$KBS_POD" -- \
    curl -sf -H "Authorization: Bearer $KBS_ADMIN_TOKEN" \
    http://localhost:8080/kbs/v0/resource-policy \
    > kbs-list-policies.json
# Note: list_policies() returns metadata only (api_server.rs:345-352); no body endpoint exists
# pre-Phase-3. Cross-check it agrees the active KBS_POLICY_ID is the same one CAP is editing.

# 3. Fingerprint both
sha256sum live-policy.rego trustee-cm.snapshot.yaml

# 4. Slice the file into CAP-managed vs everything-else
awk '/# BEGIN CAP MANAGED/,/# END CAP MANAGED/' live-policy.rego  > cap-blocks.rego
awk '!/# BEGIN CAP MANAGED/,/# END CAP MANAGED/{next}1'           live-policy.rego  > non-cap.rego
# (Verify non-cap.rego does not contain any "# BEGIN CAP" string.)

# 5. List binding keys CAP currently owns (cross-check against DB)
psql "$CAP_DB_URL" -At -c \
  "SELECT binding_key FROM kbs_owner_bindings WHERE deleted_at IS NULL
   UNION ALL
   SELECT binding_key FROM kbs_tls_bindings   WHERE deleted_at IS NULL
   ORDER BY 1;" > cap-db-keys.txt

grep -oE '"[a-z0-9-]+-(owner|tls)"' cap-blocks.rego | sort -u > cap-rego-keys.txt
diff cap-db-keys.txt cap-rego-keys.txt   # must be empty
```

Expected `live-policy.rego` skeleton:

```
package policy
import rego.v1
default allow := false
resource_bindings := {
  # legacy entries (operator-frozen) ...
  ,
  # BEGIN CAP MANAGED TLS RESOURCE BINDINGS
  "ns-app-tls": { ... }, ...
  # END CAP MANAGED TLS RESOURCE BINDINGS
}
owner_resource_bindings := {
  # BEGIN CAP MANAGED OWNER BINDINGS
  "ns-app-owner": { ... }, ...
  # END CAP MANAGED OWNER BINDINGS
}
allow if { ... }   # operator-authored evaluation rules
```

## 4. Diff strategy vs the rev14 template

With `enclava-platform/policy-templates` checked out at the rev14 tag:

```bash
policy-templates/render.sh \
  --orgs <(psql "$CAP_DB_URL" -c 'select * from confidential_apps') \
  > rendered-rev14.rego
rego fmt rendered-rev14.rego > a.rego
rego fmt live-policy.rego    > b.rego
diff -u a.rego b.rego | tee policy-diff.patch
```

Classify every hunk against the risk register below.

## 5. Risk register

| Category | Likely intent | Action |
|---|---|---|
| Extra `allow if` clause pinning a sidecar `image_digest` (e.g. attestation-proxy) | Platform-component bootstrap | **Merge** into rev14 template; bake digest into `platform-release.json`. |
| Legacy `resource_bindings` entry for a workload not in CAP DB | Pre-CAP manual provisioning | **Document, migrate, drop**. If permanent fixture (KBS-internal seed), template it. |
| Loose rule (e.g. `input.tee == "snp"` with no further constraint) | Dev/staging bypass | **Drop** before cutover. |
| Wildcard `allowed_identity_hashes: ["*"]` | Debug override | **Drop**; incident-ticket if seen in prod. |
| `allow if input.snp.init_data == ...` (note `init_data`, not `init_data_hash`) | Hand-patch around rev11 claim-name bug | **Drop** — superseded by the Phase 3 Trustee claim-rename patch. |
| Rule referencing `input.kubernetes.*` | Pre-rev12 vestige | **Drop** — rev12 removed `input.kubernetes.*` (operator-controlled). |
| Comment / formatting drift | `kubectl edit` | Ignore; rev14 reformat overwrites. |

Unclassifiable hunks block cutover.

## 6. KBS resource paths CAP creates today

From `crates/enclava-engine/src/types.rs` and `crates/enclava-api/src/kbs.rs`. For each app `{namespace=cap-<orgSlug>, name}`:

- Owner ciphertext: `default/<namespace>-<name>-owner/seed-encrypted`, optional sealed copy `default/<namespace>-<name>-owner/seed-sealed`. Binding key `<namespace>-<name>-owner`.
- TLS seed: `default/<namespace>-<name>-tls/workload-secret-seed`. Binding key `<namespace>-<name>-tls`.

Example: org `acme`, app `api` → `default/cap-acme-api-owner/seed-encrypted` and `default/cap-acme-api-tls/workload-secret-seed`. Cross-check these against `list_policies()` output and workload-resource write/delete logs to confirm no stray paths.

**Exit criterion:** `policy-diff.patch` contains only CAP-authored renames; every binding key has a row in `kbs_owner_bindings` / `kbs_tls_bindings`; every operator-added rule has a ticket marked merge / drop / deprecate. Then Phase 3 cutover is safe.
