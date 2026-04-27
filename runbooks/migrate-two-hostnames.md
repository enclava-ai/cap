# Runbook: migrate existing apps to the D1 two-hostname model

Phase 4 introduces two hostnames per app:

- App: `<app>.<orgSlug>.<platform_domain>` (Caddy / 443)
- TEE: `<app>.<orgSlug>.<tee_domain_suffix>` (attestation-proxy / 8081)

Pre-Phase-4 apps were created with a single hostname `<app>.<platform_domain>`
and one HAProxy SNI map entry. The one-shot tool below brings every existing
row up to the new contract without disrupting traffic to the old hostnames.

## Prerequisites

- Migrations 0011 (org slug), 0014 (custom domain challenges), and 0021
  (apps.tee_domain) applied.
- Cloudflare API token with edit access to the platform zone.
- HAProxy ConfigMap and DaemonSet env-aligned with the tooling defaults
  (`TENANT_HAPROXY_NAMESPACE`, `_CONFIGMAP`, `_DAEMONSET`).

## Steps

1. Snapshot the HAProxy ConfigMap (rollback insurance):

   ```bash
   kubectl -n tenant-envoy get cm haproxy-tenant -o yaml > /tmp/haproxy-tenant.bak.yaml
   ```

2. Run the migration (dry-run first by leaving CLOUDFLARE_API_TOKEN unset):

   ```bash
   DATABASE_URL=$DATABASE_URL \
   PLATFORM_DOMAIN=enclava.dev \
   TEE_DOMAIN_SUFFIX=tee.enclava.dev \
   TENANT_DNS_TARGET=$TENANT_DNS_TARGET \
   CLOUDFLARE_API_TOKEN=$CLOUDFLARE_API_TOKEN \
   CLOUDFLARE_ZONE_NAME=enclava.dev \
   ATTESTATION_PROXY_IMAGE=$ATTESTATION_PROXY_IMAGE \
   CADDY_INGRESS_IMAGE=$CADDY_INGRESS_IMAGE \
   API_URL=$API_URL \
   API_SIGNING_PUBKEY_BASE64=$API_SIGNING_PUBKEY_BASE64 \
   cargo run --release -p enclava-api --bin migrate-two-hostnames
   ```

   The tool is idempotent. It inserts new DNS records and HAProxy SNI
   map entries (old hostnames stay live so existing CLI users keep
   working) AND re-renders/SSA-applies each tenant's `*-tenant-ingress`
   ConfigMap so the new Caddyfile contains the new hostname pair. Per-app
   ingress re-render failures are logged and counted but do not abort the
   migration; the tool exits non-zero (code 2) at the end if any app
   failed so CI surfaces the partial outcome.

   `ATTESTATION_PROXY_IMAGE` and `CADDY_INGRESS_IMAGE` are required for
   the ingress regeneration step. If they are unset the tool logs a
   warning per app and skips ingress regeneration -- you must redeploy
   each app manually afterwards.

   Caddy in the tenant pod runs `caddy run` with no live config-watch
   sidecar, so existing pods keep serving the old Caddyfile until they
   restart. Plan a rolling restart (or `kubectl rollout restart sts -n
   <ns> <app>`) after the migration completes.

3. Verify the new hostnames resolve:

   ```bash
   dig +short <app>.<orgSlug>.enclava.dev
   dig +short <app>.<orgSlug>.tee.enclava.dev
   ```

4. Verify the HAProxy ConfigMap carries both `use_backend` lines and both
   `backend ...` blocks:

   ```bash
   kubectl -n tenant-envoy get cm haproxy-tenant \
     -o jsonpath='{.data.haproxy\.cfg}' | grep -E 'be_cap_.*_(app|tee)'
   ```

5. Verify each app's tenant-ingress ConfigMap contains the new hostname
   pair:

   ```bash
   for ns in $(kubectl get ns -l app.kubernetes.io/managed-by=enclava-platform -o name); do
     ns=${ns#namespace/}
     app=${ns#cap-*-}
     echo "=== $ns ==="
     kubectl -n "$ns" get cm "${app}-tenant-ingress" \
       -o jsonpath='{.data.Caddyfile}' | head -1
   done
   ```

   Each first line should be either the new `<app>.<orgSlug>.<platform>`
   hostname or that hostname plus a comma-separated custom domain.

5. After clients have moved to the new hostnames (one release cycle), use
   a follow-up cleanup binary or manual DELETE to remove the old DNS
   records and HAProxy entries.

## Rollback

```bash
kubectl -n tenant-envoy apply -f /tmp/haproxy-tenant.bak.yaml
kubectl -n tenant-envoy rollout restart daemonset/haproxy-tenant
```

DNS records can be removed individually via the Cloudflare dashboard or
the platform's `/apps/{name}/domains/{domain}` endpoint.
