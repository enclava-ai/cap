# Enclava CAP Security Review

Date: 2026-04-25
Verification pass: 2026-04-25
Scope: `crates/enclava-{api,engine,cli,common}`, `deploy/api/`

Threat model source: `README.md` says CAP runs containers inside hardware-encrypted enclaves and that the operator cannot read user data, secrets, or memory, even with root on the host. No repo-local `CLAUDE.md` was present in this checkout during this verification pass.

## Executive Summary

The confidentiality chain does not hold. The highest impact issues are confirmed in active code paths: KBS resource release is not bound to the deployed image or `cc_init_data`, the Kata agent policy is fail-open, the CLI trusts ordinary WebPKI TLS without attestation-bound certificate verification, and the Cloudflare DNS token is copied into operator-readable Kubernetes Secrets.

Several findings in the prior draft were overstated and have been corrected below. In particular, the digest-resolution TOCTOU claim is not accurate as written because `verify_image` rejects a digest mismatch; rollback currently records a database row but does not re-apply manifests; axum `Bytes` extractors have a default 2 MiB limit; and the StatefulSet does not enable shared PID namespaces.

## Confidentiality Chain

The intended chain is:

```text
user CLI -> attestation-pinned TLS -> TEE Caddy -> unlock -> LUKS volume
                                      -> KBS releases seed only to signed image
                                      -> workload runs inside SEV-SNP
```

The chain currently breaks at multiple independent points:

| Link | Verification result |
|---|---|
| CLI authenticates the TEE | Confirmed broken. `tee_client.rs` builds a normal `reqwest` client with WebPKI roots and optional invalid-cert mode, but no attestation-to-certificate binding. |
| Tenant TLS belongs only to the tenant workload | Confirmed broken. The API loads `CLOUDFLARE_API_TOKEN`, passes it into `AttestationConfig`, creates a tenant namespace `Opaque` Secret, and Caddy reads it as `CF_API_TOKEN`. |
| Only the signed workload image can get KBS secrets | Confirmed broken. TLS KBS bindings render empty `allowed_images` and empty `allowed_init_data_hashes`. |
| Kubernetes control plane cannot introspect the guest | Confirmed broken by policy. `cc_init_data` emits `default AllowRequestsFailingPolicy := true`. |
| Operator cannot plant or rotate TLS seeds | Confirmed broken. `kbs-resource-writer` can create/delete any `cap-*-tls` resource when reachable and has no auth if its token is unset. |
| Tenant and app identifiers cannot collide or inject policy syntax | Confirmed broken. Org names have no validation, app domains are globally collidable, and `cc_init_data` uses raw string formatting. |

## Verification Corrections

These prior-draft findings were changed during source verification:

| Prior claim | Corrected result |
|---|---|
| "TOCTOU between digest resolve and cosign verify lets DB digest and verified digest differ." | Not confirmed. `cosign::verify_image` calls `triangulate`, then rejects `source_image_digest != digest` at `cosign.rs:147-152`. Keep the digest parser and `SKIP_COSIGN_VERIFY` risks, but remove this as a standalone critical. |
| "Rollback re-applies previous digest without cosign verify." | Not confirmed as written. `rollback` inserts a deployment row and audit entry only; it does not update `app_containers` or call `apply_deployment_manifests`. This is a correctness bug. When rollback is implemented, it must reverify the digest and signer before applying. |
| "No body size limit; webhook accepts 1 GB." | Not confirmed. axum 0.8 `Bytes` extractors have a default 2 MiB limit. Still add explicit route limits and an early `Content-Length` cap for clarity and DoS defense. |
| "App container shares PID/IPC with sidecars." | Not confirmed. `PodSpec` does not set `shareProcessNamespace`, `hostPID`, or `hostIPC`. The confirmed issue is privileged root containers with `SYS_ADMIN` in the same pod/guest trust domain. |
| "User env can override `SECURE_PV_*` today." | Not reachable through the current API: DB container env is not populated from user input. Reserve engine-controlled env names before adding env support. |
| "KBS Rego in active reconcile path is raw text-spliced." | Partially corrected. Active `crates/enclava-api/src/kbs.rs` uses `serde_json::to_string` for rendered strings. The legacy/test-facing `crates/enclava-engine/src/manifest/kbs_policy.rs` still uses raw `format!`, and `cc_init_data.rs` still raw-formats TOML/Rego. |
| "Multi-arch index signing means children are unsigned." | Overstated. Signing an index digest is normal because the index content addresses child manifests. The real risk is policy/runtime digest ambiguity: record and bind the actual digest the runtime reports in attestation, and document whether it is an index or platform manifest digest. |

## Critical Findings

| ID | Finding | Evidence | Remediation |
|---|---|---|---|
| C1 | KBS TLS bindings do not bind image digest or `cc_init_data` hash. Empty `allowed_images` and `allowed_init_data_hashes` mean KBS policy cannot prove the requesting guest is the intended workload. | `crates/enclava-engine/src/manifest/kbs_policy.rs:32-37`, `crates/enclava-api/src/kbs.rs:681-704` | Add digest/init-data columns to `kbs_tls_bindings`; populate them from the verified deployment digest and `compute_cc_init_data`; render non-empty allow arrays; make the Trustee policy fail closed on empty allow arrays for CAP-managed entries. |
| C2 | Kata agent policy is fail-open. Agent requests not explicitly handled by policy are allowed. | `crates/enclava-engine/src/manifest/cc_init_data.rs:47` | Change default to deny, then add explicit allow rules only for boot/start operations needed by the workload. Add negative tests for `kubectl exec`, attach, logs, cp/file read, and container mutation. |
| C3 | CLI does not bind TEE TLS to attestation. A valid public CA certificate is enough. | `crates/enclava-cli/src/tee_client.rs:86-93` | Implement an attestation-pinned TLS verifier: bind leaf SPKI hash plus domain and nonce into SNP `report_data`; verify the report before sending passwords/config; remove runtime invalid-cert modes from production builds. |
| C4 | Cloudflare token is available to the operator and tenant namespace. It can be used to obtain valid certificates for tenant hostnames. | `crates/enclava-api/src/main.rs:137-141, 148-180`; `crates/enclava-engine/src/manifest/secrets.rs:9-32`; `containers.rs:327-331`; `volumes.rs:56-68` | Stop copying the token into Kubernetes Secrets. Prefer TLS-ALPN-01/HTTP-01 over the attested path. If DNS-01 remains, release a tightly scoped token through KBS only to a measured Caddy image/init-data pair and rotate the existing zone token. |
| C5 | Cosign verification can be bypassed at runtime and audit state is hardcoded true. | `crates/enclava-api/src/cosign.rs:114-121`; `routes/deployments.rs:303-304`; `DEPLOYMENT.md:80` | Make bypass a debug/test-only compile-time path; fail API startup if it is enabled in production; store the actual verification result and signer identity in `deployments`. |
| C6 | Image trust is platform-wide, not tenant-bound. A single configured public key verifies every tenant image. | `crates/enclava-api/src/cosign.rs:35-52, 122-186` | Store per-app or per-org allowed signer identity at app creation. Prefer Fulcio/OIDC identity constraints or tenant-owned public keys. Bind signer identity and digest into the deployment record and KBS policy. |
| C7 | `kbs-resource-writer` is operator-domain seed materialization with optional auth. If `KBS_RESOURCE_WRITER_TOKEN` is unset, writes are unauthenticated; if set, it is static bearer auth and compared with ordinary equality. | `crates/enclava-api/src/bin/kbs-resource-writer.rs:81-90, 187-204`; `crates/enclava-api/src/kbs.rs:272-293` | Remove this service from the steady-state design and derive TLS seed material inside the TEE from attested owner material. Transitional hardening: require a non-empty token at startup, use constant-time verification, use mTLS or in-cluster NetworkPolicy, log every write/delete, and deny deletes except cleanup. |
| C8 | Org/app/domain identifiers collide and flow into Kubernetes, KBS identity, and DNS without enough validation. Org names are unvalidated; app names are only unique inside an org; `domain = {app}.enclava.dev` is therefore globally collidable. | `routes/orgs.rs:41-104`; `routes/apps.rs:150-187, 263`; `dns.rs:253-263`; `crypto.rs:9-17` | Validate org names with DNS-1123 rules, reserve system prefixes, and enforce combined namespace length. Make platform domains globally unique, for example `{app}-{org-slug}.enclava.dev`, or add a global unique index on generated domain. Replace colon-concatenated identity hashes with length-prefixed canonical encoding. |
| C9 | Raw string template generation can break TOML/Rego when untrusted identifiers contain quotes, braces, or triple quotes. Active KBS reconcile escapes strings, but `cc_init_data` and the legacy engine KBS generator do not. | `cc_init_data.rs:49-55, 91-97`; `manifest/kbs_policy.rs:66-119`; active escape: `kbs.rs:733-739` | Use structured renderers: `serde_json::to_string` for Rego literals and `toml_edit` or `toml` serialization for TOML. Add tests with quotes, braces, newlines, `'''`, and colon-containing identifiers. Remove or fix the legacy generator so tests cannot bless unsafe output. |
| C10 | Org admins can assign `owner` and overwrite existing roles, including demoting the current owner. | `routes/orgs.rs:174-210, 316-323` | Only owners can grant/revoke owner/admin. Prevent self-demotion if it would leave zero owners. Block admins from changing owner roles. Add transactional role checks and tests for invite/update/remove edge cases. |
| C11 | Billing webhook trusts mutable webhook metadata for tier, accepts empty secret, compares HMAC with `==`, and lacks replay protection. | `routes/billing.rs:322-369`; `main.rs:197-198`; `migrations/0003_api_keys_billing_audit.sql:34-44` | Store `requested_tier`, expected amount, and invoice purpose in `payments`. Reject empty webhook secret at startup. Use `mac.verify_slice()` after hex-decoding the header. Store processed webhook event IDs and make updates idempotent with `WHERE status = 'pending'`. Fetch invoice state server-side from BTCPay before upgrading. |
| C12 | Registry and attestation fetching are SSRF-capable. User-controlled registry hostnames are accepted if they contain `.`, and the shared `reqwest::Client::new()` follows redirects. | `main.rs:244`; `registry.rs:73-80`; `cosign.rs:198-258` | Use a dedicated registry client with `redirect::Policy::none()`, HTTPS-only, response size limits, DNS/IP deny lists for loopback/link-local/RFC1918/cluster CIDRs, and preferably an explicit registry allowlist. Apply the same client to optional attestation/SBOM fetches. |
| C13 | Domain ownership is not proven. Managed-zone names can be overwritten, including platform hostnames if another org creates the same app name. | `routes/domains.rs:62-80`; `dns.rs:24-31, 247-263`; `routes/apps.rs:263` | For custom domains, require DNS TXT proof under `_enclava-challenge.<domain>` before writing A/AAAA records. For platform domains, make generated hostnames globally unique and reject attempts to set `*.enclava.dev` as a custom domain unless it is the app's own assigned hostname. |

## High Findings

- HAProxy and Caddy config injection through weak domain validation. `custom_domain` only checks `contains('.')`, then flows into HAProxy SNI text and Caddyfile/Gateway hostnames. Validate FQDNs with a parser, reject whitespace/control chars/wildcards unless explicitly supported, and render config through structured APIs where possible. Evidence: `routes/domains.rs:62`, `edge.rs:181-220`, `ingress.rs:50-80`, `gateway.rs:155-190`.
- CLI key path traversal through org names. `bootstrap_key_path(org, app)` joins org directly. Validate org names server-side and add a client-side path-component guard using `components()` to reject `..`, separators, absolute paths, and Windows prefixes. Evidence: `crates/enclava-cli/src/config.rs:88-92, 149-185`; `commands/org.rs:42-55`.
- NetworkPolicy egress allows `world` on TCP 80/443. Decide whether workloads are allowed arbitrary egress. If not, replace with per-app egress policy or explicit registries/APIs. Evidence: `network_policy.rs:110-121`.
- NetworkPolicy ingress allows every Envoy pod matching namespace `tenant-envoy` and label `app.kubernetes.io/name=envoy`. Tighten to the exact gateway service account, namespace labels controlled by the platform, or Cilium identities. Evidence: `network_policy.rs:36-42`.
- SSA uses `force()` broadly. This makes CAP take ownership of conflicting fields and also means operator-side field changes can be overwritten without forensic visibility. Keep force only where necessary, record managed fields, and add immutable attestation-critical checks before apply. Evidence: `apply/namespace.rs:8`, `apply/resources.rs:26`, `apply/statefulset.rs:18`, `apply/gateway.rs:86`, `apply/network_policy.rs:79`.
- Drift detection trusts an operator-controlled annotation. It is useful for reconciliation but not security. Sign manifest hashes with the API key and verify inside the attested workload, or treat drift as advisory only. Evidence: `apply/orchestrator.rs:15-24, 99-115`; `apply/drift.rs:50-96`.
- Bootstrap supports runtime package install if `SECURE_PV_ALLOW_RUNTIME_INSTALL=true`. It is currently set false by generated manifests, but a control-plane patch can enable root package installation. Remove runtime install support from production images and require prebuilt images. Evidence: `bootstrap_script.sh:35-51, 62-78`; `containers.rs:68-86, 297-319`.
- App and Caddy containers are privileged root with `SYS_ADMIN`. The pod does not share PID by config, but the blast radius inside the Kata guest is still broad. Split storage bootstrap into a minimal init/sidecar with narrow capabilities, drop privileges before app start, and keep Caddy separate from user workload privileges where possible. Evidence: `containers.rs:139-150, 369-383`.
- ServiceAccount token automount is not disabled. Set `automount_service_account_token: false` unless the pod requires Kubernetes API access, and add tests for the generated ServiceAccount/PodSpec. Evidence: `service_account.rs:16-24`; `statefulset.rs:111-124`.
- Unlock mode transitions are ordinary member operations and do not prove the TEE-side transition completed. Require owner/admin role, require a TEE-signed transition receipt, and make the DB update conditional on that receipt. Evidence: `unlock.rs:174-370`; role is available in `AuthContext` at `auth/middleware.rs:217-223`.
- Rate limiting trusts client-forwarded IP headers via `SmartIpKeyExtractor`. Use trusted proxy middleware or peer IP only unless the request came from a known proxy. Add per-account login throttling. Evidence: `lib.rs:29-43`.
- JWTs lack `iss`, `aud`, and token type. Add issuer, audience, `typ`/`token_use`, `jti`, and separate validations for session vs config tokens. Evidence: `auth/jwt.rs:10-26, 67-78, 80-108`.
- Runtime TLS insecure modes are production footguns. Gate `TENANT_TEE_TLS_MODE`, `TENANT_TEE_ACCEPT_INVALID_CERTS`, `ENCLAVA_TEE_TLS_MODE`, and `ENCLAVA_TEE_ACCEPT_INVALID_CERTS` behind debug/test builds or fail startup in production. Evidence: `main.rs:17-22, 230-234`; `tee_client.rs:11-18, 86-93`.
- `ImageRef::parse` accepts invalid digest strings and double `@`. Validate digest algorithm and hex length, reject additional `@`, reject empty components, and use an OCI reference parser if possible. Evidence: `crates/enclava-common/src/image.rs:21-31, 84-90`.

## Medium Findings

- Permissive CORS (`Any/Any/Any`) is applied globally, including unauthenticated routes. Restrict allowed origins/methods/headers by deployment environment. Evidence: `lib.rs:200-205`.
- Removed members keep sessions and API keys. Add membership versioning or token revocation checks, and delete/suspend API keys created by removed users when appropriate. Evidence: `orgs.rs:323`; `auth/middleware.rs:149-165`.
- API-key validation uses Argon2 against all keys sharing a 16-bit prefix. Use a random 128-bit lookup prefix plus HMAC-SHA256 with a server-side pepper for stored verification. Evidence: `auth/api_key.rs:70-72, 116-145`.
- `cc_init_data` does not bind runtime class in the agent policy. Add runtime class or equivalent measured runtime evidence where Kata exposes it, and fail if the runtime annotation/runtimeClassName is absent. Evidence: `statefulset.rs:111-113`; `cc_init_data.rs:38-80`.
- User command is shell-interpolated into `sh -c`. Store command/args separately and invoke bootstrap as `exec "$@"` after a `--` delimiter. Evidence: `containers.rs:96-110`.
- Sidecar images are digest-pinned but not cosign-verified. Verify `ATTESTATION_PROXY_IMAGE` and `CADDY_INGRESS_IMAGE` at API startup and bind their digests into `cc_init_data` and KBS policy. Evidence: `main.rs:109-144`; `validate.rs:71-84`.
- Optional provenance/SBOM JSON parsing has no explicit response size/depth limit. Use limited response bodies and parse typed structures. Evidence: `cosign.rs:250-255`; `status.rs:54`.
- `ALLOW_EPHEMERAL_KEYS=1` works in production. Make it debug/test only and fail startup if enabled in production. Evidence: `main.rs:44-47, 101-104`.
- DB error strings leak on app creation. Return a generic error and log internal details server-side. Evidence: `routes/apps.rs:292-295`.
- `unlock_status` and `app_status` trust operator-routable domain status. Label these as unauthenticated/remote status unless returned with a valid TEE attestation signature. Evidence: `unlock.rs:107-121`; `status.rs:48-76`.
- Config-token issuance requires only org membership. Require write/admin scope, owner/admin role, and TEE-bound audience; consider user confirmation for password-mode apps. Evidence: `routes/config.rs:26-70`.
- Trustee policy reconcile preserves policy outside CAP markers. That may be intentional for legacy policy, but in the operator-adversary model it is not a security boundary. Either own the full policy or verify/sign the effective policy. Evidence: `kbs.rs:575-679`.
- `COSIGN_ALLOW_HTTP_REGISTRY=1` downgrades all cosign registry access to plaintext. Restrict to debug/test or per-registry explicit config. Evidence: `cosign.rs:127-130`.
- Namespace length is unchecked after `cap-{org}-{app}` concatenation. Validate combined length before insert/apply. Evidence: `apps.rs:158-162`.
- NIP-98 `payload` tag is documented but not verified. Add payload hash verification before using NIP-98 for any mutating endpoint with a body. Evidence: `auth/nostr.rs:1-9, 69-91`.

## Low / Hygiene

- Pin Argon2 parameters explicitly instead of relying on `Argon2::default()`. Evidence: `auth/email.rs:27-40`.
- API signing public key logging is not secret, but keep credential-like log lines minimal. Evidence: `main.rs:210-214`.
- HAProxy lock is process-local while deployment uses `replicas: 2`; use optimistic concurrency/resourceVersion or a leader/lock object. Evidence: `edge.rs:16, 91-92`; `deploy/api/deployment.yaml:6-7`.
- `publish_not_ready_addresses=true` is a bootstrap tradeoff. Keep it documented and reduce exposed pre-ready endpoints. Evidence: `service.rs:29-34`.
- Email and invite lookups are exact-string/case-sensitive. Normalize email identifiers and response messages. Evidence: `auth/email.rs:59-69, 138-152`; `orgs.rs:181-198`.
- Positive findings still hold: `apply/teardown.rs` rejects invalid TLS, and manifest volumes do not use `hostPath`, `hostNetwork`, `hostPID`, or `hostIPC`.

## Detailed Remediation Plan

### Phase 0: Production Stopgaps

1. Fail API startup if `SKIP_COSIGN_VERIFY`, `COSIGN_ALLOW_HTTP_REGISTRY`, `ALLOW_EPHEMERAL_KEYS`, `TENANT_TEE_ACCEPT_INVALID_CERTS`, or empty `BTCPAY_WEBHOOK_SECRET` are present outside debug/test.
2. Rotate the Cloudflare token currently used by CAP and remove it from tenant namespaces. Inventory existing tenant Secrets named by `CLOUDFLARE_TOKEN_SECRET`.
3. Disable or firewall `kbs-resource-writer` unless a non-empty token and NetworkPolicy/mTLS are in place.
4. Add global domain uniqueness checks immediately: reject app creation if `{app}.{PLATFORM_DOMAIN}` already exists in `apps.domain` or `dns_records.hostname`.

### Phase 1: Restore the Confidentiality Chain

1. KBS binding redesign:
   - Add `image_digest`, `cc_init_data_sha256`, and optionally `sidecar_digests` columns to KBS binding tables.
   - Compute `cc_init_data` before `ensure_tls_binding`, persist its hash, and render it into `allowed_init_data_hashes`.
   - Render the verified workload digest into `allowed_images`.
   - Add policy tests where a wrong image, wrong init-data hash, wrong namespace, wrong service account, or wrong identity hash is denied.
2. Kata agent policy:
   - Change `AllowRequestsFailingPolicy` to false.
   - Add explicit allow rules for container create/start needed for the known workload and sidecars.
   - Add explicit deny tests for exec/logs/attach/cp and any request with a changed image, env, mount, namespace, service account, or annotation.
3. Attestation-pinned TLS:
   - Define `report_data = SHA256("enclava-tee-tls-v1" || domain || nonce || leaf_spki_sha256)`.
   - Extend the attestation proxy to return a nonce-bound SNP report and certificate binding.
   - Replace the CLI's default reqwest verifier with a rustls custom verifier that captures the leaf certificate and accepts it only after attestation validates the SPKI hash.
   - Cache pins per app instance only after verification, and rotate on redeploy with explicit user confirmation.
4. Tenant TLS issuance:
   - Prefer ACME TLS-ALPN-01 or HTTP-01 over the attested endpoint.
   - If DNS-01 remains, fetch the Cloudflare credential inside the TEE from KBS with the same image/init-data bindings as other secrets.
   - Use least-privilege per-zone tokens and short rotation periods.

### Phase 2: Identity, Input, and Domain Safety

1. Add `validate_org_name` mirroring app DNS-1123 validation, with max length chosen so `cap-{org}-{app}` stays within Kubernetes limits.
2. Migrate existing invalid org names to slugs while preserving display names; make tenant IDs immutable IDs or canonical slugs.
3. Replace `compute_identity_hash("{tenant}:{instance}:{pubkey}")` with canonical length-prefixed encoding, for example `u32be(len)||tenant||u32be(len)||instance||pubkey_hash`.
4. Use `serde_json`/`toml_edit` for all generated Rego/TOML/Caddy-adjacent values and add malicious identifier fixture tests.
5. Require DNS TXT proof for custom domains, and prohibit custom domains inside the managed platform zone unless explicitly assigned.

### Phase 3: Auth, Authorization, and Billing

1. Centralize route authorization helpers: `require_member`, `require_admin`, `require_owner`, `require_scope`.
2. Apply owner/admin checks to destructive routes: delete app, update unlock mode, domain changes, config-token issuance, member role changes.
3. Preserve at least one owner per org transactionally.
4. Store billing intent server-side (`requested_tier`, amount, invoice ID, purpose), then ignore webhook metadata except as informational.
5. Add replay-safe webhook processing keyed by BTCPay delivery/event ID and invoice ID.
6. Add account/email throttles independent of IP and normalize auth errors.

### Phase 4: Kubernetes and Runtime Hardening

1. Disable ServiceAccount automount on generated ServiceAccount and PodSpec.
2. Remove runtime package installation from bootstrap and require images to include needed tools.
3. Split privileged storage operations away from user workload execution; drop root and `SYS_ADMIN` before starting the app.
4. Replace world egress with a per-app egress policy model.
5. Treat manifest-hash annotations as reconciliation hints only. For security-sensitive drift, sign desired manifests and verify inside the TEE or through an attested controller.

### Phase 5: Verification Gates

1. Add unit tests for every validator: org name, domain, image digest, identity hash canonicalization, webhook signature, role transition.
2. Add manifest snapshot tests that assert KBS bindings contain non-empty image and init-data allow lists.
3. Add negative policy tests using OPA or the Trustee policy evaluator.
4. Add integration tests for:
   - wrong image digest cannot fetch KBS seed;
   - wrong `cc_init_data` hash cannot fetch KBS seed;
   - CLI refuses a valid public CA cert without matching attestation;
   - admin cannot promote to owner or demote last owner;
   - duplicate platform hostname is rejected.
5. Add deployment readiness checks that verify Kubernetes manifests were actually applied, not only that database rows were inserted.

## Reviewed Files

Primary files reviewed in this pass include:

`README.md`, `DEPLOYMENT.md`, `deploy/api/deployment.yaml`,
`crates/enclava-api/src/{main.rs,lib.rs,cosign.rs,registry.rs,dns.rs,edge.rs,kbs.rs,deploy.rs,models.rs}`,
`crates/enclava-api/src/routes/{apps.rs,deployments.rs,domains.rs,orgs.rs,billing.rs,unlock.rs,config.rs,status.rs}`,
`crates/enclava-api/src/auth/{middleware.rs,jwt.rs,email.rs,api_key.rs,nostr.rs}`,
`crates/enclava-api/src/bin/kbs-resource-writer.rs`,
`crates/enclava-engine/src/{types.rs,validate.rs}`,
`crates/enclava-engine/src/manifest/{cc_init_data.rs,kbs_policy.rs,containers.rs,statefulset.rs,secrets.rs,volumes.rs,network_policy.rs,gateway.rs,ingress.rs,service.rs,service_account.rs,bootstrap_script.sh}`,
`crates/enclava-engine/src/apply/{orchestrator.rs,drift.rs,namespace.rs,resources.rs,statefulset.rs,gateway.rs,network_policy.rs}`,
`crates/enclava-cli/src/{tee_client.rs,config.rs}`,
and the SQL migrations under `crates/enclava-api/migrations/`.
