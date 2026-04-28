# CAP Launch Readiness Execution Plans

These plans turn the remaining launch-readiness work into executable gates.
They assume CAP is the control plane for new tenants, Flux tenant manifests stay
suspended for this path, tenant owners use only the `enclava` CLI, and operators
may use `ssh control1.encl` for cluster verification.

The launch bar is not "tests passed once". The bar is reproducibility,
operability, confidentiality preservation, and clear rollback.

## 0. Global Rules

### Required Environments

- `control1.encl`: operator access to the cluster.
- `lokalc.warrior`: clean-client machine for user-flow tests.
- GitHub repos:
  - `enclava-ai/cap`
  - `enclava-ai/attestation-proxy`
  - `enclava-ai/caddy-ingress`
  - `FlowForge-sh/enclava-ops-manifests`
- CAP API target: `https://cap-test01-enclava.enclava.dev`.
- Test tenant domain suffix: `enclava.dev`.

### Before Every Run

Run from the workspace:

```bash
git -C cap status --short
git -C attestation-proxy status --short
git -C caddy-ingress status --short
git -C enclava-ops-manifests status --short
ssh control1.encl 'kubectl get nodes -o wide'
ssh control1.encl 'kubectl -n cap-test01 get pods -o wide'
ssh control1.encl 'kubectl -n trustee-operator-system get deploy,svc trustee-deployment'
```

Pass criteria:

- Source repos are clean or all dirty files are explicitly part of the test.
- `master-1` and `worker-1` are `Ready`.
- `cap-api`, `postgres`, and `trustee-deployment` are ready.
- CAP `/health` returns `ok`.

### Evidence Artifacts

Each run must write artifacts under the ignored `docs/` tree so large reports
do not become release metadata accidentally:

```text
cap/docs/launch-readiness-runs/<YYYYMMDD-HHMMSS>-<run-name>/
```

Required files:

- `summary.md`: human-readable outcome and operator notes.
- `results.json`: structured timings and pass/fail data.
- `commands.log`: commands run from the clean client and operator nodes.
- `cluster-snapshot-before.txt`
- `cluster-snapshot-after.txt`
- `resource-usage.csv` for soak and stress tests.
- `cleanup-proof.txt` for destroy/DNS/KBS cleanup tests.

### Hard Failure Conditions

Stop and mark the run failed if any of these occur:

- Owner password or recovery material is logged outside the owner CLI context.
- CAP API receives password-bearing claim/unlock material.
- Tenant sidecars use mutable or temporary image tags.
- Tenant DNS is created but not removed after destroy.
- KBS policy/resource state remains after destroy.
- `worker-1` becomes `NotReady`, memory-pressure tainted, or accumulates orphaned QEMU processes.
- CAP health fails after a test.

## 1. Automated Clean-Client E2E Test

### Goal

Prove a new user can complete the full lifecycle with only `enclava` CLI and
public HTTPS:

1. signup
2. create app
3. deploy v1
4. claim initial password
5. write persisted data
6. deploy v2
7. verify persisted data survived
8. restart into locked state
9. unlock manually
10. enable auto-unlock
11. restart and verify auto-unlock
12. disable auto-unlock
13. restart locked again
14. unlock manually again
15. destroy
16. verify DNS and KBS cleanup

### Preparation

On `lokalc.warrior`:

```bash
ssh lokalc.warrior
mkdir -p ~/e2e/cap-clean-client
cd ~/e2e/cap-clean-client
rm -rf .enclava
export ENCLAVA_HOME="$PWD/.enclava"
export ENCLAVA_API_URL="https://cap-test01-enclava.enclava.dev"
enclava --version
```

Use real GHCR payload images, never `ttl.sh`.

Payload requirements:

- `/version` returns a version string.
- `/health` returns JSON containing version and a persisted state file path.
- v1 writes `/data/owner-lifecycle-state.json`.
- v2/v3/v4 keep reading the same file and report its original creation marker.

### Test Driver

Create or update a script in `cap/tools/clean_client_lifecycle.py` that:

- SSHes to `lokalc.warrior`.
- Creates an isolated `$ENCLAVA_HOME`.
- Creates a unique email/org/app name.
- Runs only `enclava` CLI commands for user actions.
- Talks to app public HTTPS for app health/data checks.
- Records timings for each phase.
- Never runs `kubectl` from the clean-client side.

Required high-level CLI flow:

```bash
enclava signup --email "$EMAIL" --password "$ACCOUNT_PASSWORD"
enclava org create "$ORG"
enclava create "$APP" --org "$ORG" --unlock password
enclava deploy --app "$APP" --image "$IMAGE_V1"
curl -fsS "https://${APP}.enclava.dev/version"
curl -fsS "https://${APP}.enclava.dev/health"
enclava deploy --app "$APP" --image "$IMAGE_V2"
enclava status --app "$APP"
curl -fsS "https://${APP}.enclava.dev/health"
enclava unlock "$APP"
enclava unlock-mode "$APP" auto-unlock
enclava deploy --app "$APP" --image "$IMAGE_V2"
enclava unlock-mode "$APP" password
enclava deploy --app "$APP" --image "$IMAGE_V2"
enclava unlock "$APP"
enclava destroy "$APP" --force
```

Operator-side verification may use `kubectl`, but must be separate from the
user-flow proof.

### Cleanup Verification

After destroy, verify from `control1.encl`:

```bash
APP=<app>
NS=<namespace>
ssh control1.encl "kubectl get ns $NS"
ssh control1.encl "kubectl -n trustee-operator-system logs deploy/trustee-deployment --all-containers=true --tail=300"
ssh control1.encl "kubectl -n trustee-operator-system exec deploy/trustee-deployment -- find /opt/confidential-containers/kbs/repository/default -maxdepth 1 -name '*${APP}*' -print"
```

DNS cleanup should be checked through CAP-owned Cloudflare reconciliation, not
by assuming Kubernetes deletion is enough. The test driver should call a CAP
admin/debug endpoint if one exists. If it does not exist, add a read-only
operator tool that queries Cloudflare by record name and writes the result to
`cleanup-proof.txt`.

### Pass Criteria

- All lifecycle phases pass without direct cluster calls from the clean client.
- v2 reads data created by v1.
- Password claim/unlock happen through the TEE endpoint, not CAP.
- Auto-unlock cycle returns to `unlocked` without password input.
- Password-mode restart returns `locked` and unlock succeeds.
- Destroy removes tenant namespace, CAP route, DNS record, KBS TLS seed, KBS
  owner-resource policy entries, and CAP DB active app state.

## 2. Parallel E2E Soak

### Goal

Prove CAP behaves predictably under multiple concurrent new users and does not
destabilize `worker-1`, Longhorn, KBS, DNS, or CAP Postgres.

### Scenarios

Run three soak tiers:

1. `parallel-2`: 2 users, full lifecycle, expected to pass before beta.
2. `parallel-5`: 5 users, full lifecycle, expected to pass before launch.
3. `parallel-10`: 10 users, create/deploy/destroy with staggered starts,
   expected to identify capacity limits before public launch.

Use `CAP_MAX_CONCURRENT_APPLIES=1` initially. The test measures queue time, not
just app boot time.

### Metrics To Collect

Per app:

- signup time
- create time
- deploy API response time
- time to pod scheduled
- time to TEE claim endpoint reachable
- first claim time
- time to public app health
- v2 redeploy time
- locked restart time
- manual unlock time
- auto-unlock restart time
- destroy time
- cleanup completion time

Cluster:

```bash
kubectl get nodes -o wide
kubectl top nodes
kubectl top pods -A
kubectl -n cap-test01 get pods -o wide
kubectl -n longhorn-system get pods -o wide
kubectl -n kube-system get pods -o wide
kubectl get events -A --sort-by=.lastTimestamp
ssh worker1.encl 'pgrep -a qemu-system-x86 || true'
ssh worker1.encl 'free -h; uptime; systemctl is-active k0sworker containerd-external nydus'
```

Longhorn-specific:

```bash
kubectl -n longhorn-system get volumes.longhorn.io
kubectl -n longhorn-system get engine,replica,instancemanager
kubectl -n longhorn-system logs -l app=longhorn-manager --tail=300
```

### Report

Generate:

```text
cap/docs/launch-readiness-runs/<run>/parallel-soak-report.html
```

The report must include:

- phase timing table
- p50/p90/p99 phase times
- failure table with exact phase and app
- cluster resource graphs
- worker health timeline
- QEMU process counts over time
- Longhorn attach/detach errors
- DNS and KBS cleanup proof

### Pass Criteria

- `parallel-5` passes twice in a row.
- No worker `NotReady`, memory pressure, Cilium failure, Longhorn manager OOM,
  or orphaned QEMU accumulation.
- Failed tenant deploys are terminal and explainable to the CLI.
- Cleanup succeeds for every app, including failed deploy attempts.

## 3. Disaster Recovery Drill

### Goal

Prove CAP can be rebuilt from Git plus SOPS secrets and still manage current
tenant state.

### Non-Destructive Drill

This is the first drill and should be done before any destructive restore.

1. Snapshot current state:

```bash
ssh control1.encl 'kubectl -n cap-test01 get all,secret,cm,pvc -o yaml > /tmp/cap-test01-before.yaml'
ssh control1.encl 'kubectl -n trustee-operator-system get deploy,svc,secret,cm,pvc -o yaml > /tmp/trustee-before.yaml'
```

2. Render source from `enclava-ops-manifests` with SOPS decryption.
3. Server-side dry-run it:

```bash
kustomize build <decrypted-cap-test01-overlay> | ssh control1.encl 'kubectl apply --server-side --dry-run=server -f -'
```

4. Apply source.
5. Roll CAP API.
6. Verify:

```bash
kubectl -n cap-test01 rollout status deploy/cap-api
kubectl -n trustee-operator-system rollout status deploy/trustee-deployment
curl -fsS https://cap-test01-enclava.enclava.dev/health
```

7. Pick an existing CAP-created tenant and run:

```bash
enclava status --app <app>
curl -fsS https://<app>.enclava.dev/health
enclava unlock <app>
```

### Destructive Staging Drill

Only after non-destructive drill passes:

- Restore CAP Postgres into a staging namespace.
- Point a staging CAP API at restored DB.
- Do not touch production tenant namespaces.
- Verify CAP can list apps and compute the same tenant namespace/app identity.

### Pass Criteria

- Source render matches live intent.
- CAP API and Trustee roll from source-backed manifests.
- Existing tenants continue serving or remain unlockable.
- No KBS resource/policy entries are lost.
- Recovery instructions fit in one runbook with no ad hoc shell history.

## 4. Secret Rotation Runbook

### Secrets In Scope

- CAP API signing key.
- CAP session HMAC key.
- CAP Cloudflare API token.
- BTCPay credentials.
- SOPS age key, as a higher-risk separate rotation.

### Rotation Principles

- Rotate one secret class at a time.
- Use dual-read/single-write compatibility where possible.
- Never print secret values in logs or test output.
- Update SOPS source before or immediately after live patching.
- Verify old credential rejection when safe.

### KBS Workload-Resource Writer Removal Verification

There is no longer a CAP-managed bearer-token writer for KBS resources. Before
launch, verify the old path is absent rather than rotating it.

Runbook:

1. Confirm no `kbs-resource-writer` Deployment, Service, or CAP env var exists.
2. Confirm CAP only reconciles Trustee policy bindings.
3. Confirm rekey/delete go through the attested workload-resource API with
   receipt envelopes.
2. Roll writer.
3. Roll CAP.
4. Smoke `PUT` and `DELETE` from CAP pod.
5. Remove previous token.
6. Roll writer again.
7. Verify old token is rejected with `401`.

### Cloudflare Token Rotation

Runbook:

1. Create new Cloudflare token with minimal zone permissions:
   - zone read
   - DNS edit for `enclava.dev`
2. Update SOPS `cap-api-secrets`.
3. Apply source.
4. Create and destroy a test app.
5. Verify DNS record creation and deletion.
6. Revoke old token.
7. Repeat DNS smoke.

### CAP Signing/HMAC Rotation

Implementation requirement:

- API JWT verification should support a previous HMAC key during a bounded
  grace period, or force sessions to expire on rotation.
- Config JWT public key rotation must coordinate with tenant `cc_init_data`.
  Existing tenants trust the embedded public key until redeployed.

Pass criteria:

- New sessions/config tokens work.
- Old sessions behave according to documented policy.
- Existing tenant config-token paths are not silently broken.

## 5. Worker Guardrails And Recovery

### Guardrails To Verify

- `CAP_MAX_CONCURRENT_APPLIES=1` set in live CAP.
- RuntimeClass overhead reserves Kata memory.
- Tenant ResourceQuota includes runtime overhead.
- Tenant namespaces have pod/security/network policies.
- CAP refuses or queues excessive concurrent deploys.

Verification:

```bash
kubectl -n cap-test01 get deploy cap-api -o json | jq '.spec.template.spec.containers[0].env'
kubectl get runtimeclass kata-qemu-snp kata-qemu-tdx kata-coco-dev -o yaml
kubectl get ns -l app.kubernetes.io/managed-by=cap -o name
kubectl -n <tenant-ns> get resourcequota -o yaml
```

### QEMU/Containerd Cleanup Runbook

Use only during non-production or declared incident response.

1. Cordon `worker-1`.
2. Stop new CAP applies.
3. Capture evidence:

```bash
ssh worker1.encl 'free -h; uptime; ps -eo pid,ppid,stat,comm,args | egrep "qemu|kata|containerd|tetragon|cilium|kube-proxy"'
kubectl get pods -A -o wide | grep worker-1
```

4. Scale test tenants down or destroy them through CAP.
5. Stop runtime services in order:

```bash
ssh worker1.encl 'sudo systemctl stop k0sworker containerd-external nydus'
```

6. Kill orphaned runtime processes by explicit PID list only. Do not use broad
   `pkill -f`.
7. Clear stale containerd runtime state only after evidence is captured.
8. Restart services:

```bash
ssh worker1.encl 'sudo systemctl start nydus containerd-external k0sworker'
```

9. Recreate unhealthy DaemonSet pods.
10. Run Kata smoke pod.
11. Uncordon.

Pass criteria:

- `worker-1` Ready.
- No orphaned QEMU after smoke pod cleanup.
- Cilium, kube-proxy, Longhorn, Tetragon, and promtail healthy.

## 6. Monitoring And Alerts

### CAP API

Required metrics/log alerts:

- `cap_api_apply_failed_total`
- `cap_api_apply_duration_seconds`
- `cap_api_deploy_queue_depth`
- `cap_api_dns_create_failed_total`
- `cap_api_dns_delete_failed_total`
- `cap_api_kbs_policy_update_failed_total`
- `cap_api_kbs_workload_teardown_failed_total`
- `cap_api_postgres_errors_total`

If metrics do not exist yet, add a `/metrics` endpoint and Prometheus scrape.

Immediate log-based alerts until metrics exist:

```text
CAP logs contain: "failed to apply", "dns", "Cloudflare", "KBS", "database error"
Trustee logs contain: workload-resource status >= 400
```

### Tenant And Worker Alerts

Alerts:

- worker memory pressure
- node not ready
- high QEMU process count
- Longhorn attach/detach errors
- Longhorn replica degraded
- Cilium agent not ready
- tenant pod pending over threshold
- tenant pod crashloop
- failed ACME issuance
- Caddy TLS-ALPN issuance failures

### Dashboards

Dashboards:

- CAP deploy lifecycle timings.
- CAP API request rate/errors.
- Trustee workload-resource request rate/errors.
- Cloudflare API failures.
- Worker memory/load/QEMU count.
- Longhorn volume attach latency and failures.
- Per-tenant pod phase/readiness.

Pass criteria:

- Every failure class has an alert and an owner-facing or operator-facing
  runbook.
- Alerts are tested by injecting at least one synthetic failure per class.

## 7. CAP Postgres Backup And Restore

### Goal

CAP database backup protects control-plane state. It must not be confused with
tenant workload backup.

### Backup Strategy

- Nightly logical dump with `pg_dump`.
- Optional WAL archiving once production volume grows.
- Encrypted off-cluster storage.
- Retention:
  - hourly for 24h
  - daily for 14d
  - weekly for 8w

### Backup Command Shape

Run from an operator job/pod in `cap-test01`:

```bash
pg_dump "$DATABASE_URL" --format=custom --no-owner --file=/backup/cap-$(date -u +%Y%m%dT%H%M%SZ).dump
```

The backup target must be encrypted before leaving the cluster. Acceptable
options:

- SOPS/age recipient for platform operators.
- Restic repository with encrypted password stored in SOPS.
- Object storage with client-side encryption.

### Restore Drill

1. Create isolated restore Postgres.
2. Restore latest dump:

```bash
pg_restore --clean --if-exists --dbname "$RESTORE_DATABASE_URL" cap-<timestamp>.dump
```

3. Start staging CAP against restored DB.
4. Verify:
   - users/orgs/apps listed
   - deployment records intact
   - app namespace identities match live
   - no write actions are taken against production tenants

Pass criteria:

- Restore completes from last backup.
- Staging CAP reads restored state.
- Recovery point objective and recovery time objective are recorded.

## 8. Tenant Workload Backup And Restore

### Confidentiality Model

Tenant PVC backups must never require platform access to plaintext. The
platform may back up encrypted block/PVC bytes. Plaintext backup inside the
mounted filesystem requires owner-controlled logic inside the TEE.

Two supported backup classes:

1. Platform crash-consistent encrypted backup:
   - Snapshot/copy Longhorn PVCs.
   - Data remains LUKS-encrypted.
   - Platform cannot inspect plaintext.
   - Restore may require filesystem recovery if snapshot was taken while busy.

2. Owner/application-consistent confidential backup:
   - Owner authorizes backup through `enclava` CLI.
   - Workload quiesces or writes an application-level snapshot inside the TEE.
   - Backup artifact is encrypted inside the TEE to an owner-supplied key or
     tenant-held backup key before leaving the confidential environment.
   - Platform stores opaque ciphertext only.

### Required CAP Features

- `enclava backup create <app>` for owner-triggered backup.
- `enclava backup list <app>`.
- `enclava backup restore <app> <backup-id>`.
- CAP API backup records and status.
- Tenant-side backup agent or proxy endpoint reachable only after owner unlock.
- Backup encryption public key registration.
- Restore flow that rehydrates PVC ciphertext before workload boot, or imports
  owner-encrypted application backup inside the TEE after boot.

### Platform Encrypted PVC Backup Test

1. Deploy app and write data.
2. Stop app cleanly if possible, or mark backup as crash-consistent.
3. Snapshot app-data PVC and tls-data PVC.
4. Restore into new app namespace.
5. Boot restored app.
6. Owner unlocks using same owner seed/password path.
7. Verify data exists.

Pass criteria:

- Platform never obtains LUKS key.
- Restored app unlocks only through owner/TEE path.
- TLS state either restores or reissues according to selected backup class.

### Application-Consistent Backup Test

1. Owner runs `enclava backup create`.
2. Workload writes backup artifact inside TEE.
3. Artifact is encrypted before egress.
4. Destroy original app or restore into a new app.
5. Owner runs restore.
6. Workload imports data inside TEE.
7. Verify application integrity.

Pass criteria:

- CAP stores only encrypted artifact metadata and opaque ciphertext.
- Restore requires owner authority.
- Backup integrity is verified before import.

## 9. Confidential Volume Resize

### Goal

Allow app-data and TLS-data volume growth without exposing plaintext or
reinitializing LUKS.

### Confidentiality Constraint

CAP may request a larger PVC. CAP must not access plaintext, LUKS keys, mounted
filesystems, or owner password material. LUKS and filesystem expansion must run
inside the tenant pod after the appropriate key is available.

### Design

Outer resize:

- CAP updates the StatefulSet volume claim template target in desired state and
  patches existing PVC requested storage.
- Kubernetes/Longhorn grows the block device.
- CAP records requested and observed size.

Inner resize:

- Startup script runs after `cryptsetup luksOpen`.
- It checks whether the opened mapper device is smaller than the underlying
  block device.
- If growth is needed:
  - run `cryptsetup resize <map>`
  - run filesystem check/grow for supported filesystems
  - for ext4: `resize2fs /dev/mapper/<map>`
- It writes a resize status file into the mounted encrypted filesystem and
  ownership signal directory.

Current bootstrap location:

- `cap/crates/enclava-engine/src/manifest/bootstrap_script.sh`
- Add resize check after `cryptsetup luksOpen` and before/after `mount` as
  appropriate:
  - `cryptsetup resize` before mounting.
  - `resize2fs` can run mounted for ext4, but the safer first implementation is
    run after open before handing control to the app, with clear error handling.

### API/CLI Requirements

CAP API:

- `PATCH /apps/{name}/storage`
- request:

```json
{
  "app_data_size": "20Gi",
  "tls_data_size": "4Gi"
}
```

- Only allow growth, never shrink.
- Enforce tier max storage.
- Enforce valid Kubernetes quantity.
- Create deployment/audit record.
- Patch PVCs:
  - `data-<statefulset>-0`
  - `tls-state-<statefulset>-0`
- Reapply StatefulSet desired size for future replacement pods.

CLI:

```bash
enclava storage resize <app> --app-data 20Gi
enclava storage resize <app> --tls-data 4Gi
enclava storage status <app>
```

Engine:

- `StorageSpec` remains desired size source.
- Manifest ResourceQuota must grow with requested storage.
- StatefulSet tests must assert updated VCT sizes.

### Resize Test Plan

1. Create app with `5Gi` app-data and `2Gi` TLS-data.
2. Deploy and claim.
3. Write a large marker file and checksum into `/data`.
4. Resize app-data to `10Gi`.
5. Wait for PVC `status.capacity.storage` to reach `10Gi`.
6. Restart pod.
7. Startup script runs `cryptsetup resize` and `resize2fs`.
8. Owner unlocks if password mode.
9. Verify:
   - checksum unchanged
   - `df -h /data` shows new size
   - LUKS UUID unchanged
   - no reformat occurred
   - owner seed unchanged
10. Repeat for TLS-data with Caddy cert state.

Negative tests:

- Shrink request rejected.
- Resize above tier limit rejected.
- Invalid quantity rejected.
- Resize while pod pending remains queued/observable.
- Missing `resize2fs` fails with clear startup error and does not corrupt data.

Pass criteria:

- No plaintext leaves TEE.
- Existing data survives.
- LUKS header and UUID remain stable.
- Filesystem size increases.
- App returns healthy after resize.

## 10. Staging vs Production ACME

### Goal

Use Let's Encrypt staging for tests and production for launch without hitting
production rate limits.

### Configuration

Current env:

```text
TENANT_CADDY_ACME_CA=https://acme-staging-v02.api.letsencrypt.org/directory
TENANT_TEE_TLS_MODE=staging
```

Production should use:

```text
TENANT_CADDY_ACME_CA=https://acme-v02.api.letsencrypt.org/directory
TENANT_TEE_TLS_MODE=production
```

### Protection Rules

- CI/soak must always use staging.
- Production ACME must require an explicit promotion flag.
- CAP should refuse bulk test app creation against production ACME unless a
  per-run override is set.
- Tenant TLS state must persist across restarts through the TLS-data LUKS
  volume and KBS TLS seed.
- Destroy/recreate tests in production ACME must use unique subdomains and
  strict rate-limit budgeting.

### Promotion Test

1. Run full clean-client E2E on staging.
2. Switch one controlled canary namespace to production ACME.
3. Create one app.
4. Verify certificate issuer is production.
5. Restart app twice.
6. Verify no reissuance unless expected.
7. Destroy app.
8. Verify DNS cleanup.
9. Switch test config back to staging.

Pass criteria:

- Production issuance works once.
- Restarts reuse persisted Caddy state.
- No repeated issuance loop.
- Staging remains default for automated tests.

## 11. Launch Gate Matrix

Launch candidate can proceed only when all rows are green:

| Gate | Required proof |
| --- | --- |
| Source clean | All repos clean, pushed, CI green |
| Clean-client lifecycle | Two consecutive full lifecycle passes |
| Parallel soak | `parallel-5` passes twice, `parallel-10` characterized |
| Destroy cleanup | DNS, namespace, CAP DB state, KBS policy/resources cleaned |
| Disaster recovery | Source-backed apply and restored CAP DB drill pass |
| Secret rotation | Cloudflare, BTCPay, API signing/session, and SOPS rotations tested |
| Worker guardrails | RuntimeClass, quotas, QEMU cleanup runbook tested |
| Monitoring | Alerts installed and synthetic failures tested |
| CAP DB backup | Backup and restore drill passes |
| Tenant backup | Encrypted PVC backup and owner-consistent backup plans tested |
| Resize | App-data and TLS-data growth tests pass |
| ACME | Staging default, production canary issuance, restart persistence |

## 12. Recommended Execution Order

1. Commit this plan.
2. Add metrics/log alert coverage for CAP and Trustee workload-resource writes.
3. Implement clean-client lifecycle driver.
4. Run clean-client lifecycle twice.
5. Implement parallel soak report generation.
6. Run `parallel-2`, then `parallel-5`.
7. Implement storage resize API/CLI/bootstrap growth.
8. Run resize tests.
9. Implement CAP Postgres backup job and restore drill.
10. Implement tenant encrypted backup/restore MVP.
11. Run disaster recovery drill.
12. Run secret rotation drills.
13. Run production ACME canary.
14. Freeze launch candidate, rebuild images, pin digests, run full suite.
