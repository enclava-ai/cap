# Trustee Policy Audit

- Namespace: `trustee-operator-system`
- ConfigMap: `resource-policy`
- Key: `policy.rego`
- Created: `2026-04-27T19:43:10Z`
- KBS admin endpoint: unauthenticated probe returned HTTP `401`; current KBS config has admin `DenyAll`, so metadata list could not be queried with an admin JWT.
- KBS loaded policy was read from `/opt/confidential-containers/opa/policy.rego` inside the KBS container.

Review:

1. `live-configmap-vs-kbs-loaded.patch` should be empty.
2. `cap-binding-key-diff.patch` must be empty before cutover.
3. Classify every rule in `non-cap.rego` using B4 risk register.
4. Diff `live-policy.rego` against `enclava-tenant-manifests/infra/trustee-kbs-policy/resource-policy.rego` from the repo checkout.
5. Record each operator-added rule as merge, drop, or known deviation before enabling `KBS_REQUIRE_SIGNED_POLICY=true`.
