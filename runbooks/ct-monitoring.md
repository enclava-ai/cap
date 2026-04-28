# Certificate Transparency Monitoring

Phase 0 requires CT monitoring for `*.enclava.dev` and `*.tee.enclava.dev`
after the tenant Caddy cutover to TLS-ALPN-01. CAP cannot prevent every
misissued certificate by code alone; CAA is the preventive control and this
runbook is the detection control.

## Required DNS State

Publish CAA for the platform zone with the production Let's Encrypt account
URI:

```text
enclava.dev.       CAA 0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/<id>; validationmethods=tls-alpn-01"
enclava.dev.       CAA 0 issuewild ";"
tee.enclava.dev.   CAA 0 issue ";"
tee.enclava.dev.   CAA 0 issuewild ";"
```

Replace `<id>` with the production Caddy/Let's Encrypt account id before
publishing. Keep TTL low during rollout.

## Polling Check

Run from the CAP repo:

```bash
CT_DOMAIN=enclava.dev \
CT_ALLOWED_ISSUER_REGEX="Let's Encrypt" \
runbooks/ct-monitoring.sh
```

The script writes `runbooks/audits/ct-monitoring/report-enclava.dev.json`,
tracks newly seen crt.sh IDs, and exits non-zero if any certificate for the
zone is issued by an unexpected issuer.

## Alert Wiring

Schedule the script every 10-15 minutes and alert on exit code `2`. Store the
report artifact with the alert. A valid alert means either the allowed issuer
list is stale or a certificate was issued outside the expected ACME path.
