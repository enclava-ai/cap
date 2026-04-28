# B1: Let's Encrypt RFC 8657 CAA Support

**Question:** Does Let's Encrypt honor the RFC 8657 CAA extensions `accounturi` and `validationmethods` when issuing certificates?

**Verdict:** YES — both are honored in production.

**Confidence:** HIGH

## Evidence

### 1. Official documentation

Let's Encrypt's CAA documentation explicitly lists support for both parameters and names the three accepted validation-method strings: `http-01`, `dns-01`, `tls-alpn-01` — matching RFC 8657 verbatim.
- Source: <https://letsencrypt.org/docs/caa/>

### 2. Production rollout announcement

Let's Encrypt enabled ACME-CAA Account and Method Binding in production on **2022-12-16**. Hugo Landau (RFC 8657 author) noted this was the first known production deployment.
- Announcement: <https://community.letsencrypt.org/t/enabling-acme-caa-account-and-method-binding/189588>
- Background: <https://www.devever.net/~hl/acme-caa-live>

### 3. Boulder source

The CA implementation lives in `va/caa.go` in `letsencrypt/boulder` (<https://github.com/letsencrypt/boulder/blob/main/va/caa.go>). Relevant logic:
- `parseCAARecord` extracts parameters per RFC 8659 §4.2/§4.3.
- `caaAccountURIMatches` matches against configured account-URI prefixes; **a property with multiple `accounturi` parameters is unsatisfiable** (returns false).
- `caaValidationMethodMatches` validates method names with `^[[:alnum:]-]+$` and checks `caaMethod.IsValid()` against the internal ACME challenge whitelist (`http-01`, `dns-01`, `tls-alpn-01`).
- An "authorized" / "unauthorized" Prometheus counter is incremented at the end of evaluation.

### 4. Unrecognized-parameter handling (gap vs RFC 8659)

Boulder **silently ignores** unrecognized parameters in `issue`/`issuewild` properties. RFC 8659 §4.2 says CAs MUST NOT issue if a record contains an unrecognized parameter on a property they are processing. This is a known industry-wide deviation; the CABF Validation Subcommittee is in the middle of tightening this (see below).

### 5. CABF policy timeline (Feb 2026 SCWG)

Per the 2026-02-05 Validation Subcommittee minutes (<https://groups.google.com/a/groups.cabforum.org/g/validation/c/mIIhFrF1HJ8>):
- **2026-09-15:** Early-safety ballot — CAs must not treat RFC 8657 records as implicit authorization without explicit support.
- **2027-03-15:** Full compliance — all CAs MUST process `accounturi` and `validationmethods` per RFC 8657. Let's Encrypt already meets this.

### 6. Real-world reports

- 2020 community thread "Boulder ignores RFC 8657 accounturi" — predates production rollout, no longer applicable: <https://community.letsencrypt.org/t/boulder-ignores-rfc-8657-accounturi/123336>
- 2022 enablement thread confirms working in prod (no regressions reported through 2026): <https://community.letsencrypt.org/t/enabling-acme-caa-account-and-method-binding/189588>

## Recommended Action

**Proceed with the full CAA record as planned.** The pinned form

```
enclava.dev. CAA 0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/<id>; validationmethods=tls-alpn-01"
```

is fully enforced by Boulder today. Both belt (`accounturi`) and suspenders (`validationmethods=tls-alpn-01`) work — the SECURITY_MITIGATION_PLAN's "known gap" caveat about `validationmethods` can be removed.

**Operational notes:**
1. Do **not** include duplicate `accounturi` or `validationmethods` parameters — Boulder treats this as unsatisfiable and refuses issuance.
2. Confirm the platform's production ACME account ID before publishing the CAA record; an incorrect ID hard-blocks all issuance.
3. Stage the change in Let's Encrypt's staging environment first (`acme-staging-v02`) using the staging account URI; the same Boulder code path runs there.
4. Set DNS TTL low (300s) during initial rollout so a misconfigured `accounturi` can be reverted quickly.
5. Audit the CAA record at least quarterly — if the platform rotates ACME accounts, the CAA must update in lockstep.

## Confidence Justification

HIGH — three independent corroborating sources (official docs, public production announcement, current Boulder source code), plus active CABF policy work that assumes Let's Encrypt is already compliant. The only residual unknown is Boulder's silent ignoring of unrecognized parameters, which does not affect the platform's recipe (all parameters used are RFC-defined and Boulder-recognized).
