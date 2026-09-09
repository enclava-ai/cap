# Static TLS certificate validation (enclava-init)

`src/tls_certificate.rs` provisions the tenant-ingress TLS certificate through
the workload-attested broker and validates retained state on the encrypted
`tls-state` volume before reuse.

## Trust model

- Every chain — retained on disk or freshly delivered by the broker — is
  validated with `rustls-webpki` `EndEntityCert::verify_for_usage` for
  `serverAuth` against the independently trusted public root store
  (`webpki-roots`, the Mozilla CA certificate programme). Path building
  enforces per-certificate signatures, issuer validity windows, CA basic
  constraints/path lengths, name constraints, and the serverAuth EKU.
- Certificates carried inside a chain never extend the trust store. A
  trailing self-signed root, a root sent in the same broker response, a
  leaf-only chain, or a chain rooted at an untrusted CA all fail closed.
- The leaf must cover every configured hostname, and a signature probe
  verifies the leaf was issued for exactly the retained/generated private key.
- The public root store deliberately does not contain the Let's Encrypt
  **staging** roots, so staging-issued chains are rejected by default.
  Production evidence (enclava-work, reviewed 2026-09-09) shows the live
  `ACME_DIRECTORY_URL`/`TENANT_CADDY_ACME_CA`/signed-release
  `tenant_caddy_acme_ca` all point at the production Let's Encrypt directory,
  whose chains validate against the public store. A future staging deployment
  needs explicit, separately reviewed trust support (e.g. pinned reviewed
  staging roots plus a signed issuer selection); it must never be inferred
  from URLs, chain contents, or broker responses, and it is not implemented
  here.

## Retained-state policy

- Reuse is only permitted when `certificates/tls.crt` and
  `certificates/tls.key` are regular files (no symlinks, including dangling
  ones; no directories or other non-regular inodes; stat errors fail) and the
  full anchored validation passes. Repeated valid reuse performs zero broker
  calls.
- Invalid retained state aborts init without ordering a replacement
  certificate and without replacing the retained private key. Recovery is
  explicit operator removal of the stale `tls.crt`.
- Only an actually missing certificate (`ENOENT`) starts issuance. A
  certificate-less retained key is kept and reused for the new CSR, so an
  interrupted first issuance retries with the same key.
- Fresh broker responses are validated with the same anchored checks before
  `tls.crt` is written.

`notBefore` tolerates at most 300 s of clock skew (validation is retried at
the certificate's own `notBefore`); expiry is strict at the current time.
