# Enclava CAP

**Heroku-like deploys for AMD SEV-SNP confidential workloads.**

CAP is a PaaS for running containers inside hardware-encrypted enclaves.
Developers push an OCI image; the platform handles TEE provisioning, encrypted
storage, attestation, key management, and TLS. The operator cannot read user
data, secrets, or memory — even with root on the host.

> Status: early. The API, engine, and CLI crates are functional; production
> use requires an AMD SEV-SNP cluster with the companion attestation-proxy.

## Quick start

```bash
docker compose up --build
curl http://localhost:3000/health
```

That brings up the API against a local PostgreSQL. See [DEPLOYMENT.md](DEPLOYMENT.md)
for production deployment, environment variables, and Kubernetes manifests.

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    CLI      │────▶│ API Server  │────▶│  Database   │
└─────────────┘     └─────────────┘     └─────────────┘
                          │
                          ▼
                   ┌─────────────┐
                   │   Engine    │────▶ Kubernetes (SEV-SNP nodes)
                   └─────────────┘
```

| Crate | Purpose |
|-------|---------|
| `enclava-common` | Shared types, crypto utilities, image resolution |
| `enclava-engine` | Kubernetes manifest generation and server-side apply |
| `enclava-api` | Axum REST API: auth, billing, deployments |
| `enclava-cli` | Developer CLI (`enclava deploy`, `enclava unlock`, …) |

## Development

```bash
cargo test --workspace        # all tests
cargo run -p enclava-api      # start the API locally
cargo build -p enclava-cli --release
```

Rust 2024 edition, MSRV 1.85. The API is built with axum + sqlx; the engine
uses kube-rs. Crypto primitives (argon2, hkdf, x25519, aes-gcm, zeroize) are
shared with the attestation-proxy.

## Contributing

Issues and PRs welcome. Please run `cargo fmt` and `cargo test --workspace`
before submitting.

## License

MIT — see [LICENSE](LICENSE).
