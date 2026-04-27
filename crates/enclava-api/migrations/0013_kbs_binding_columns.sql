-- Per-binding attestation expectations referenced by the Phase 2 read-side Rego.
-- image_digest + signer_identity flow from the customer-signed deployment descriptor;
-- init_data_hash is the SHA-256 of cc_init_data anchored in SNP HOST_DATA (D6).
ALTER TABLE kbs_tls_bindings
    ADD COLUMN image_digest             text,
    ADD COLUMN init_data_hash           bytea,
    ADD COLUMN signer_identity_subject  text,
    ADD COLUMN signer_identity_issuer   text;
