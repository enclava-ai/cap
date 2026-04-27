-- Per-app cosign / Fulcio identity (D4). Nullable for existing rows;
-- enforced NOT NULL at app create time once Phase 9 lands.
ALTER TABLE apps
    ADD COLUMN signer_identity_subject text,
    ADD COLUMN signer_identity_issuer  text,
    ADD COLUMN signer_identity_set_at  timestamptz;
