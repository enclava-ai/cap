-- Per-user CLI Ed25519 public keys (D10). pubkey is the raw 32-byte public key.
-- A user may have multiple active keys (one per device); revoked_at marks retirement.
CREATE TABLE user_signing_keys (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    pubkey     bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);

CREATE UNIQUE INDEX idx_user_signing_keys_user_id_pubkey_active
    ON user_signing_keys(user_id, pubkey)
    WHERE revoked_at IS NULL;

CREATE INDEX idx_user_signing_keys_user_id ON user_signing_keys(user_id);

-- Customer-signed deployment descriptors (D10). Table name kept as
-- `deployment_intents` for migration compatibility; rev11+ stores full
-- DeploymentDescriptor canonical bytes here, signed by a key in the org keyring.
CREATE TABLE deployment_intents (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id              uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    deploy_id           uuid NOT NULL,
    descriptor_payload  bytea NOT NULL,
    signature           bytea NOT NULL,
    signing_key_id      uuid NOT NULL REFERENCES user_signing_keys(id),
    created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_deployment_intents_app_id_created_at
    ON deployment_intents(app_id, created_at DESC);
