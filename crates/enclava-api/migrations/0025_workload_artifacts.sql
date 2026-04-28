-- Workload-readable deployment artifacts returned by
-- GET /api/v1/workload/artifacts after Trustee validates the workload's
-- attestation token. Values are JSON because enclava-init verifies the same
-- semantic descriptor/keyring/artifact bundle the signing service produced.
CREATE TABLE workload_artifacts (
    descriptor_core_hash        bytea PRIMARY KEY,
    app_id                      uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    deploy_id                   uuid NOT NULL,
    descriptor_payload          jsonb NOT NULL,
    descriptor_signature        bytea NOT NULL,
    descriptor_signing_key_id   text NOT NULL,
    org_keyring_payload         jsonb NOT NULL,
    org_keyring_signature       bytea NOT NULL,
    signed_policy_artifact      jsonb NOT NULL,
    created_at                  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_workload_artifacts_app_deploy
    ON workload_artifacts(app_id, deploy_id);
