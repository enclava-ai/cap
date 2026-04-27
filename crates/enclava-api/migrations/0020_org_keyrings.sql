-- Owner-signed org keyring (D10, rev5). The platform stores keyring_payload as
-- opaque CE-v1 canonical bytes; signature is the org owner's Ed25519 signature.
-- Each new version is append-only; old versions are retained for audit.
CREATE TABLE org_keyrings (
    org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    version         bigint NOT NULL,
    keyring_payload bytea NOT NULL,
    signature       bytea NOT NULL,
    signing_key_id  uuid NOT NULL REFERENCES user_signing_keys(id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, version)
);

CREATE INDEX org_keyrings_org_id_version ON org_keyrings(org_id, version DESC);
