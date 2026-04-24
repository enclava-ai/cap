CREATE TABLE kbs_tls_bindings (
    app_id                         uuid PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
    binding_key                    text NOT NULL UNIQUE,
    repository                     text NOT NULL DEFAULT 'default',
    tag                            text NOT NULL DEFAULT 'workload-secret-seed',
    namespace                      text NOT NULL,
    service_account                text NOT NULL,
    tenant_instance_identity_hash  text NOT NULL,
    created_at                     timestamptz NOT NULL DEFAULT now(),
    updated_at                     timestamptz NOT NULL DEFAULT now(),
    deleted_at                     timestamptz
);

CREATE INDEX idx_kbs_tls_bindings_active
    ON kbs_tls_bindings (deleted_at)
    WHERE deleted_at IS NULL;
