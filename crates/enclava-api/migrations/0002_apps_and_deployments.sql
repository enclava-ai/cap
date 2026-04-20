CREATE TYPE unlock_enum AS ENUM ('auto', 'password');
CREATE TYPE app_status_enum AS ENUM ('creating', 'running', 'stopped', 'failed', 'deleting');
CREATE TYPE trigger_enum AS ENUM ('api', 'cli', 'rollback');
CREATE TYPE deploy_status_enum AS ENUM ('pending', 'applying', 'watching', 'healthy', 'failed', 'rolled_back');

-- Apps
CREATE TABLE apps (
    id                           uuid PRIMARY KEY,
    org_id                       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                         text NOT NULL,
    namespace                    text NOT NULL UNIQUE,
    instance_id                  text NOT NULL UNIQUE,
    tenant_id                    text NOT NULL,
    service_account              text NOT NULL,
    bootstrap_owner_pubkey_hash  text NOT NULL,
    tenant_instance_identity_hash text NOT NULL,
    unlock_mode                  unlock_enum NOT NULL DEFAULT 'auto',
    domain                       text NOT NULL,
    custom_domain                text,
    status                       app_status_enum NOT NULL DEFAULT 'creating',
    created_at                   timestamptz NOT NULL DEFAULT now(),
    updated_at                   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE INDEX idx_apps_org_id ON apps(org_id);
CREATE INDEX idx_apps_namespace ON apps(namespace);

-- App containers
CREATE TABLE app_containers (
    id            uuid PRIMARY KEY,
    app_id        uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    name          text NOT NULL,
    image_ref     text NOT NULL,
    image_digest  text,
    port          int,
    command       text,
    storage_paths text[],
    is_primary    boolean NOT NULL DEFAULT false,
    UNIQUE (app_id, name)
);

CREATE INDEX idx_app_containers_app_id ON app_containers(app_id);

-- App resource limits
CREATE TABLE app_resources (
    app_id           uuid PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
    cpu_limit        text NOT NULL DEFAULT '1',
    memory_limit     text NOT NULL DEFAULT '1Gi',
    app_data_size    text NOT NULL DEFAULT '5Gi',
    tls_data_size    text NOT NULL DEFAULT '2Gi'
);

-- Deployment history
CREATE TABLE deployments (
    id            uuid PRIMARY KEY,
    app_id        uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    trigger       trigger_enum NOT NULL DEFAULT 'api',
    status        deploy_status_enum NOT NULL DEFAULT 'pending',
    spec_snapshot jsonb NOT NULL,
    manifest_hash text,
    image_digest  text,
    error_message text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    completed_at  timestamptz
);

CREATE INDEX idx_deployments_app_id ON deployments(app_id);
CREATE INDEX idx_deployments_app_id_created_at ON deployments(app_id, created_at DESC);
