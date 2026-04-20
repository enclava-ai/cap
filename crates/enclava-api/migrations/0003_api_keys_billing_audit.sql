CREATE TYPE sub_status_enum AS ENUM ('active', 'expired', 'grace_period');
CREATE TYPE payment_status_enum AS ENUM ('pending', 'confirmed', 'expired');

-- API keys (scoped to org)
CREATE TABLE api_keys (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by   uuid NOT NULL REFERENCES users(id),
    key_hash     text NOT NULL,
    key_prefix   text NOT NULL,
    name         text NOT NULL,
    scopes       text[] NOT NULL DEFAULT '{}',
    last_used_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz
);

CREATE INDEX idx_api_keys_org_id ON api_keys(org_id);
CREATE INDEX idx_api_keys_key_prefix ON api_keys(key_prefix);

-- Subscriptions
CREATE TABLE subscriptions (
    id                   uuid PRIMARY KEY,
    org_id               uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    tier                 tier_enum NOT NULL,
    status               sub_status_enum NOT NULL DEFAULT 'active',
    current_period_start timestamptz NOT NULL DEFAULT now(),
    current_period_end   timestamptz NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_subscriptions_org_id ON subscriptions(org_id);

-- Payments
CREATE TABLE payments (
    id                uuid PRIMARY KEY,
    org_id            uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    subscription_id   uuid REFERENCES subscriptions(id),
    amount_sats       bigint NOT NULL,
    btcpay_invoice_id text NOT NULL UNIQUE,
    status            payment_status_enum NOT NULL DEFAULT 'pending',
    created_at        timestamptz NOT NULL DEFAULT now(),
    confirmed_at      timestamptz
);

CREATE INDEX idx_payments_org_id ON payments(org_id);
CREATE INDEX idx_payments_btcpay_invoice_id ON payments(btcpay_invoice_id);

-- Audit log (append-only)
CREATE TABLE audit_log (
    id         bigserial PRIMARY KEY,
    org_id     uuid REFERENCES organizations(id),
    app_id     uuid,
    user_id    uuid,
    action     text NOT NULL,
    detail     jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_org_id ON audit_log(org_id);
CREATE INDEX idx_audit_log_app_id ON audit_log(app_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at DESC);

-- Config metadata (key names only, values live on encrypted filesystem inside TEE)
CREATE TABLE config_metadata (
    id         uuid PRIMARY KEY,
    app_id     uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    key_name   text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (app_id, key_name)
);

CREATE INDEX idx_config_metadata_app_id ON config_metadata(app_id);
