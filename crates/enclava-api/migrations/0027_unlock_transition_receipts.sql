CREATE TABLE unlock_transition_receipts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    from_mode unlock_enum NOT NULL,
    to_mode unlock_enum NOT NULL,
    receipt jsonb NOT NULL,
    receipt_pubkey_sha256 bytea NOT NULL,
    receipt_timestamp timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_unlock_transition_receipts_app_timestamp
    ON unlock_transition_receipts(app_id, receipt_timestamp DESC);
