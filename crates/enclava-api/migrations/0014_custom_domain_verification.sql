-- Custom domain ownership verification challenges (BYO domains per D5).
-- One row per (app_id, domain) verification attempt; verified_at is set on
-- successful challenge response, expires_at bounds the window for the proof.
CREATE TABLE custom_domain_challenges (
    id              uuid PRIMARY KEY,
    app_id          uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    domain          text NOT NULL,
    challenge_token text NOT NULL,
    verified_at     timestamptz,
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_custom_domain_challenges_app_id_domain
    ON custom_domain_challenges(app_id, domain);
