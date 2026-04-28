-- Phase 10 API-key hardening.
--
-- Legacy rows keep hash_format='argon2_legacy' and remain verifiable during
-- the rotation window. New keys use a 128-bit lookup prefix and store a
-- HMAC-SHA256 verifier over the secret with API_KEY_HMAC_PEPPER.
ALTER TABLE api_keys
    ADD COLUMN hash_format text NOT NULL DEFAULT 'argon2_legacy';

CREATE UNIQUE INDEX idx_api_keys_hmac_v1_prefix
    ON api_keys (key_prefix)
    WHERE hash_format = 'hmac_v1';
