-- Phase 4 (D1 two-hostname model): every app now has both an app hostname
-- (`<app>.<orgSlug>.<platform_domain>`) and a TEE hostname
-- (`<app>.<orgSlug>.<tee_domain_suffix>`). Existing rows are backfilled by
-- the migrate-two-hostnames one-shot binary, so the column is nullable here
-- and tightened to NOT NULL in a later migration once the backfill has run.
ALTER TABLE apps
    ADD COLUMN tee_domain text;
