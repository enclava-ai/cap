-- Custom (third-party) domains are owned by the user; the platform does not
-- create or update Cloudflare records for them. Allow zone_id/record_id to be
-- NULL so we can still track the row for cleanup without a Cloudflare handle.
ALTER TABLE dns_records ALTER COLUMN zone_id DROP NOT NULL;
ALTER TABLE dns_records ALTER COLUMN record_id DROP NOT NULL;
