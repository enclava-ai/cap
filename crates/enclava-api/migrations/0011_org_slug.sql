-- Customer-facing org slug: 8 lowercase hex chars, generated at org creation,
-- immutable, globally unique. Used in hostnames per D1 (e.g. <app>.<orgSlug>.enclava.dev).
ALTER TABLE organizations
    ADD COLUMN cust_slug varchar(8);

-- Backfill: derive a deterministic 8-hex slug from the org id so re-running the
-- migration produces the same result and so existing apps can map to a slug
-- without collision risk (uuid space dwarfs 32 bits, but the substring of a
-- random uuid v4 is uniformly distributed; collisions are detected by the
-- UNIQUE constraint and would require manual remediation).
UPDATE organizations
SET cust_slug = substring(replace(id::text, '-', '') from 1 for 8)
WHERE cust_slug IS NULL;

ALTER TABLE organizations
    ALTER COLUMN cust_slug SET NOT NULL;

ALTER TABLE organizations
    ADD CONSTRAINT organizations_cust_slug_key UNIQUE (cust_slug);

ALTER TABLE organizations
    ADD CONSTRAINT organizations_cust_slug_format
        CHECK (cust_slug ~ '^[0-9a-f]{8}$');
