-- DNS records owned by CAP.
--
-- Tenant TLS certificates remain tenant-owned inside the confidential workload.
-- This table tracks only public DNS records CAP created or adopted through the
-- configured Cloudflare zone.
CREATE TABLE dns_records (
    id          uuid PRIMARY KEY,
    app_id      uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    hostname    text NOT NULL,
    zone_id     text NOT NULL,
    record_id   text NOT NULL,
    record_type text NOT NULL,
    target      text NOT NULL,
    is_custom   boolean NOT NULL DEFAULT false,
    provider    text NOT NULL DEFAULT 'cloudflare',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (hostname)
);

CREATE INDEX idx_dns_records_app_id ON dns_records(app_id);
