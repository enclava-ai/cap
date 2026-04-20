-- Add supply chain metadata columns to deployments
ALTER TABLE deployments ADD COLUMN cosign_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE deployments ADD COLUMN provenance_attestation JSONB;
ALTER TABLE deployments ADD COLUMN sbom JSONB;
