-- Phase 10 membership lifecycle.
--
-- Membership rows are retained for audit/reinvite semantics. Active
-- authorization paths must require removed_at IS NULL.
ALTER TABLE memberships
    ADD COLUMN removed_at timestamptz;

CREATE INDEX idx_memberships_active_org_user
    ON memberships (org_id, user_id)
    WHERE removed_at IS NULL;

CREATE INDEX idx_memberships_active_owner
    ON memberships (org_id)
    WHERE role = 'owner' AND removed_at IS NULL;
