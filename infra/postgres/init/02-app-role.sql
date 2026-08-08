-- Cluster-level setup: roles and default privileges.
--
-- Runs once, on first boot of an empty volume. Kept out of the Atlas-managed
-- schema because roles are cluster objects, not schema objects — and Atlas
-- Community does not manage them.

-- The role the API, projectors and workers connect as.
--
-- Deliberately NOT the owner of any table: FORCE ROW LEVEL SECURITY exempts
-- table owners, so an owner connection silently bypasses every policy. This is
-- the single most common way RLS turns out not to be in effect (ADR-011).
CREATE ROLE chronos_app LOGIN PASSWORD 'chronos_app_dev_password';

GRANT CONNECT ON DATABASE chronos TO chronos_app;
GRANT USAGE ON SCHEMA public TO chronos_app;

-- Tables that already exist.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO chronos_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO chronos_app;

-- And every table a future migration creates, so a new projection is reachable
-- without remembering to grant it.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO chronos_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO chronos_app;
