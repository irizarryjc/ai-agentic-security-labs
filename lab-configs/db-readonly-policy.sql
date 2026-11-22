-- =============================================================================
-- Least-Privilege Read-Only Database Policy for Coding Agents (PostgreSQL)
-- Companion repo: https://github.com/irizarryjc/ai-agentic-security-labs
--
-- PURPOSE:
--   Demonstrates a scoped, time-bound, read-only database role for an agent
--   diagnostic workflow. Never grant SUPERUSER, CREATEDB, CREATEROLE,
--   REPLICATION, BYPASSRLS, or pg_execute_server_program to an agent identity.
--
-- SAFETY NOTICE:
--   Review and test in a disposable lab database first. Replace all
--   <placeholders> before adapting to staging or approved non-prod environments.
--   Do not store passwords or tokens in prompts, git commits, or agent logs.
-- =============================================================================

-- 1. Create a non-login capability role and a dedicated view schema.
CREATE ROLE agent_readonly_base NOLOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT
    NOREPLICATION
    NOBYPASSRLS;

CREATE SCHEMA IF NOT EXISTS app_ro;

-- 2. Expose only non-PII summary views in app_ro (never base tables with PII).
-- Example view definition assuming an application table app.orders exists:
-- CREATE OR REPLACE VIEW app_ro.order_summary_v AS
-- SELECT order_id, status, amount_cents, created_bucket
-- FROM app.orders;

-- 3. Lock down default schema permissions and grant minimal SELECT access.
REVOKE ALL ON DATABASE <db_name> FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA app_ro FROM PUBLIC;

GRANT CONNECT ON DATABASE <db_name> TO agent_readonly_base;
GRANT USAGE ON SCHEMA app_ro TO agent_readonly_base;
GRANT SELECT ON ALL TABLES IN SCHEMA app_ro TO agent_readonly_base;

-- Explicitly deny server-side filesystem and OS program helpers.
REVOKE pg_read_server_files FROM agent_readonly_base;
REVOKE pg_write_server_files FROM agent_readonly_base;
REVOKE pg_execute_server_program FROM agent_readonly_base;

-- 4. Create a ticket-scoped, time-bound login role for a short diagnostic window.
-- Replace '<token>' via your secrets manager and set a short VALID UNTIL window
-- (format: 'YYYY-MM-DD HH:MM:SS+00', for example 2 hours ahead in UTC).
CREATE ROLE agent_ro_ticket LOGIN
    PASSWORD '<token>'
    VALID UNTIL 'YYYY-MM-DD HH:MM:SS+00'
    CONNECTION LIMIT 2
    IN ROLE agent_readonly_base;

-- Enforce read-only transactions and strict query resource caps at role level.
ALTER ROLE agent_ro_ticket SET default_transaction_read_only = on;
ALTER ROLE agent_ro_ticket SET statement_timeout = '5s';
ALTER ROLE agent_ro_ticket SET lock_timeout = '2s';
ALTER ROLE agent_ro_ticket SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE agent_ro_ticket SET search_path = app_ro;

-- 5. Defense-in-depth DDL guard: block any DDL initiated by an agent_% role.
CREATE OR REPLACE FUNCTION app_ro.block_agent_ddl()
RETURNS event_trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_user LIKE 'agent_%' OR session_user LIKE 'agent_%' THEN
        RAISE EXCEPTION
            'DDL blocked by policy for agent identity: %',
            session_user;
    END IF;
END;
$$;

DROP EVENT TRIGGER IF EXISTS trg_block_agent_ddl;
CREATE EVENT TRIGGER trg_block_agent_ddl
    ON ddl_command_start
    EXECUTE FUNCTION app_ro.block_agent_ddl();

-- 6. Verification queries (run as DBA to audit effective role flags and grants).
-- SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolreplication,
--        rolbypassrls, rolconnlimit, rolvaliduntil
-- FROM pg_roles
-- WHERE rolname LIKE 'agent_%';

-- 7. Emergency revocation / rollback commands (execute immediately in an incident).
-- ALTER ROLE agent_ro_ticket NOLOGIN;
-- SELECT pg_terminate_backend(pid)
-- FROM pg_stat_activity
-- WHERE usename = 'agent_ro_ticket';
-- DROP EVENT TRIGGER IF EXISTS trg_block_agent_ddl;
-- DROP FUNCTION IF EXISTS app_ro.block_agent_ddl();
-- DROP ROLE IF EXISTS agent_ro_ticket;
-- DROP ROLE IF EXISTS agent_readonly_base;

-- =============================================================================
-- CROSS-ENGINE EQUIVALENTS (CONCEPTUAL POINTERS: VERIFY IN CURRENT DOCS)
-- =============================================================================
-- Oracle Database:
--   Create a dedicated account with CREATE SESSION and SELECT on redacted
--   views only, bound to a PROFILE with IDLE_TIME, CONNECT_TIME, and
--   CPU_PER_CALL limits. Never grant SYSDBA, SYSOPER, SYSBACKUP, DBA,
--   DROP ANY TABLE, or ALTER SYSTEM to an agent identity.
--
-- Microsoft SQL Server:
--   Create a dedicated login and database user with explicit SELECT grants on
--   non-PII views and explicit DENY on base tables. Never assign sysadmin,
--   db_owner, db_ddladmin, db_datawriter, or db_backupoperator.
--
-- MongoDB:
--   Create a dedicated user with a custom role allowing only find on approved
--   non-PII views or collections (use maxTimeMS on queries). Never assign
--   root, dbAdminAnyDatabase, readWriteAnyDatabase, backup, restore, or
--   clusterAdmin.
-- =============================================================================
