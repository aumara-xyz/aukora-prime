\set ON_ERROR_STOP on
-- Run only once, as postgres, in the newly owned private synthetic cluster.
SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = 'prime_memory')
    OR EXISTS (SELECT FROM pg_database WHERE datname = 'aukora_prime_synthetic') AS collision \gset
\if :collision
    \echo Existing role or database found; inspect before any retry.
    \quit 3
\endif

CREATE ROLE prime_memory LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4 PASSWORD NULL;
CREATE DATABASE aukora_prime_synthetic OWNER postgres TEMPLATE template0 ENCODING 'UTF8';
-- These defaults belong solely to this fresh operator-owned cluster.
REVOKE ALL ON DATABASE postgres, template0, template1 FROM PUBLIC;
REVOKE ALL ON DATABASE aukora_prime_synthetic FROM PUBLIC;
GRANT CONNECT ON DATABASE aukora_prime_synthetic TO prime_memory;

\connect aukora_prime_synthetic postgres
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA prime_memory AUTHORIZATION postgres;
GRANT USAGE, CREATE ON SCHEMA prime_memory TO prime_memory;
ALTER ROLE prime_memory IN DATABASE aukora_prime_synthetic SET search_path = prime_memory;
-- No membership, database/schema ownership, database CREATE/TEMP privilege,
-- or parameter privilege is granted. Migration can create objects only in this schema.
