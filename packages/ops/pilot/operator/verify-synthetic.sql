\set ON_ERROR_STOP on
SELECT current_setting('listen_addresses') AS listen_addresses,
       current_setting('port') AS port,
       current_setting('unix_socket_directories') AS socket_directory,
       current_setting('unix_socket_group') AS socket_group,
       current_setting('unix_socket_permissions') AS socket_permissions,
       current_setting('max_connections') AS max_connections,
       current_setting('shared_buffers') AS shared_buffers,
       current_setting('fsync') AS fsync,
       current_setting('full_page_writes') AS full_page_writes,
       current_setting('synchronous_commit') AS synchronous_commit;
SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolreplication,
       rolbypassrls, rolinherit, rolcanlogin, rolconnlimit
FROM pg_roles WHERE rolname = 'prime_memory';
SELECT count(*) AS inherited_or_assumed_roles
FROM pg_auth_members WHERE member = (SELECT oid FROM pg_roles WHERE rolname = 'prime_memory');
SELECT datname, pg_get_userbyid(datdba) AS database_owner,
       has_database_privilege('prime_memory', oid, 'CONNECT') AS memory_connect,
       has_database_privilege('prime_memory', oid, 'CREATE') AS memory_create,
       has_database_privilege('prime_memory', oid, 'TEMP') AS memory_temp
FROM pg_database ORDER BY datname;
\connect aukora_prime_synthetic postgres
SELECT nspname, pg_get_userbyid(nspowner) AS schema_owner
FROM pg_namespace WHERE nspname IN ('public', 'prime_memory') ORDER BY nspname;
SELECT line_number, type, database, user_name, auth_method, options, error
FROM pg_hba_file_rules ORDER BY line_number;
