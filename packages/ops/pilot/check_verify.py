#!/usr/bin/env python3
"""Focused disposable checks. No root impersonation, host audit, or socket connection."""
import copy
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import verify


def fixture_spec():
    def directory(path, owner='root', group='root', mode='0755'):
        return dict(path=path, owner=owner, group=group, mode=mode)

    def file(path, owner='root', group='root', mode='0644'):
        return dict(path=path, owner=owner, group=group, mode=mode, sha256='0' * 64)

    release = verify.CODE + '/releases/' + '1' * 64
    code_file = release + '/worker.mjs'
    config_file = verify.CONFIG + '/authority/immutable-host-config.mjs'
    memory_config = verify.CONFIG + '/memory/immutable-host-config.mjs'
    directories = [directory(root, mode='0711' if root in (verify.STATE, verify.RUN) else '0755')
                   for root in (verify.CODE, verify.CONFIG, verify.STATE, verify.RUN)]
    directories += [directory(release), directory(verify.CONFIG + '/authority', group='prime-authority', mode='0750'),
                    directory(verify.CONFIG + '/memory', group='prime-memory', mode='0750'),
                    directory(verify.WITNESS, 'prime-authority', 'prime-authority', '0700'),
                    directory(verify.RUN + '/authority', 'prime-authority', 'prime-authority-ipc', '0710'),
                    directory(verify.RUN + '/memory', 'prime-memory', 'prime-memory-ipc', '0710'),
                    directory(verify.RUN + '/postgres', 'postgres', 'prime-pg-socket', '0750')]
    files = [file(code_file), file(config_file, group='prime-authority', mode='0440'),
             file(memory_config, group='prime-memory', mode='0440')]
    units = []
    for name, user in verify.UNITS.items():
        files.append(file('/etc/systemd/system/' + name))
        units.append(dict(name=name, sha256='0' * 64, user=user, group=verify.PRIMARY_GROUPS[user],
                          supplementary_groups=verify.GROUPS[user][:]))
    subjects = []
    for user, groups in verify.GROUPS.items():
        denied_read = [config_file] if user in ('prime-app', 'prime-memory') else []
        if user in ('prime-app', 'postgres'):
            denied_read.append(memory_config)
        subjects.append(dict(user=user, group=verify.PRIMARY_GROUPS[user], supplementary_groups=groups[:],
                             denied_write=[code_file], denied_read=denied_read,
                             denied_traverse=[], allowed_traverse=[]))
    sockets = [dict(path=path, owner=owner, group=group, mode=mode, allowed_users=allowed[:], denied_users=denied[:])
               for path, (owner, group, mode, allowed, denied) in verify.SOCKETS.items()]
    return dict(schema='prime-pilot-privileges-v1', source_only=True, directories=directories, files=files,
                subjects=subjects, sockets=sockets, units=units, release_root=release)


class VerifierChecks(unittest.TestCase):
    def setUp(self):
        self.spec = fixture_spec()

    def refusal(self, reason, mutation):
        bad = copy.deepcopy(self.spec)
        mutation(bad)
        with self.assertRaisesRegex(verify.Refusal, '^' + reason + '$'):
            verify.validate_spec(bad)

    def test_source_mode_cannot_report_host_boundary_pass_or_call_host_tools(self):
        with patch.object(verify, 'host_observations', side_effect=AssertionError('host probe')), \
             patch.object(verify, 'unit_observations', side_effect=AssertionError('unit probe')):
            result = verify.verify(self.spec, 'source', '0' * 64)
        self.assertEqual(result['verdict'], 'PENDING')
        self.assertEqual(result['host_dac_status'], 'NOT_RUN')
        self.assertEqual(result['unit_status'], 'NOT_RUN')
        self.assertTrue(result['source_only'])
        self.assertTrue(all(value == 'PENDING' for value in result['qualification'].values()))
        self.assertEqual(result['known_source_conflicts'], [])

    def test_old_postgres_memory_group_conflict_and_socket_scope_regressions_refused(self):
        postgres = lambda s: next(row for row in s['subjects'] if row['user'] == 'postgres')
        pg_unit = lambda s: next(row for row in s['units'] if row['user'] == 'postgres')
        self.refusal('PG_MEMORY_CONFIG_READ_GROUP_CONFLICT', lambda s: postgres(s).update(supplementary_groups=['prime-memory']))
        self.refusal('PG_MEMORY_CONFIG_READ_GROUP_CONFLICT', lambda s: pg_unit(s).update(supplementary_groups=['prime-memory']))
        self.refusal('UNSAFE_POSTGRES_SOCKET_DIRECTORY', lambda s: next(row for row in s['directories']
                     if row['path'] == verify.RUN + '/postgres').update(group='prime-memory'))
        self.refusal('INVALID_SOCKET_PERMISSIONS', lambda s: next(row for row in s['sockets']
                     if row['owner'] == 'postgres').update(group='prime-memory'))
        self.refusal('INVALID_SOCKET_PATH', lambda s: next(row for row in s['sockets']
                     if row['owner'] == 'postgres').update(path=verify.RUN + '/postgres/.s.PGSQL.55432'))
        self.refusal('INVALID_SUBJECT_GROUPS', lambda s: next(row for row in s['subjects']
                     if row['user'] == 'prime-memory')['supplementary_groups'].remove('prime-pg-socket'))

    def test_observed_postgres_nss_or_process_private_memory_group_is_failure(self):
        # Distinct synthetic GIDs exercise both NSS/running-process callers without host probes.
        verify.reject_postgres_private_group('postgres', {114, 812}, memory_gid=811)
        for observed_groups in ({114, 811}, {114, 812, 811}):
            with self.assertRaisesRegex(verify.Refusal, '^PG_MEMORY_CONFIG_READ_GROUP_CONFLICT$'):
                verify.reject_postgres_private_group('postgres', observed_groups, memory_gid=811)
        verify.reject_postgres_private_group('prime-memory', {811, 812}, memory_gid=811)

    def test_worker_private_configs_require_root_readonly_primary_group_and_pinned_parent(self):
        config = lambda s: next(row for row in s['files'] if row['path'].startswith(verify.CONFIG + '/memory/'))
        self.refusal('UNSAFE_PRIVATE_CONFIG', lambda s: config(s).update(owner='prime-memory', mode='0600'))
        self.refusal('UNSAFE_PRIVATE_CONFIG', lambda s: config(s).update(owner='root', mode='0600'))
        self.refusal('UNSAFE_PRIVATE_CONFIG', lambda s: config(s).update(group='prime-memory-ipc'))
        self.refusal('UNSAFE_PRIVATE_CONFIG_PARENT', lambda s: next(row for row in s['directories']
                      if row['path'] == verify.CONFIG + '/memory').update(group='root'))
        self.refusal('UNSAFE_PRIVATE_CONFIG_PARENT', lambda s: next(row for row in s['directories']
                      if row['path'] == verify.CONFIG + '/memory').update(mode='0755'))

    def test_postgres_secret_probe_cannot_be_omitted_or_redirected_to_authority_config(self):
        postgres = lambda s: next(row for row in s['subjects'] if row['user'] == 'postgres')
        self.refusal('MISSING_POSTGRES_MEMORY_SECRET_NEGATIVE_PROBE', lambda s: postgres(s).update(denied_read=[]))
        self.refusal('MISSING_POSTGRES_MEMORY_SECRET_NEGATIVE_PROBE', lambda s: postgres(s).update(
                     denied_read=[verify.CONFIG + '/authority/immutable-host-config.mjs']))

    def test_exact_file_pin_and_drift(self):
        with tempfile.TemporaryDirectory(prefix='prime-pilot-verify-') as temporary:
            path = Path(temporary) / 'expected.json'
            data = json.dumps(self.spec, separators=(',', ':')).encode()
            path.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            self.assertEqual(verify.read_spec(path, digest), self.spec)
            path.write_bytes(data + b'\n')
            with self.assertRaisesRegex(verify.Refusal, '^EXPECTATIONS_DIGEST_MISMATCH$'):
                verify.read_spec(path, digest)

    def test_duplicate_json_field_refused_even_with_matching_external_digest(self):
        with tempfile.TemporaryDirectory(prefix='prime-pilot-json-') as temporary:
            path = Path(temporary) / 'expected.json'
            data = b'{"schema":"prime-pilot-privileges-v1","schema":"prime-pilot-privileges-v1"}'
            path.write_bytes(data)
            with self.assertRaisesRegex(verify.Refusal, '^DUPLICATE_JSON_FIELD$'):
                verify.read_spec(path, hashlib.sha256(data).hexdigest())

    def test_unpinned_and_out_of_scope_probes_default_deny(self):
        self.refusal('UNPINNED_PROBE_PATH', lambda s: s['subjects'][0]['denied_write'].append(verify.CONFIG + '/not-pinned'))
        self.refusal('OUT_OF_SCOPE_PATH', lambda s: s['subjects'][0]['denied_write'].append('/etc/passwd'))
        self.refusal('UNSAFE_PATH', lambda s: s['files'][0].update(path=verify.CODE + '/releases/../escape.mjs'))
        self.refusal('INVALID_SPEC_FIELDS', lambda s: s.update(policy={'allow': True}))
        self.refusal('INVALID_RELEASE_ROOT', lambda s: s.update(release_root=verify.CODE + '/releases/marker-only'))

    def test_app_cannot_gain_authority_group_or_become_authority_socket_client(self):
        self.refusal('INVALID_SUBJECT_GROUPS', lambda s: s['subjects'][0]['supplementary_groups'].append('prime-authority-ipc'))
        self.refusal('INVALID_SOCKET_SUBJECTS', lambda s: s['sockets'][0].update(allowed_users=['prime-app']))
        self.refusal('INVALID_SOCKET_SUBJECTS', lambda s: s['sockets'][0]['allowed_users'].append('prime-app'))

    def test_weakened_source_directory_and_unit_policies_refused(self):
        self.refusal('WRITABLE_CODE_OR_CONFIG', lambda s: s['directories'][0].update(mode='0777'))
        self.refusal('UNPROTECTED_ROOT_DIRECTORY', lambda s: s['directories'][2].update(owner='prime-app', group='prime-app'))
        self.refusal('UNSAFE_IPC_DIRECTORY', lambda s: next(e for e in s['directories'] if e['path'].endswith('/authority')
                      and e['path'].startswith(verify.RUN)).update(mode='0750'))
        self.refusal('UNPROTECTED_UNIT_FILE', lambda s: next(e for e in s['files'] if e['path'].endswith('prime-app.service')).update(owner='prime-app'))
        self.refusal('UNPROTECTED_WITNESS', lambda s: next(e for e in s['directories'] if e['path'] == verify.WITNESS).update(mode='0750'))
        self.refusal('UNSAFE_PRIVATE_CONFIG', lambda s: next(e for e in s['files'] if e['path'].startswith(verify.CONFIG)).update(mode='0644'))

    def test_existing_postgres_identity_shell_preserved_prime_accounts_require_nologin(self):
        distro = SimpleNamespace(pw_uid=113, pw_gid=114, pw_shell='/bin/bash')
        verify.validate_host_account('postgres', distro, SimpleNamespace(gr_gid=114))
        with self.assertRaisesRegex(verify.Refusal, '^POSTGRES_REPORTED_IDENTITY_CHANGED$'):
            verify.validate_host_account('postgres', SimpleNamespace(pw_uid=115, pw_gid=114, pw_shell='/bin/bash'),
                                         SimpleNamespace(gr_gid=114))
        for user in ('prime-app', 'prime-authority', 'prime-memory'):
            with self.assertRaisesRegex(verify.Refusal, '^LOGIN_NOT_DISABLED$'):
                verify.validate_host_account(user, SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_shell='/bin/bash'),
                                             SimpleNamespace(gr_gid=1001))
            verify.validate_host_account(user, SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_shell='/usr/sbin/nologin'),
                                         SimpleNamespace(gr_gid=1001))

    def test_writable_or_untrusted_real_ancestor_metadata_refused(self):
        verify.protected_ancestor(SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755))
        for owner, mode in ((0, 0o775), (0, 0o777), (123, 0o755)):
            with self.assertRaisesRegex(verify.Refusal, '^WRITABLE_RELEASE_ANCESTOR$'):
                verify.protected_ancestor(SimpleNamespace(st_uid=owner, st_mode=stat.S_IFDIR | mode))

    def test_missing_security_checks_cannot_observe_dac_success(self):
        self.assertEqual(verify.summarize([]), 'PENDING')
        self.assertEqual(verify.summarize([{'status': 'OBSERVED'}, {'status': 'PENDING'}]), 'PENDING')
        self.assertEqual(verify.summarize([{'status': 'FAIL'}, {'status': 'PENDING'}]), 'FAIL')
        self.refusal('MISSING_SOCKET', lambda s: s['sockets'].pop())
        self.refusal('MISSING_UNIT', lambda s: s['units'].pop())
        self.refusal('MISSING_UNTRUSTED_NEGATIVE_PROBE', lambda s: s['subjects'][0].update(denied_write=[]))

    def test_internal_relative_release_target_allowed_escape_and_absolute_refused(self):
        root = verify.CODE + '/releases/pinned'
        link = root + '/node_modules/pkg'
        self.assertEqual(verify.relative_release_target(link, '../lib/pkg', root), root + '/lib/pkg')
        with self.assertRaisesRegex(verify.Refusal, '^ABSOLUTE_RELEASE_LINK$'):
            verify.relative_release_target(link, root + '/lib/pkg', root)
        with self.assertRaisesRegex(verify.Refusal, '^ESCAPING_RELEASE_LINK$'):
            verify.relative_release_target(link, '../../../../etc/passwd', root)

    def test_malformed_nested_values_are_refusals(self):
        self.refusal('INVALID_SUBJECT_IDENTITY', lambda s: s['subjects'][0].update(user=[]))
        self.refusal('INVALID_STRING_LIST', lambda s: s['subjects'][0].update(supplementary_groups=[{}]))
        self.refusal('UNKNOWN_IDENTITY', lambda s: s['files'][0].update(owner=[]))

    def test_unexpected_write_access_probe_never_truncates_or_changes_fixture(self):
        with tempfile.TemporaryDirectory(prefix='prime-pilot-open-') as temporary:
            path = Path(temporary) / 'owned-disposable-file'
            data = b'Negative access observation must not destroy this fixture.\n'
            path.write_bytes(data)
            before = path.stat()
            request = json.dumps({'checks': {'denied_write': [str(path)]}})
            child = subprocess.run([sys.executable, '-I', '-c', verify.PROBE, request], env=verify.SAFE_ENV,
                                   check=True, capture_output=True, timeout=4)
            observed = json.loads(child.stdout)['observations'][0]
            self.assertEqual(observed['status'], 'FAIL')
            self.assertEqual(observed['reason'], 'OPEN_ALLOWED_NO_DATA_READ_OR_WRITTEN')
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual((path.stat().st_size, path.stat().st_mtime_ns), (before.st_size, before.st_mtime_ns))

    def test_unexpected_read_access_reports_fail_without_returning_secret_or_changing_fixture(self):
        with tempfile.TemporaryDirectory(prefix='prime-pilot-read-') as temporary:
            path = Path(temporary) / 'disposable-secret'
            data = b'disposable-secret-must-never-appear-in-observation-output'
            path.write_bytes(data)
            before = path.stat()
            request = json.dumps({'checks': {'denied_read': [str(path)]}})
            child = subprocess.run([sys.executable, '-I', '-c', verify.PROBE, request], env=verify.SAFE_ENV,
                                   check=True, capture_output=True, timeout=4)
            observed = json.loads(child.stdout)['observations'][0]
            self.assertEqual((observed['status'], observed['reason']),
                             ('FAIL', 'OPEN_ALLOWED_NO_DATA_READ_OR_WRITTEN'))
            self.assertNotIn(data, child.stdout + child.stderr)
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual((path.stat().st_size, path.stat().st_mtime_ns), (before.st_size, before.st_mtime_ns))

    def test_hidden_unit_dropins_and_enabled_autostart_fail_observation(self):
        def command(argv, dropins='', enabled='static'):
            unit = next(entry for entry in self.spec['units'] if entry['name'] in argv)
            if 'is-enabled' in argv:
                return SimpleNamespace(returncode=0, stdout=(enabled + '\n').encode())
            values = dict(LoadState='loaded', ActiveState='inactive', User=unit['user'], Group=unit['group'],
                          SupplementaryGroups=' '.join(unit['supplementary_groups']),
                          FragmentPath='/etc/systemd/system/' + unit['name'], DropInPaths=dropins,
                          MainPID='0', NoNewPrivileges='yes', ProtectSystem='strict', ProtectHome='yes')
            return SimpleNamespace(returncode=0, stdout=''.join(k + '=' + v + '\n' for k, v in values.items()).encode())
        with patch.object(verify, 'check_unit_file'), patch.object(verify, 'run_command', side_effect=command):
            self.assertTrue(all(row['status'] == 'OBSERVED' for row in verify.unit_observations(self.spec)))
        with patch.object(verify, 'check_unit_file'), patch.object(verify, 'run_command', side_effect=lambda a: command(a, dropins='/etc/systemd/system/prime-app.service.d/override.conf')):
            self.assertTrue(all(row['status'] == 'FAIL' and row['reason'] == 'UNIT_DROP_INS_PRESENT'
                                for row in verify.unit_observations(self.spec)))
        with patch.object(verify, 'check_unit_file'), patch.object(verify, 'run_command', side_effect=lambda a: command(a, enabled='enabled')):
            self.assertTrue(all(row['status'] == 'FAIL' and row['reason'] == 'UNIT_AUTOSTART_OR_UNSAFE_STATE'
                                for row in verify.unit_observations(self.spec)))

    def test_unit_file_pin_is_authoritative_without_duplicate_file_entry(self):
        spec = copy.deepcopy(self.spec)
        spec['files'] = [row for row in spec['files'] if row['path'] not in verify.UNIT_FILES]
        verify.validate_spec(spec)
        with patch.object(verify, 'check_unit_file', side_effect=verify.Refusal('UNIT_FILE_DIGEST_MISMATCH')), \
             patch.object(verify, 'run_command', side_effect=AssertionError('must fail before systemctl')):
            rows = verify.unit_observations(spec)
        self.assertTrue(all(row['status'] == 'FAIL' and row['reason'] == 'UNIT_FILE_DIGEST_MISMATCH' for row in rows))

    def test_whole_dependency_closure_metadata_precedes_digest_observation(self):
        root = self.spec['release_root']
        root_metadata = SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o755)
        file_metadata = SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o644, st_nlink=1, st_size=19)
        evaluator = SimpleNamespace(full_digest=lambda _: Path(root).name)
        with patch.object(verify, 'safe_chain', return_value=root_metadata), \
             patch.object(verify.os, 'walk', return_value=[(root + '/node_modules', [], ['dependency.mjs'])]), \
             patch.object(Path, 'lstat', return_value=file_metadata), patch.dict(sys.modules, {'pilot': evaluator}):
            row = verify.release_observation(self.spec)
        self.assertEqual(row['status'], 'OBSERVED')
        self.assertEqual(row['entries'], 1)
        self.assertEqual(row['physical_bytes'], 19)
        for owner, mode, links, reason in [(123, 0o644, 1, 'UNTRUSTED_RELEASE_ENTRY_OWNER'),
                                          (0, 0o664, 1, 'MUTABLE_OR_HARDLINKED_RELEASE_FILE'),
                                          (0, 0o644, 2, 'MUTABLE_OR_HARDLINKED_RELEASE_FILE')]:
            bad = SimpleNamespace(st_uid=owner, st_gid=0, st_mode=stat.S_IFREG | mode, st_nlink=links, st_size=19)
            with patch.object(verify, 'safe_chain', return_value=root_metadata), \
                 patch.object(verify.os, 'walk', return_value=[(root + '/node_modules', [], ['dependency.mjs'])]), \
                 patch.object(Path, 'lstat', return_value=bad), patch.dict(sys.modules, {'pilot': evaluator}):
                row = verify.release_observation(self.spec)
            self.assertEqual((row['status'], row['reason']), ('FAIL', reason))


if __name__ == '__main__':
    unittest.main(verbosity=2)
