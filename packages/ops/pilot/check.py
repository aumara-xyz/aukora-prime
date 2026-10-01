#!/usr/bin/env python3
"""Disposable source checks; never provisions identities, PG or services."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import pilot
import parents
import verify

HERE = Path(__file__).resolve().parent


def fixture(base):
    release = base / 'release'
    (release / 'harness').mkdir(parents=True)
    (release / 'packages/runtime-bridge/src').mkdir(parents=True)
    (release / 'harness/cli.mjs').write_text('// synthetic root boot entry\n')
    (release / 'packages/runtime-bridge/src/worker.mjs').write_text('// synthetic worker entry\n')
    (release / 'node_modules').mkdir()
    (release / 'node_modules/contained').symlink_to('../packages/runtime-bridge', target_is_directory=True)
    node = base / 'node'; node.write_bytes(b'fixture, never executed\n'); node.chmod(0o755)
    spec = dict(schema='prime-pilot-deployment-v1', release_source=str(release),
        release_digest=pilot.full_digest(release), node_source=str(node), node_sha256=pilot.sha(node.read_bytes()),
        deployment_manifest_source=str(base / 'manifest.json'), deployment_manifest_sha256='0' * 64,
        services={})
    for kind in ('app', 'authority', 'memory'):
        entry = 'harness/cli.mjs' if kind == 'app' else 'packages/runtime-bridge/src/worker.mjs'
        row = dict(entrypoint=entry, sha256=pilot.sha((release / entry).read_bytes()))
        if kind != 'app':
            config = base / (kind + '.mjs'); config.write_text('// synthetic config, no secrets\n')
            row.update(config_source=str(config), config_sha256=pilot.sha(config.read_bytes()))
        spec['services'][kind] = row
    manifest = dict(version=1, kind='prime-preview-deployment/v1', source_commit='a' * 40,
                    release_digest=spec['release_digest'], ui_integrity_sha256='b' * 64,
                    release_dir=str(pilot.release_path(spec)), qualification='PENDING')
    data = pilot.json_bytes(manifest); (base / 'manifest.json').write_bytes(data)
    spec['deployment_manifest_sha256'] = pilot.sha(data)
    return spec


class PilotChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='prime-pilot-source-')
        self.base = Path(self.temporary.name)
        self.spec = fixture(self.base)

    def tearDown(self):
        self.temporary.cleanup()

    def test_render_closes_pins_and_verifier_without_host_effects(self):
        with patch.object(pilot, 'command', side_effect=AssertionError('host command')), \
             patch.object(pilot, 'linux_root', side_effect=AssertionError('root mutation')):
            pilot.verify_inputs(self.spec)
            with self.assertRaisesRegex(pilot.Refusal, pilot.WORKER_CONFIG_HOLD):
                pilot.render(self.spec, self.base / 'rendered')
        self.assertFalse((self.base / 'rendered').exists())
        texts = {kind: pilot.unit(kind, self.spec) for kind in pilot.UNITS}
        value = pilot.expectations(self.spec, texts)
        verify.validate_spec(value)
        observation = verify.verify(value, 'source', pilot.sha(pilot.json_bytes(value)))
        self.assertEqual(observation['verdict'], 'PENDING')
        for operation in (pilot.install_code, pilot.install_units):
            with self.assertRaisesRegex(pilot.Refusal, pilot.WORKER_CONFIG_HOLD): operation(self.spec)

    def test_release_bytes_internal_links_and_executable_bits_match_js_evaluator(self):
        gates = (HERE.parent / 'gates.mjs').as_uri()
        code = 'import {fullTreeDigest} from ' + json.dumps(gates) + ';console.log(fullTreeDigest(process.argv[1]).digest)'
        result = subprocess.run(['node', '--input-type=module', '-e', code, self.spec['release_source']],
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), self.spec['release_digest'])
        entry = Path(self.spec['release_source']) / 'harness/cli.mjs'; entry.chmod(0o755)
        self.assertNotEqual(pilot.full_digest(self.spec['release_source']), self.spec['release_digest'])
        entry.chmod(0o644); entry.write_text('// changed\n')
        with self.assertRaisesRegex(pilot.Refusal, 'RELEASE_PIN_MISMATCH'):
            pilot.verify_inputs(self.spec)

    def test_escaping_dependency_link_and_hardlink_refused(self):
        release = Path(self.spec['release_source'])
        outside = self.base / 'outside'; outside.write_text('outside')
        link = release / 'escape'; link.symlink_to('../outside')
        with self.assertRaisesRegex(pilot.Refusal, 'RELEASE_LINK_ESCAPES_ROOT'):
            pilot.full_digest(release)
        link.unlink(); os.link(release / 'harness/cli.mjs', release / 'hardlink')
        with self.assertRaisesRegex(pilot.Refusal, 'MUTABLE_OR_HARDLINKED_RELEASE_FILE'):
            pilot.full_digest(release)

    def test_modified_node_config_and_manifest_refused(self):
        for field, reason in [('node_source', 'FILE_PIN_MISMATCH'),
                              ('deployment_manifest_source', 'FILE_PIN_MISMATCH')]:
            path = Path(self.spec[field]); before = path.read_bytes(); path.write_bytes(before + b'changed')
            with self.assertRaisesRegex(pilot.Refusal, reason): pilot.verify_inputs(self.spec)
            path.write_bytes(before)
        config = Path(self.spec['services']['authority']['config_source']); config.write_text('changed')
        with self.assertRaisesRegex(pilot.Refusal, 'FILE_PIN_MISMATCH'): pilot.verify_inputs(self.spec)

    def test_manifest_binding_cannot_use_candidate_derived_expected_digest(self):
        path = Path(self.spec['deployment_manifest_source'])
        manifest = json.loads(path.read_bytes()); manifest['release_digest'] = 'f' * 64
        data = pilot.json_bytes(manifest); path.write_bytes(data)
        self.spec['deployment_manifest_sha256'] = pilot.sha(data)
        with self.assertRaisesRegex(pilot.Refusal, 'DEPLOYMENT_MANIFEST_BINDING_MISMATCH'):
            pilot.verify_inputs(self.spec)

    def test_unknown_and_unsafe_entrypoint_contracts_refused(self):
        value = copy.deepcopy(self.spec); value['allow_fallback'] = True
        with self.assertRaisesRegex(pilot.Refusal, 'CLOSED_DEPLOYMENT_SPEC_REQUIRED'): pilot.fixed_spec(value)
        value = copy.deepcopy(self.spec); value['services']['authority']['entrypoint'] = '../host.mjs'
        with self.assertRaisesRegex(pilot.Refusal, 'PATH_ESCAPE'): pilot.fixed_spec(value)
        value = copy.deepcopy(self.spec); value['services']['app']['entrypoint'] = 'old-app.mjs'
        with self.assertRaisesRegex(pilot.Refusal, 'EXACT_APP_BOOT_ENTRYPOINT_REQUIRED'): pilot.fixed_spec(value)

    def test_shared_layout_is_disjoint_from_pg_and_protects_retained_witness(self):
        rows = {r['path']: r for r in parents.shared_layout()}
        for root in (pilot.STATE, pilot.RUN):
            self.assertEqual(rows[str(root)], dict(path=str(root), owner='root', group='root', mode='0711'))
        self.assertNotIn(str(pilot.STATE / 'postgres'), rows)
        self.assertNotIn(str(pilot.RUN / 'postgres'), rows)
        self.assertNotIn(str(pilot.CONF), rows)
        self.assertEqual(rows[str(pilot.WITNESS)]['mode'], '0700')
        self.assertNotIn(pilot.STATE, pilot.WITNESS.parents)
        self.assertEqual(set(parents.GROUPS), {'prime-app', 'prime-authority', 'prime-memory', 'prime-authority-ipc', 'prime-memory-ipc'})
        self.assertNotIn('prime-authority-ipc', parents.SUPPLEMENTARY['app'])

    def test_existing_identity_refuses_before_any_privileged_command(self):
        import pwd
        with patch.object(parents, 'linux_root'), patch.object(parents, 'postgres_identity'), \
             patch.object(pwd, 'getpwnam', return_value=object()), \
             patch.object(parents, 'command', side_effect=AssertionError('mutation')):
            with self.assertRaisesRegex(parents.Refusal, 'IDENTITY_EXISTS_NO_ACCOUNT_MUTATION'):
                parents.provision_layout()

    def test_existing_or_symlink_parent_refuses_before_accounts_or_groups(self):
        import pwd, grp
        state = self.base / 'state'; state.symlink_to(self.base, target_is_directory=True)
        with patch.object(parents, 'linux_root'), patch.object(parents, 'postgres_identity'), \
             patch.object(pwd, 'getpwnam', side_effect=KeyError('absent')), \
             patch.object(grp, 'getgrnam', side_effect=KeyError('absent')), \
             patch.object(parents, 'STATE', state), patch.object(parents, 'command', side_effect=AssertionError('mutation')):
            with self.assertRaisesRegex(parents.Refusal, 'OWNED_ROOT_MUST_BE_NEW'):
                parents.provision_layout()

    def test_static_bounded_units_bind_root_manifest_and_fixed_worker_cli(self):
        units = {k: pilot.unit(k, self.spec) for k in pilot.UNITS}
        for value in units.values():
            self.assertNotIn('[Install]', value)
            self.assertNotIn('Wants=', value); self.assertNotIn('Requires=', value)
            self.assertIn('Restart=no', value); self.assertIn('ProtectSystem=strict', value)
            self.assertIn('MemorySwapMax=0', value)
        app = units['app']
        self.assertNotIn('--expected-release-digest', app)
        self.assertNotIn('--release-dir', app)
        self.assertIn('--deployment-manifest /etc/aukora-prime/preview-deployment.json', app)
        self.assertIn('--state-dir /var/lib/aukora-prime/app --port 18731', app)
        self.assertIn('IPAddressAllow=localhost', app)
        for kind in ('authority', 'memory'):
            self.assertIn('worker.mjs --config /etc/aukora-prime/' + kind + '/config.mjs', units[kind])
            self.assertNotIn('--kind', units[kind])
        pg = units['postgres']
        self.assertIn('User=postgres\nGroup=postgres\nSupplementaryGroups=prime-memory', pg)
        self.assertIn('-D /var/lib/aukora-prime/postgres ', pg)
        self.assertNotIn('/postgres/data', pg)
        self.assertIn('RemoveIPC=no', pg)

    def test_peer_only_pg_target_no_password_or_tcp_access(self):
        configs = pilot.postgres_files()
        self.assertIn("listen_addresses = ''", configs['postgresql.conf'])
        self.assertIn("unix_socket_group = 'prime-memory'\nunix_socket_permissions = 0770", configs['postgresql.conf'])
        self.assertIn('local aukora_prime_synthetic prime_memory peer map=prime_memory_role', configs['pg_hba.conf'])
        self.assertEqual(configs['pg_ident.conf'], 'prime_memory_role prime-memory prime_memory\n')
        self.assertIn('PASSWORD NULL', pilot.peer_role_sql())
        self.assertIn('NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', pilot.peer_role_sql())

    def test_cluster_suppression_parser_rejects_ambiguous_policy(self):
        self.assertTrue(pilot.compatible_create_policy(b'# reviewed\ncreate_main_cluster = false # keep\n'))
        for data in (b'create_main_cluster = true\n', b'create_main_cluster = false\ninclude x\n',
                     b'create_main_cluster = false\ncreate_main_cluster = false\n', b'\xff'):
            self.assertFalse(pilot.compatible_create_policy(data))

    def test_pinned_json_uses_held_inode_bytes_and_duplicate_fields_refuse(self):
        path = self.base / 'spec.json'; data = b'{"ok":1}'; path.write_bytes(data)
        original = pilot.os.open
        def replace_after_open(p, flags, *args):
            fd = original(p, flags, *args)
            if Path(p) == path:
                path.rename(path.with_suffix('.old')); path.write_bytes(b'{"ok":2}')
            return fd
        with patch.object(pilot.os, 'open', side_effect=replace_after_open):
            self.assertEqual(json.loads(pilot.regular(path, pilot.sha(data))), {'ok': 1})
        with self.assertRaisesRegex(pilot.Refusal, 'DUPLICATE_JSON_FIELD'):
            json.loads('{"ok":1,"ok":2}', object_pairs_hook=pilot.pairs)

    def test_missing_or_wrong_artifact_pin_refuses_before_any_mutation(self):
        for extra in ([], ['--expected-artifact-sha256', '0' * 64]):
            r = subprocess.run([sys.executable, '-B', str(HERE / 'parents.py'), 'provision-layout', *extra],
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(json.loads(r.stdout)['status'], 'REFUSED')


if __name__ == '__main__':
    unittest.main()
