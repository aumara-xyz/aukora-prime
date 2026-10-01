#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Disposable app-only staging protocol checks; no root writes, launch or network."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest

SOURCE = Path(__file__).with_name('preview_stage.py')
loader = importlib.util.spec_from_file_location('preview_stage', SOURCE)
p = importlib.util.module_from_spec(loader); loader.loader.exec_module(p)


class PreviewChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='prime-preview-stage-check-')
        self.base = Path(self.temporary.name).resolve()
        self.release = self.base / 'candidate'; self.release.mkdir(mode=0o755)
        (self.release / 'harness').mkdir(mode=0o755)
        (self.release / 'harness/cli.mjs').write_bytes(b'// immutable entry fixture, never executed\n')
        (self.release / 'prime-release.json').write_text(json.dumps({'source_commit': 'a' * 40}))
        (self.release / 'prime-ui-integrity.json').write_bytes(b'{"version":1,"fixture":true}\n')
        (self.release / 'physical').mkdir(mode=0o755)
        (self.release / 'physical/module.mjs').write_bytes(b'// dependency bytes\n')
        os.chmod(self.release / 'physical/module.mjs', 0o755)
        (self.release / 'node_modules').mkdir(mode=0o755)
        os.symlink('../physical', self.release / 'node_modules/example')
        self.node = self.base / 'trusted-node'; self.node.write_bytes(b'approved node bytes fixture')
        self.node_license = self.base / 'trusted-node-LICENSE'
        self.node_license.write_bytes(b'Official Node license fixture\nCopyright terms preserved exactly.\n')
        self.spec = {'schema': 'prime-preview-stage-v1', 'port': 18732, 'release_source': str(self.release),
                     'release_digest': p.tree(self.release)['digest'], 'node_source': str(self.node),
                     'node_sha256': p.sha(self.node.read_bytes()), 'manifest_source': str(self.base / 'anchor.json'),
                     'node_license_source': str(self.node_license),
                     'node_license_sha256': p.sha(self.node_license.read_bytes()),
                     'manifest_sha256': '0' * 64,
                     'app_entry_sha256': p.sha((self.release / 'harness/cli.mjs').read_bytes())}
        self.manifest = {'version': 1, 'kind': 'prime-preview-deployment/v1', 'source_commit': 'a' * 40,
                         'release_dir': str(p.paths(self.spec)['release']),
                         'release_digest': self.spec['release_digest'],
                         'ui_integrity_sha256': p.sha((self.release / 'prime-ui-integrity.json').read_bytes()),
                         'qualification': 'PENDING'}
        self.anchor()

    def tearDown(self):
        self.temporary.cleanup()

    def anchor(self):
        data = (json.dumps(self.manifest, indent=2) + '\n').encode()
        Path(self.spec['manifest_source']).write_bytes(data)
        self.spec['manifest_sha256'] = p.sha(data)

    def rejects(self, action, reason):
        with self.assertRaises(p.Refusal) as caught:
            action()
        self.assertEqual(str(caught.exception), reason)

    def test_independent_pins_match_with_internal_dependency_links(self):
        anchor, node, license_bytes, observed = p.verify(self.spec)
        self.assertEqual(anchor, Path(self.spec['manifest_source']).read_bytes())
        self.assertEqual(node, self.node.read_bytes())
        self.assertEqual(license_bytes, self.node_license.read_bytes())
        self.assertEqual(observed['digest'], self.spec['release_digest'])
        self.assertIn('physical/module.mjs', observed['entries'])

    def test_digest_matches_owned_javascript_evaluator_unicode_sort_and_links(self):
        node = shutil.which('node')
        if node is None:
            self.skipTest('explicit local evaluator Node unavailable')
        for name in ['\U0001f600.mjs', '\ue000.mjs']:
            (self.release / name).write_bytes(b'unicode order fixture')
        evaluator = SOURCE.parent.parent / 'gates.mjs'
        code = ('import {fullTreeDigest} from ' + json.dumps(evaluator.as_uri())
                + ';console.log(fullTreeDigest(process.argv[1]).digest)')
        result = subprocess.run([node, '--input-type=module', '-e', code, str(self.release)],
                                env={'PATH': '/usr/bin:/bin'}, check=True, capture_output=True, text=True)
        self.assertEqual(result.stdout.strip(), p.tree(self.release)['digest'])

    def test_copied_complete_tree_retains_digest_under_private_umask(self):
        previous = os.umask(0o077)
        try:
            destination = self.base / 'copied'
            copied = p.tree(self.release, destination)
        finally:
            os.umask(previous)
        self.assertEqual(copied['digest'], p.tree(destination)['digest'])
        self.assertEqual((destination / 'physical').stat().st_mode & 0o777, 0o755)
        self.assertEqual((destination / 'physical/module.mjs').stat().st_mode & 0o777, 0o755)
        self.assertEqual(os.readlink(destination / 'node_modules/example'), '../physical')
        # H measured 86,806 digest rows; the bound counts physical directories too.
        # Exercise exact finite cap edges on this small fixture, without a test forest.
        self.assertEqual(p.MAX_FILES, 200000)
        self.assertGreater(p.MAX_FILES, 86806)
        self.assertEqual(p.MAX_BYTES, 2 * 1024 ** 3)
        self.assertEqual(p.MAX_METADATA, 65536)
        entries = len(copied['entries']) - 1
        original_files, original_bytes = p.MAX_FILES, p.MAX_BYTES
        try:
            p.MAX_FILES = entries
            self.assertEqual(p.tree(self.release)['digest'], copied['digest'])
            p.MAX_FILES = entries - 1
            self.rejects(lambda: p.tree(self.release), 'RELEASE_FILE_LIMIT')
            p.MAX_FILES = original_files
            p.MAX_BYTES = copied['bytes']
            self.assertEqual(p.tree(self.release)['digest'], copied['digest'])
            p.MAX_BYTES = copied['bytes'] - 1
            self.rejects(lambda: p.tree(self.release), 'RELEASE_BYTES_LIMIT')
        finally:
            p.MAX_FILES, p.MAX_BYTES = original_files, original_bytes

    def test_changed_dependency_rejected_by_external_release_pin(self):
        (self.release / 'physical/module.mjs').write_bytes(b'changed')
        self.rejects(lambda: p.verify(self.spec), 'RELEASE_PIN_MISMATCH')

    def test_changed_node_rejected(self):
        self.node.write_bytes(b'other node')
        self.rejects(lambda: p.verify(self.spec), 'FILE_PIN_MISMATCH')

    def test_license_source_and_exact_pin_are_required(self):
        for field in ['node_license_source', 'node_license_sha256']:
            spec = copy.deepcopy(self.spec); del spec[field]
            self.rejects(lambda: p.spec_value(spec), 'CLOSED_PREVIEW_SPEC_REQUIRED')
        spec = {**self.spec, 'node_license_sha256': 'wrong'}
        self.rejects(lambda: p.spec_value(spec), 'EXACT_SHA256_REQUIRED')
        spec = {**self.spec, 'node_license_source': 'relative/LICENSE'}
        self.rejects(lambda: p.spec_value(spec), 'ABSOLUTE_CANONICAL_PATH_REQUIRED')

    def test_changed_or_wrong_license_pin_is_rejected(self):
        self.rejects(lambda: p.verify({**self.spec, 'node_license_sha256': 'f' * 64}), 'FILE_PIN_MISMATCH')
        self.node_license.write_bytes(b'changed license')
        self.rejects(lambda: p.verify(self.spec), 'FILE_PIN_MISMATCH')

    def test_license_bound_and_source_link_refused(self):
        self.node_license.write_bytes(b'x' * (2 * 1024 * 1024 + 1))
        self.spec['node_license_sha256'] = p.sha(self.node_license.read_bytes())
        self.rejects(lambda: p.verify(self.spec), 'BOUNDED_SINGLE_LINK_REGULAR_FILE_REQUIRED')
        self.node_license.unlink(); os.symlink('trusted-node', self.node_license)
        with self.assertRaises(OSError):
            p.verify(self.spec)

    def test_runtime_copy_uses_captured_pinned_license_without_source_reread(self):
        _, node, license_bytes, _ = p.verify(self.spec)
        self.node_license.write_bytes(b'changed after verification')
        output = self.base / 'runtime-files'; output.mkdir(mode=0o755)
        previous = os.umask(0o077)
        try:
            p.runtime_files(output, node, license_bytes, p.launcher(self.spec))
        finally:
            os.umask(previous)
        self.assertEqual((output / 'node-LICENSE').read_bytes(), license_bytes)
        self.assertEqual((output / 'node-LICENSE').stat().st_mode & 0o777, 0o644)
        self.assertEqual((output / 'node').read_bytes(), node)
        self.assertEqual((output / 'node').stat().st_mode & 0o777, 0o755)
        self.assertEqual((output / 'launch').read_bytes(), p.launcher(self.spec))
        self.assertEqual(p.plan(self.spec)['destinations']['node_license'],
                         str(p.paths(self.spec)['base'] / 'node-LICENSE'))

    def test_changed_manifest_rejected_before_candidate_observation(self):
        Path(self.spec['manifest_source']).write_bytes(b'{}')
        self.rejects(lambda: p.verify(self.spec), 'FILE_PIN_MISMATCH')

    def test_entry_pin_cannot_be_replaced_by_release_digest(self):
        bad = {**self.spec, 'app_entry_sha256': 'f' * 64}
        self.rejects(lambda: p.verify(bad), 'APP_ENTRY_PIN_MISMATCH')

    def test_ui_anchor_cannot_come_from_candidate(self):
        self.manifest['ui_integrity_sha256'] = 'f' * 64; self.anchor()
        self.rejects(lambda: p.verify(self.spec), 'UI_INTEGRITY_PIN_MISMATCH')

    def test_source_commit_exact_binding(self):
        self.manifest['source_commit'] = 'b' * 40; self.anchor()
        self.rejects(lambda: p.verify(self.spec), 'SOURCE_COMMIT_BINDING_MISMATCH')

    def test_externally_pinned_oversized_metadata_refused_before_staging(self):
        # Independently supplied pins can bind a file that the reviewed boot parser
        # cannot consume. Verification must refuse it before creating root paths.
        metadata = json.dumps({'source_commit': 'a' * 40, 'padding': 'x' * 65536}).encode()
        self.assertGreater(len(metadata), p.MAX_METADATA)
        (self.release / 'prime-release.json').write_bytes(metadata)
        self.spec['release_digest'] = p.tree(self.release)['digest']
        self.manifest['release_digest'] = self.spec['release_digest']
        self.manifest['release_dir'] = str(p.paths(self.spec)['release'])
        self.anchor()
        self.rejects(lambda: p.verify(self.spec), 'BOUNDED_SINGLE_LINK_REGULAR_FILE_REQUIRED')
        self.assertFalse(p.paths(self.spec)['base'].exists())

    def test_manifest_rejects_candidate_path_and_qualification_pass(self):
        self.manifest['release_dir'] = str(self.release); self.anchor()
        self.rejects(lambda: p.verify(self.spec), 'MANIFEST_RELEASE_BINDING_MISMATCH')
        self.manifest['release_dir'] = str(p.paths(self.spec)['release'])
        self.manifest['qualification'] = 'PASS'; self.anchor()
        self.rejects(lambda: p.verify(self.spec), 'EXACT_PENDING_PREVIEW_REQUIRED')

    def test_closed_scope_no_worker_configuration_or_entry_override(self):
        for key in ['authority', 'memory', 'config_source', 'app_entrypoint']:
            bad = {**self.spec, key: 'forbidden extension'}
            self.rejects(lambda: p.spec_value(bad), 'CLOSED_PREVIEW_SPEC_REQUIRED')
        data = Path(self.spec['manifest_source']).read_bytes().replace(b'"version": 1', b'"version": 1, "version": 1')
        self.rejects(lambda: p.strict(data), 'DUPLICATE_JSON_FIELD')

    def test_release_escaping_absolute_and_cyclic_links_rejected(self):
        link = self.release / 'bad'
        for target, reason in [('../../outside', 'RELEASE_LINK_ESCAPES_ROOT'),
                               ('/etc/passwd', 'ABSOLUTE_OR_UNSAFE_RELEASE_LINK'),
                               ('bad', 'RELEASE_LINK_CYCLE')]:
            os.symlink(target, link)
            self.rejects(lambda: p.tree(self.release), reason)
            link.unlink()

    def test_unowned_hardlink_and_group_writes_refused(self):
        os.link(self.release / 'physical/module.mjs', self.release / 'hardlinked')
        self.rejects(lambda: p.tree(self.release), 'NONREGULAR_OR_MUTABLE_RELEASE_FILE')
        (self.release / 'hardlinked').unlink()
        os.chmod(self.release / 'physical/module.mjs', 0o775)
        self.rejects(lambda: p.tree(self.release), 'NONREGULAR_OR_MUTABLE_RELEASE_FILE')

    def test_source_ancestor_links_are_never_followed(self):
        alias = self.base / 'alias'; os.symlink('candidate', alias)
        with self.assertRaises(OSError):
            p.stable_bytes(alias / 'harness/cli.mjs')

    def test_launcher_uses_only_retained_manifest_exact_release_and_app_uid(self):
        launch = p.launcher(self.spec).decode()
        self.assertIn('"997"', launch); self.assertIn('"987"', launch)
        self.assertIn('boot --deployment-manifest /etc/aukora-prime/preview-deployment.json', launch)
        self.assertIn('--release-dir ' + str(p.paths(self.spec)['release']), launch)
        self.assertIn('--state-dir ' + str(p.paths(self.spec)['state']), launch)
        self.assertIn('--port 18732', launch)
        self.assertNotIn('systemctl', launch); self.assertNotIn('--expected-release-digest', launch)
        self.assertNotIn('authority', launch); self.assertNotIn('memory', launch)

    def test_both_explicit_ports_change_launcher_and_spec_pins(self):
        launchers, spec_pins = [], []
        for port in [18731, 18732]:
            spec = {**self.spec, 'port': port}
            launch = p.launcher(spec)
            record = p.plan(spec)
            self.assertEqual(record['port'], port)
            self.assertTrue(launch.endswith((' --port ' + str(port) + '\n').encode()))
            self.assertEqual(record['launcher_sha256'], p.sha(launch))
            launchers.append(record['launcher_sha256'])
            spec_pins.append(p.sha(json.dumps(spec, sort_keys=True).encode()))
        self.assertNotEqual(launchers[0], launchers[1])
        self.assertNotEqual(spec_pins[0], spec_pins[1])

    def test_port_is_required_exact_integer_without_default_or_coercion(self):
        missing = copy.deepcopy(self.spec); del missing['port']
        self.rejects(lambda: p.spec_value(missing), 'CLOSED_PREVIEW_SPEC_REQUIRED')
        for port in [True, False, None, '18731', '18732', 18731.0, 18732.0,
                     0, -1, 443, 18730, 18733, [], {}]:
            with self.subTest(port=port):
                spec = {**self.spec, 'port': port}
                self.rejects(lambda: p.plan(spec), 'EXACT_REVIEWED_PREVIEW_PORT_REQUIRED')
                self.rejects(lambda: p.launcher(spec), 'EXACT_REVIEWED_PREVIEW_PORT_REQUIRED')

    def test_local_render_has_no_process_or_host_mutation(self):
        spec_path = self.base / 'spec.json'; spec_path.write_text(json.dumps(self.spec))
        output = self.base / 'rendered'
        result = subprocess.run([sys.executable, str(SOURCE), 'render', '--spec', str(spec_path),
                                 '--expected-spec-sha256', p.sha(spec_path.read_bytes()),
                                 '--output-dir', str(output)], check=True, capture_output=True, text=True)
        record = json.loads(result.stdout)
        self.assertEqual(record['qualification'], 'PENDING')
        self.assertEqual(sorted(item.name for item in output.iterdir()),
                         ['launch', 'node-LICENSE', 'plan.json', 'preview-deployment.json'])
        self.assertEqual((output / 'node-LICENSE').read_bytes(), self.node_license.read_bytes())
        self.assertEqual((output / 'node-LICENSE').stat().st_mode & 0o777, 0o644)
        self.assertEqual((output / 'preview-deployment.json').read_bytes(),
                         Path(self.spec['manifest_source']).read_bytes())
        self.assertFalse(p.paths(self.spec)['base'].exists())

    def test_mac_apply_is_refused_before_inputs(self):
        if sys.platform == 'darwin':
            self.rejects(lambda: p.apply({}), 'H_LINUX_ROOT_ONLY')
        else:
            self.skipTest('Mac-specific absence of mutation authority')

    def test_existing_output_refused_without_overwrite(self):
        file = self.base / 'existing'; file.write_bytes(b'retain')
        self.rejects(lambda: p.absent(file), 'DESTINATION_ALREADY_EXISTS')
        with self.assertRaises(FileExistsError):
            p.fresh_file(file, b'replacement', 0o644)
        self.assertEqual(file.read_bytes(), b'retain')


if __name__ == '__main__':
    unittest.main()
