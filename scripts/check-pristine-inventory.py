#!/usr/bin/env python3
"""Disposable, offline archive/pristine guards, with a fake version-only executable for one gate.

No real package manager, archive command, compiler or network is used. PATH contains only refusal
sentinels for pnpm/node/tar, except one task-owned wrong-version stub. Full-mode negative cases
prove refusal before commands/install; all positive cases stop at patches-only. Every fixture has
its own locally produced hash-pinned archive.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

SCRIPT = Path(__file__).resolve().with_name('build-dsh.py')
BASE = [
    {'name': 'fixture/', 'type': tarfile.DIRTYPE},
    {'name': 'fixture/README.md', 'body': b'original\n'},
    {'name': 'fixture/pnpm-lock.yaml', 'body': b'lockfileVersion: 9\n'},
    {'name': 'fixture/package.json', 'body': b'{"name":"disposable-pristine-fixture"}\n'},
    {'name': 'fixture/empty/', 'type': tarfile.DIRTYPE},
    {'name': 'fixture/nested/tool.sh', 'body': b'#!/bin/sh\nexit 0\n', 'mode': 0o775},
    {'name': 'fixture/README.link', 'type': tarfile.SYMTYPE, 'target': 'README.md'},
    {'name': 'fixture/nested/readme', 'type': tarfile.SYMTYPE, 'target': '../README.link'},
]
checks = 0
assertions = 0


def require(condition, message):
    global assertions
    assertions += 1
    if not condition:
        raise AssertionError(message)


class Fixture:
    def __init__(self, directory, members=None, existing=True, patch=False):
        self.root = directory / 'root'
        self.source = self.root / 'vendor/dsh'
        self.archive = self.root / 'vendor/dsh-source.tar.gz'
        self.root.joinpath('patches').mkdir(parents=True)
        self.archive.parent.mkdir()
        self.members = BASE if members is None else members
        with tarfile.open(self.archive, 'w:gz', format=tarfile.PAX_FORMAT) as snapshot:
            for item in self.members:
                member = tarfile.TarInfo(item['name'])
                member.type = item.get('type', tarfile.REGTYPE)
                member.mode = item.get('mode', 0o775 if member.isdir() else 0o664)
                member.linkname = item.get('target', '')
                body = item.get('body', b'')
                member.size = len(body) if member.isfile() else 0
                snapshot.addfile(member, io.BytesIO(body) if member.isfile() else None)
        pin = {'commit': '0' * 40, 'archiveUrl': 'https://example.invalid/never-requested',
               'archiveSha256': hashlib.sha256(self.archive.read_bytes()).hexdigest(),
               'lockfileSha256': hashlib.sha256(b'lockfileVersion: 9\n').hexdigest(),
               'packageManager': 'pnpm@11.7.0', 'localPatches': []}
        if patch:
            spec = {'formatVersion': 1, 'reason': 'Disposable exact patch only.',
                    'edits': [{'path': 'README.md', 'find': 'original', 'replace': 'patched'}],
                    'expectAfterApply': [{'path': 'README.md', 'contains': 'patched'}],
                    'expectAfterBuild': [{'path': 'built.js', 'contains': 'fixture artifact'}]}
            patch_path = self.root / 'patches/fixture.patch.json'
            patch_path.write_text(json.dumps(spec))
            pin['localPatches'] = [{'file': 'patches/fixture.patch.json', 'reason': spec['reason'],
                                   'sha256': hashlib.sha256(patch_path.read_bytes()).hexdigest()}]
        (self.root / 'upstream-dsh.json').write_text(json.dumps(pin))
        self.marker = directory / 'forbidden-command-invoked'
        self.bin = directory / 'sentinel-bin'
        self.bin.mkdir()
        for name in ('pnpm', 'node', 'tar'):
            sentinel = self.bin / name
            sentinel.write_text('#!/bin/sh\nprintf invoked > "' + str(self.marker) + '"\nexit 97\n')
            sentinel.chmod(0o755)
        if existing:
            self.source.mkdir()
            # Fixture construction is independent of the producer's extraction code.
            for item in self.members:
                path = '/'.join(item['name'].rstrip('/').split('/')[1:])
                if not path:
                    continue
                target = self.source / path
                target.parent.mkdir(parents=True, exist_ok=True)
                kind = item.get('type', tarfile.REGTYPE)
                if kind == tarfile.DIRTYPE:
                    target.mkdir(exist_ok=True)
                elif kind == tarfile.SYMTYPE:
                    target.symlink_to(item['target'])
                elif kind == tarfile.REGTYPE:
                    target.write_bytes(item.get('body', b''))
                    target.chmod(0o755 if item.get('mode', 0o664) & 0o111 else 0o644)

    def run(self, expected=None, options=('--patches-only',)):
        global checks
        command = [sys.executable, str(SCRIPT), '--root', str(self.root), *options]
        result = subprocess.run(command, env={**os.environ, 'PATH': str(self.bin)},
                                capture_output=True, text=True, timeout=15)
        checks += 1
        require(not self.marker.exists(), 'forbidden command executed: ' + str(command))
        output = result.stdout + result.stderr
        if expected is None:
            require(result.returncode == 0, output)
            require('no install, build or record was run' in output, output)
        else:
            require(result.returncode != 0 and expected in output, output)
        return result


def case(name, action):
    with tempfile.TemporaryDirectory(prefix='prime-pristine-') as temporary:
        action(Path(temporary))
    print('PASS ' + name)


def mutate_tree(directory, mutation, expected='source-path-unexpected'):
    fixture = Fixture(directory)
    mutation(fixture)
    fixture.run(expected)


def invalid_archive(directory, member, expected):
    fixture = Fixture(directory, [*BASE, member], existing=False)
    fixture.run(expected)
    require(not fixture.source.exists(), 'invalid archive must not be published')
    require(not list(fixture.archive.parent.glob('.dsh-pristine-*')), 'temporary extraction leaked')


case('fresh verified extraction including contained symlinks', lambda directory: Fixture(directory, existing=False).run())
case('matching complete existing inventory', lambda directory: Fixture(directory).run())
case('implicit archive parent directories', lambda directory: Fixture(
    directory, [item for item in BASE if item.get('type') != tarfile.DIRTYPE], existing=False).run())


def patched(directory):
    fixture = Fixture(directory, patch=True)
    fixture.run()
    require(fixture.source.joinpath('README.md').read_text() == 'patched\n', 'exact patch lost')
    fixture.run('source-file-mismatch')


case('exact patches apply after pristine gate; rerun refuses patched bytes', patched)


def build_phase_fixture(directory):
    fixture = Fixture(directory, patch=True)
    fixture.source.joinpath('built.js').write_text('fixture artifact\n')
    fixture.run(options=('--patches-only', '--skip-pristine', '--phase', 'build'))
    require(fixture.source.joinpath('README.md').read_text() == 'original\n', 'build phase must not patch')


case('legacy build-expectation fixture seam has no execution', build_phase_fixture)


def no_build_bypass(directory):
    fixture = Fixture(directory)
    binding = fixture.source / '.dsh-build/pinned-harness-build.json'
    binding.parent.mkdir()
    binding.write_text('retain before refused CLI\n')
    fixture.run('--skip-pristine requires --patches-only', options=('--skip-pristine',))
    require(binding.read_text() == 'retain before refused CLI\n', 'CLI refusal mutated binding')


case('build cannot bypass inventory, refusal precedes mutation', no_build_bypass)

for name in ('.pnpmfile.cjs', '.pnpmfile.mjs', '.npmrc', 'pnpmfile.cjs', 'pnpm-workspace.yaml', 'extra.js'):
    case('extra file refused: ' + name, lambda directory, name=name: mutate_tree(
        directory, lambda fixture: fixture.source.joinpath(name).write_text('unarchived\n')))
for name in ('node_modules', '.dsh-build', 'lib', '.pnpm'):
    case('extra generated directory refused: ' + name, lambda directory, name=name: mutate_tree(
        directory, lambda fixture: fixture.source.joinpath(name).mkdir()))
case('extra nested configuration refused', lambda directory: mutate_tree(
    directory, lambda fixture: fixture.source.joinpath('nested/.npmrc').write_text('unarchived\n')))
case('extra symlink refused without traversal', lambda directory: mutate_tree(
    directory, lambda fixture: fixture.source.joinpath('extra-link').symlink_to('../outside')))
case('extra FIFO refused', lambda directory: mutate_tree(
    directory, lambda fixture: os.mkfifo(fixture.source / 'extra-pipe')))
case('missing regular file refused', lambda directory: mutate_tree(
    directory, lambda fixture: fixture.source.joinpath('README.md').unlink(), 'source-path-missing'))
case('missing empty directory refused', lambda directory: mutate_tree(
    directory, lambda fixture: fixture.source.joinpath('empty').rmdir(), 'source-path-missing'))


def replace_path(fixture, name, kind):
    target = fixture.source / name
    target.unlink() if not target.is_dir() else target.rmdir()
    if kind == 'directory':
        target.mkdir()
    elif kind == 'link':
        target.symlink_to('package.json')
    else:
        target.write_text('replacement\n')


for name, kind in (('README.md', 'directory'), ('README.md', 'link'), ('empty', 'link'), ('README.link', 'file')):
    case('archive path type mismatch: ' + name + '/' + kind, lambda directory, name=name, kind=kind: mutate_tree(
        directory, lambda fixture: replace_path(fixture, name, kind), 'source-type-mismatch'))
case('changed archived symlink target refused', lambda directory: mutate_tree(
    directory, lambda fixture: (fixture.source.joinpath('README.link').unlink(),
                                fixture.source.joinpath('README.link').symlink_to('package.json')),
    'source-link-mismatch'))
case('changed archived bytes refused', lambda directory: mutate_tree(
    directory, lambda fixture: fixture.source.joinpath('README.md').write_text('modified\n'), 'source-file-mismatch'))
case('changed executable mode refused', lambda directory: mutate_tree(
    directory, lambda fixture: fixture.source.joinpath('README.md').chmod(0o755), 'source-mode-mismatch'))
case('changed directory mode refused', lambda directory: mutate_tree(
    directory, lambda fixture: fixture.source.joinpath('empty').chmod(0o777), 'source-mode-mismatch'))
case('changed extraction root mode refused', lambda directory: mutate_tree(
    directory, lambda fixture: fixture.source.chmod(0o777), 'source-root-mode-mismatch'))


def archived_hardlink(fixture):
    original = fixture.source / 'README.md'
    outside = fixture.root / 'retained-copy'
    original.rename(outside)
    os.link(outside, original)


case('extracted regular-file hardlink refused', lambda directory: mutate_tree(directory, archived_hardlink,
                                                                           'source-file-link-mismatch'))
for name in ('fixture/../escape', '../escape', '/absolute', 'fixture//extra', 'fixture/./extra',
             'fixture\\extra', 'fixture/line\nextra', 'C:/drive'):
    case('unsafe archive path refused: ' + repr(name), lambda directory, name=name: invalid_archive(
        directory, {'name': name, 'body': b'unsafe'}, 'source-archive-path-invalid'))
case('multiple archive roots refused', lambda directory: invalid_archive(
    directory, {'name': 'other/file', 'body': b'unsafe'}, 'source-archive-root-mismatch'))
case('duplicate archive file refused', lambda directory: invalid_archive(
    directory, {'name': 'fixture/README.md', 'body': b'duplicate'}, 'source-archive-path-duplicate'))
case('duplicate canonical directory refused', lambda directory: invalid_archive(
    directory, {'name': 'fixture/empty', 'type': tarfile.DIRTYPE}, 'source-archive-path-duplicate'))
case('file replacing implicit directory refused', lambda directory: invalid_archive(
    directory, {'name': 'fixture/nested', 'body': b'unsafe'}, 'source-archive-parent-type-mismatch'))
case('symlink-parent archive child refused', lambda directory: invalid_archive(
    directory, {'name': 'fixture/README.link/child', 'body': b'unsafe'}, 'source-archive-parent-type-mismatch'))
for kind in (tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE):
    case('unsupported archive member type refused: ' + str(kind), lambda directory, kind=kind: invalid_archive(
        directory, {'name': 'fixture/unsupported', 'type': kind, 'target': 'fixture/README.md'},
        'source-archive-type-invalid'))
case('special archive permission bits refused', lambda directory: invalid_archive(
    directory, {'name': 'fixture/suid', 'body': b'unsafe', 'mode': 0o4755}, 'source-archive-type-invalid'))
for target, expected in (('../outside', 'source-archive-link-escape'), ('/outside', 'source-archive-link-invalid'),
                         ('absent', 'source-archive-link-dangling'), ('cycle', 'source-archive-link-cycle'),
                         ('README.md/child', 'source-archive-link-type-mismatch'),
                         ('empty/../README.md', 'source-archive-link-escape'),
                         ('README.md\n', 'source-archive-link-invalid')):
    case('unsafe archive symlink refused: ' + repr(target), lambda directory, target=target, expected=expected:
         invalid_archive(directory, {'name': 'fixture/cycle', 'type': tarfile.SYMTYPE, 'target': target}, expected))


def symlink_source_root(directory):
    fixture = Fixture(directory)
    outside = fixture.root / 'outside-source'
    fixture.source.rename(outside)
    fixture.source.symlink_to(outside)
    fixture.run('source-root-type-mismatch')
    require(outside.joinpath('README.md').read_bytes() == b'original\n', 'outside source changed')


case('symlink extraction root refused', symlink_source_root)


def digest_drift(directory):
    fixture = Fixture(directory)
    with fixture.archive.open('ab') as archive:
        archive.write(b'changed')
    fixture.run('source-digest-mismatch')


case('archive digest drift refused', digest_drift)


def archive_link_or_special(directory, kind):
    fixture = Fixture(directory)
    retained = fixture.root / 'retained-archive'
    fixture.archive.rename(retained)
    if kind == 'symlink':
        fixture.archive.symlink_to(retained)
    elif kind == 'dangling-symlink':
        fixture.archive.symlink_to(fixture.root / 'absent')
    elif kind == 'hardlink':
        os.link(retained, fixture.archive)
    else:
        os.mkfifo(fixture.archive)
    fixture.run('source-archive-type-invalid')


for kind in ('symlink', 'dangling-symlink', 'hardlink', 'FIFO'):
    case('archive metadata refuses without command/network: ' + kind, lambda directory, kind=kind:
         archive_link_or_special(directory, kind))


def refused_before_version(directory):
    fixture = Fixture(directory)
    fixture.source.joinpath('.pnpmfile.cjs').write_text('unarchived hook\n')
    fixture.run('source-path-unexpected', options=())


case('contaminated full build refuses before pnpm version lookup', refused_before_version)


def wrong_version(directory):
    fixture = Fixture(directory)
    version_marker = directory / 'fake-version-queried'
    sentinel = fixture.bin / 'pnpm'
    sentinel.write_text('#!/bin/sh\nif [ "$#" = 1 ] && [ "$1" = --version ]; then\n'
                        '  printf queried > "' + str(version_marker) + '"\n'
                        '  printf "11.6.0\\n"\n  exit 0\nfi\n'
                        'printf forbidden > "' + str(fixture.marker) + '"\nexit 97\n')
    sentinel.chmod(0o755)
    fixture.run('package-manager-version-mismatch', options=())
    require(version_marker.read_text() == 'queried', 'wrong-version seam was not reached')
    require(not fixture.source.joinpath('.dsh-build').exists(), 'refusal minted build metadata')


case('wrong pnpm version refuses before install or build (task-owned stub)', wrong_version)
print(json.dumps({'status': 'PASS', 'checks': checks, 'assertions': assertions,
                  'scope': 'synthetic disposable archive/pristine and patches-only guards',
                  'package_manager_invocations': 0, 'network_requests': 0,
                  'fake_version_only_stub_invocations': 1,
                  'actual_pinned_build': 'UNPERFORMED'}, sort_keys=True))
