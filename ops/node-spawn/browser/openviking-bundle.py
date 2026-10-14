#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Verify pinned wheels, model and llama tree before bundling or extraction."""
import argparse
import email.parser
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

DOMAIN = 'aukora:browser-openviking-bundle:v1'
MAX_BYTES = 6 * 1024 ** 3
MAX_ENTRIES = 512
WHEEL = 'openviking-0.4.21-cp310-abi3-manylinux_2_31_x86_64.whl'
WHEEL_SHA = 'e223518bd33b50bbd6b1c7860e4856cd7c477eb8656afdbe7871ff59355b37a6'


class Refusal(ValueError):
    pass


def refuse(code):
    raise Refusal('OPENVIKING_BUNDLE_' + code)


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def relative(value):
    if not isinstance(value, str) or not value or '\\' in value or '\n' in value or '\r' in value:
        refuse('PATH_INVALID')
    path = Path(value)
    if path.is_absolute() or path.as_posix() != value or any(part in ('', '.', '..') for part in value.split('/')):
        refuse('PATH_INVALID')
    return value


def normalized(value):
    return re.sub('[-_.]+', '-', value).lower()


def pins(checkout):
    checkout = Path(checkout)
    pin = json.loads((checkout / 'vendor/openviking/upstream-openviking.json').read_bytes())
    lock = (checkout / 'vendor/openviking' / relative(pin['lock']['path'])).read_bytes()
    if hashlib.sha256(lock).hexdigest() != pin['lock']['sha256']:
        refuse('LOCK_DIGEST_MISMATCH')
    rows = {}
    for block in lock.decode('ascii').replace('\\\n', '').splitlines():
        if not block.strip():
            continue
        match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([^\s]+)\s+((?:--hash=sha256:[0-9a-f]{64}\s*)+)', block)
        if not match or normalized(match[1]) in rows:
            refuse('LOCK_INVALID')
        rows[normalized(match[1])] = (match[2], set(re.findall(r'sha256:([0-9a-f]{64})', match[3])))
    if pin['version'] != '0.4.21' or rows.get('openviking', (None, ()))[0] != '0.4.21' or WHEEL_SHA not in rows['openviking'][1]:
        refuse('WHEEL_PIN_MISMATCH')
    if len(rows) != pin['lock']['distributions'] or pin['lock']['python'] != '3.11':
        refuse('LOCK_INVALID')
    llama = json.loads((checkout / 'host/pins/llama-server-b11381.json').read_bytes())
    if llama['version'] != 'b11381' or llama['install_dir'] != '/opt/llama.cpp/b11381':
        refuse('LLAMA_PIN_INVALID')
    files = {relative(row['path']): row['sha256'] for row in llama['files']}
    links = {relative(row['path']): row['target'] for row in llama['symlinks']}
    if (len(files) != len(llama['files']) or len(links) != len(llama['symlinks']) or files.keys() & links.keys()
            or files.get(llama['entry']) != llama['entry_sha256']
            or any(re.fullmatch('[0-9a-f]{64}', value) is None for value in files.values())):
        refuse('LLAMA_PIN_INVALID')
    for name, target in links.items():
        relative(target)
        if (Path(name).parent / target).as_posix() not in files.keys() | links.keys():
            refuse('LLAMA_PIN_INVALID')
    return pin, lock, rows, files, links


def tree_entries(root):
    files, links, directories = {}, {}, set()
    pending = [Path(root)]
    while pending:
        directory = pending.pop()
        for child in directory.iterdir():
            name = child.relative_to(root).as_posix()
            mode = child.lstat().st_mode
            if stat.S_ISLNK(mode):
                links[name] = os.readlink(child)
            elif stat.S_ISDIR(mode):
                directories.add(name)
                pending.append(child)
            elif stat.S_ISREG(mode) and child.stat().st_nlink == 1:
                files[name] = {'path': name, 'bytes': child.stat().st_size, 'sha256': digest(child)}
            else:
                refuse('FILE_TYPE_INVALID')
    implied = {parent.as_posix() for name in (*files, *links) for parent in Path(name).parents if parent != Path('.')}
    if directories != implied:
        refuse('TREE_UNLISTED')
    return files, links


def verify_llama(root, expected_files, expected_links):
    files, links = tree_entries(root)
    if {name: row['sha256'] for name, row in files.items()} != expected_files or links != expected_links:
        refuse('LLAMA_TREE_MISMATCH')


def wheel_identity(path):
    parts = path.name[:-4].split('-')
    if path.suffix != '.whl' or len(parts) not in (5, 6):
        refuse('WHEEL_INVALID')
    py, abi, architecture = parts[-3:]
    platforms = architecture.split('.')
    allowed_platform = all(value == 'any' or value in ('manylinux1_x86_64', 'manylinux2010_x86_64', 'manylinux2014_x86_64')
                           or (re.fullmatch(r'manylinux_2_([0-9]+)_x86_64', value) and int(value.split('_')[2]) <= 39) for value in platforms)
    allowed_python = any(value in ('py3', 'py311', 'cp311') or (abi == 'abi3' and re.fullmatch(r'cp3[0-9]+', value)
                        and int(value[3:]) <= 11) for value in py.split('.'))
    if not allowed_platform or not allowed_python or abi not in ('none', 'abi3', 'cp311'):
        refuse('WHEEL_PLATFORM_INVALID')
    with zipfile.ZipFile(path) as archive:
        metadata = [item for item in archive.infolist() if item.filename.endswith('.dist-info/METADATA')]
        wheel = [item for item in archive.infolist() if item.filename.endswith('.dist-info/WHEEL')]
        if (len(metadata) != 1 or metadata[0].file_size > 1024 * 1024 or len(wheel) != 1
                or wheel[0].file_size > 1024 * 1024
                or metadata[0].filename.rsplit('/', 1)[0] != wheel[0].filename.rsplit('/', 1)[0]):
            refuse('WHEEL_METADATA_INVALID')
        headers = email.parser.BytesParser().parsebytes(archive.read(metadata[0]))
        wheel_headers = email.parser.BytesParser().parsebytes(archive.read(wheel[0]))
        expected_tags = {python_tag + '-' + abi_tag + '-' + platform_tag
                         for python_tag in py.split('.') for abi_tag in abi.split('.') for platform_tag in platforms}
        if set(wheel_headers.get_all('Tag', [])) != expected_tags:
            refuse('WHEEL_METADATA_INVALID')
    name, version = headers.get('Name'), headers.get('Version')
    if not name or not version or normalized(name) != normalized(parts[0]) or version != parts[1]:
        refuse('WHEEL_METADATA_INVALID')
    return normalized(name), version


def validate_tree(root, checkout, manifest=True):
    root = Path(root)
    pin, lock, rows, llama_files, llama_links = pins(checkout)
    files, links = tree_entries(root)
    if links != {'llama/' + name: target for name, target in llama_links.items()}:
        refuse('LLAMA_TREE_MISMATCH')
    lock_row = files.get('requirements.lock')
    if not lock_row or lock_row['bytes'] != len(lock) or lock_row['sha256'] != pin['lock']['sha256']:
        refuse('LOCK_DIGEST_MISMATCH')
    model_name = 'models/' + relative(pin['embeddingModel']['file'])
    model = files.get(model_name)
    if not model or model['bytes'] != pin['embeddingModel']['bytes'] or model['sha256'] != pin['embeddingModel']['sha256']:
        refuse('MODEL_DIGEST_MISMATCH')
    verify_llama(root / 'llama', llama_files, llama_links)
    selected = {}
    for name, row in files.items():
        if not name.startswith('wheels/'):
            continue
        if name.count('/') != 1:
            refuse('WHEEL_INVALID')
        filename = Path(name).name
        parts = filename[:-4].split('-')
        if not filename.endswith('.whl') or len(parts) not in (5, 6):
            refuse('WHEEL_INVALID')
        declared_name, declared_version = normalized(parts[0]), parts[1]
        if declared_name not in rows or rows[declared_name][0] != declared_version or row['sha256'] not in rows[declared_name][1]:
            refuse('WHEEL_DIGEST_MISMATCH')
        distribution, version = wheel_identity(root / name)
        if distribution in selected:
            refuse('WHEEL_DUPLICATE')
        selected[distribution] = name
    if selected.keys() != rows.keys():
        refuse('CLOSURE_INCOMPLETE')
    if selected['openviking'] != 'wheels/' + WHEEL or files[selected['openviking']]['sha256'] != WHEEL_SHA:
        refuse('WHEEL_PIN_MISMATCH')
    expected = {'requirements.lock', model_name} | {'llama/' + name for name in llama_files} | set(selected.values())
    if set(files) != expected | ({'manifest.json'} if manifest else set()):
        refuse('TREE_UNLISTED')
    artifacts = [files[name] for name in sorted(expected)]
    result = {'domain': DOMAIN, 'platform': 'linux-x86_64', 'python': '3.11', 'artifacts': artifacts,
              'symlinks': [{'path': name, 'target': links[name]} for name in sorted(links)],
              'totalBytes': sum(row['bytes'] for row in artifacts)}
    if result['totalBytes'] > MAX_BYTES or len(files) + len(links) > MAX_ENTRIES:
        refuse('SIZE_LIMIT')
    if manifest:
        if (root / 'manifest.json').stat().st_size > 1024 * 1024:
            refuse('MANIFEST_INVALID')
        if json.loads((root / 'manifest.json').read_bytes()) != result:
            refuse('MANIFEST_MISMATCH')
    return result


class BundleTarInfo(tarfile.TarInfo):
    @classmethod
    def frombuf(cls, buffer, encoding, errors):
        member = super().frombuf(buffer, encoding, errors)
        if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.SYMTYPE):
            refuse('ARCHIVE_TYPE_INVALID')
        return member


def extract_bundle(archive, target, checkout):
    target = Path(target)
    if target.exists() or not target.is_absolute() or target.parent.resolve() != target.parent:
        refuse('TARGET_INVALID')
    _, _, _, _, llama_links = pins(checkout)
    allowed_links = {'llama/' + name: value for name, value in llama_links.items()}
    try:
        target.mkdir(mode=0o700)
        with tarfile.open(archive, 'r:gz', tarinfo=BundleTarInfo) as source:
            names, count, total = set(), 0, 0
            for member in source:
                name = relative(member.name)
                count += 1
                if name in names:
                    refuse('ARCHIVE_DUPLICATE')
                names.add(name)
                total += member.size
                if count > MAX_ENTRIES or member.size < 0 or total > MAX_BYTES or member.sparse is not None:
                    refuse('SIZE_LIMIT')
                if member.isdir():
                    refuse('ARCHIVE_TYPE_INVALID')
                if member.issym():
                    if allowed_links.get(name) != member.linkname:
                        refuse('ARCHIVE_LINK_INVALID')
                    continue
                if not member.isfile() or any(parent.as_posix() in names and parent.as_posix() in allowed_links for parent in Path(name).parents):
                    refuse('ARCHIVE_TYPE_INVALID')
                destination = target / name
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with source.extractfile(member) as stream, destination.open('xb') as output:
                    shutil.copyfileobj(stream, output, 1024 * 1024)
        for name in sorted(names & allowed_links.keys()):
            destination = target / name
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            destination.symlink_to(allowed_links[name])
        return validate_tree(target, checkout)
    except BaseException:
        shutil.rmtree(target)
        raise


def build(output, llama_tree, checkout):
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        refuse('LINUX_X86_64_REQUIRED')
    if any(name in os.environ for name in ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT')):
        refuse('PRELOAD_FORBIDDEN')
    py = shutil.which('python3.11')
    if not py:
        refuse('PYTHON311_REQUIRED')
    if subprocess.run([py, '-I', '-c', 'import sys; sys.exit(sys.version_info[:2] != (3,11))'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        refuse('PYTHON311_REQUIRED')
    output, llama_tree = Path(output), Path(llama_tree)
    if not output.is_absolute() or output.exists() or output.parent.resolve() != output.parent:
        refuse('OUTPUT_INVALID')
    if not llama_tree.is_absolute() or llama_tree.resolve() != llama_tree or not llama_tree.is_dir():
        refuse('LLAMA_INPUT_INVALID')
    pin, lock, _, files, links = pins(checkout)
    verify_llama(llama_tree, files, links)
    if shutil.disk_usage(output.parent).free < MAX_BYTES:
        refuse('DISK_REQUIRED')
    with tempfile.TemporaryDirectory(prefix='.openviking-bundle-', dir=output.parent) as temporary:
        root = Path(temporary) / 'payload'
        root.mkdir()
        (root / 'wheels').mkdir()
        (root / 'models').mkdir()
        (root / 'requirements.lock').write_bytes(lock)
        # The existing lock chooses versions and hashes; pip may choose only binary Linux CPython 3.11 artifacts.
        environment = {name: value for name, value in os.environ.items() if not name.startswith(('PIP_', 'PYTHON'))}
        platforms = ['manylinux_2_%d_x86_64' % minor for minor in range(39, 4, -1)]
        platforms += ['manylinux2014_x86_64', 'manylinux2010_x86_64', 'manylinux1_x86_64']
        target = [value for name in platforms for value in ('--platform', name)]
        target += ['--python-version', '3.11', '--implementation', 'cp', '--abi', 'cp311', '--abi', 'abi3', '--abi', 'none']
        commands = [[py, '-I', '-m', 'pip', '--isolated', 'download', '--disable-pip-version-check', '--no-cache-dir', *target,
                     '--index-url', 'https://pypi.org/simple', '--only-binary=:all:', '--require-hashes', '--no-deps',
                     '--dest', str(root / 'wheels'), '-r', str(root / 'requirements.lock')],
                    ['curl', '-fsSL', '--proto', '=https', '--proto-redir', '=https', '--retry', '2',
                     '--output', str(root / 'models' / pin['embeddingModel']['file']), pin['embeddingModel']['url']]]
        for command in commands:
            if not shutil.which(command[0]) or subprocess.run(command, env=environment, stdout=subprocess.DEVNULL,
                                                            stderr=subprocess.DEVNULL).returncode:
                refuse('DOWNLOAD_FAILED')
        shutil.copytree(llama_tree, root / 'llama', symlinks=True)
        result = validate_tree(root, checkout, manifest=False)
        (root / 'manifest.json').write_text(json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n')
        partial = Path(temporary) / 'bundle.tar.gz'
        with partial.open('wb') as output_stream, gzip.GzipFile(filename='', mode='wb', fileobj=output_stream, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                actual, symlinks = tree_entries(root)
                for name in sorted(actual.keys() | symlinks.keys()):
                    info = tarfile.TarInfo(name)
                    info.mode = 0o644
                    if name in symlinks:
                        info.type, info.linkname, info.mode = tarfile.SYMTYPE, symlinks[name], 0o777
                        archive.addfile(info)
                    else:
                        info.size = actual[name]['bytes']
                        with (root / name).open('rb') as source:
                            archive.addfile(info, source)
        # Exclusive publication keeps an existing output intact even if it appears during the build.
        with output.open('xb') as published, partial.open('rb') as source:
            shutil.copyfileobj(source, published, 1024 * 1024)
        for row in result['artifacts']:
            print('ARTIFACT %s bytes=%d sha256=%s' % (row['path'], row['bytes'], row['sha256']))
        print('ARTIFACT manifest.json bytes=%d sha256=%s' % ((root / 'manifest.json').stat().st_size, digest(root / 'manifest.json')))
        print('BUNDLE bytes=%d sha256=%s payload_bytes=%d' % (output.stat().st_size, digest(output), result['totalBytes']))


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        refuse('USAGE')


def main():
    parser = Arguments()
    parser.add_argument('--output', required=True)
    parser.add_argument('--llama-tree', required=True)
    try:
        arguments = parser.parse_args()
        if any(sys.argv.count(flag) != 1 for flag in ('--output', '--llama-tree')):
            refuse('DUPLICATE_ARGUMENT')
        build(arguments.output, arguments.llama_tree, Path(__file__).resolve().parents[3])
    except (Refusal, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, tarfile.TarError):
        error = sys.exc_info()[1]
        print('REFUSED ' + (str(error) if isinstance(error, Refusal) else 'OPENVIKING_BUNDLE_INPUT_INVALID'), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
