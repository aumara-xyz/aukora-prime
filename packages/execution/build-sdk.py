#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Materialize/build the exact third-party SDK from an owner-supplied archive."""
import argparse, hashlib, json, pathlib, subprocess, tarfile

COMMIT = '6648bd0c290efbc41ba131ee9831ee45cd431f94'
ARCHIVE_SHA256 = '298ee3c0566c51e593e9eadc724a0e1c072fbb542b4f362b82e82a254f8eaea6'
FILES = ['LICENSE', 'buf.yaml'] + [f'proto/{p}.proto' for p in ['openshell','sandbox','datamodel','options']] + [
    f'sdk/typescript/{p}' for p in ['package.json','package-lock.json','buf.gen.yaml','tsconfig.json','tsconfig.build.json','tsconfig.json.license','tsconfig.build.json.license','README.md']
] + [f'sdk/typescript/src/{p}.ts' for p in ['client','errors','index','oidc','raw','ssh-validate','transport']]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=pathlib.Path, required=True)
    parser.add_argument('--into', type=pathlib.Path, required=True)
    parser.add_argument('--build', action='store_true', help='Install locked local dependencies, generate and compile. Requires network.')
    args = parser.parse_args()
    if digest(args.archive) != ARCHIVE_SHA256:
        raise SystemExit('archive digest mismatch')
    if args.into.exists() and any(args.into.iterdir()):
        raise SystemExit('destination must be empty')
    args.into.mkdir(parents=True, exist_ok=True)
    with tarfile.open(args.archive) as archive:
        for rel in FILES:
            item = archive.getmember(f'OpenShell-{COMMIT}/{rel}')
            if not item.isfile():
                raise SystemExit(f'non-regular source entry: {rel}')
            target = args.into / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.extractfile(item).read())
    sdk = args.into / 'sdk/typescript'
    metadata = json.loads((sdk / 'package.json').read_text())
    if metadata['name'] != '@nvidia/openshell-sdk' or metadata['version'] != '0.0.0':
        raise SystemExit('unexpected SDK package metadata')
    source_hashes = {rel: digest(args.into / rel) for rel in FILES}
    if args.build:
        cache = args.into.resolve() / '.npm-cache'
        subprocess.run(['npm','ci','--ignore-scripts','--userconfig=/dev/null','--cache',str(cache),'--no-audit','--no-fund'],cwd=sdk,check=True)
        for command in ['gen','build']:
            subprocess.run(['npm','run',command,'--userconfig=/dev/null'],cwd=sdk,check=True)
    output_hashes = {str(p.relative_to(sdk)): digest(p) for p in sorted((sdk/'dist').rglob('*')) if p.is_file()}
    manifest = {'version':1,'project':'https://github.com/NVIDIA/OpenShell','source_commit':COMMIT,
        'upstream_version':'0.1.2','package_name':metadata['name'],'package_version':'0.0.0',
        'archive_sha256':ARCHIVE_SHA256,'source_sha256':source_hashes,'built':bool(output_hashes), 'output_sha256':output_hashes}
    (sdk/'prime-sdk-build.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'sdk_root':str(sdk.resolve()),'source_commit':COMMIT,'package_version':'0.0.0','built':bool(output_hashes),'output_files':len(output_hashes)}))

if __name__ == '__main__':
    main()
