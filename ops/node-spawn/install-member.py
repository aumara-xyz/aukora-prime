#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Bind one node name to its admitted public member without replacing existing state.
import json
import os
import re
import stat
import sys

ROOT = '/'
UID = 0
FIELDS = {'version', 'node', 'network_root_pubkey', 'member_pubkey', 'redemption_id'}


def refuse(code):
    raise ValueError(code)


def checked(value):
    if (type(value) is not dict or set(value) != FIELDS
            or type(value['version']) is not int or value['version'] != 1
            or type(value['node']) is not str or len(value['node']) > 63
            or not re.fullmatch(r'[a-z][a-z0-9]*(-[a-z0-9]+)*', value['node'])
            or any(type(value[key]) is not str or not re.fullmatch(r'[0-9a-f]{64}', value[key])
                   for key in ('network_root_pubkey', 'member_pubkey', 'redemption_id'))):
        refuse('MEMBER_CONFIG_INVALID')
    return value


def protected(fd, directory):
    info = os.fstat(fd)
    if (info.st_uid != UID or info.st_mode & 0o022
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or (not directory and (info.st_nlink != 1 or info.st_size > 4096))):
        refuse('MEMBER_CONFIG_UNPROTECTED')


def install(value):
    value = checked(value)
    if os.geteuid() != UID:
        refuse('MEMBER_CONFIG_ROOT_REQUIRED')
    descriptors = []
    try:
        directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(directory)
        protected(directory, True)
        for name in ('etc', 'aukora-node'):
            created = False
            if name == 'aukora-node':
                try:
                    os.mkdir(name, 0o755, dir_fd=directory)
                    created = True
                except FileExistsError:
                    pass
            directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            descriptors.append(directory)
            if created:
                os.fchmod(directory, 0o755)
            protected(directory, True)
        content = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
        try:
            file = os.open('member.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                           0o644, dir_fd=directory)
        except FileExistsError:
            file = os.open('member.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            descriptors.append(file)
            protected(file, False)
            try:
                same = checked(json.loads(os.read(file, 4097))) == value
            except (ValueError, UnicodeError):
                same = False
            if not same:
                refuse('MEMBER_CONFIG_CONFLICT')
            return
        descriptors.append(file)
        os.fchmod(file, 0o644)
        protected(file, False)
        with os.fdopen(os.dup(file), 'wb') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.fsync(directory)
    except OSError:
        refuse('MEMBER_CONFIG_IO')
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2 or len(sys.argv[1]) > 4096:
            refuse('MEMBER_CONFIG_INVALID')
        install(json.loads(sys.argv[1]))
    except (ValueError, UnicodeError) as error:
        code = str(error) if str(error).startswith('MEMBER_CONFIG_') else 'MEMBER_CONFIG_INVALID'
        print('REFUSED ' + code, file=sys.stderr)
        sys.exit(1)
