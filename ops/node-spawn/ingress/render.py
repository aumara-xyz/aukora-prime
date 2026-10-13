#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Render the two-host Caddy ingress from operator-supplied names and ports."""

import argparse
import os
import re
import tempfile
from pathlib import Path

DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def hostname(value):
    labels = value.split(".")
    if (value != value.lower() or value == "localhost" or "*" in value
            or len(value) > 253 or len(labels) < 2
            or any(DNS_LABEL.fullmatch(label) is None for label in labels)):
        raise argparse.ArgumentTypeError("require a lowercase DNS hostname without wildcard, port or path")
    return value


def port(value):
    parsed = int(value)
    if not 1024 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("port must be in 1024..65535")
    return parsed


def render(template, app_host, owner_host, harness_port, owner_port):
    if app_host == owner_host:
        raise ValueError("INGRESS_HOSTS_MUST_DIFFER")
    if harness_port == owner_port:
        raise ValueError("INGRESS_PORTS_MUST_DIFFER")
    result = template
    for marker, value in {
        "__APP_HOST__": app_host,
        "__OWNER_HOST__": owner_host,
        "__HARNESS_PORT__": str(harness_port),
        "__OWNER_PORT__": str(owner_port),
    }.items():
        result = result.replace(marker, value)
    if re.search(r"__[A-Z_]+__", result):
        raise ValueError("INGRESS_TEMPLATE_INCOMPLETE")
    return result


def write_output(path, payload):
    path = Path(path)
    if path.exists() and path.is_symlink():
        raise ValueError("INGRESS_OUTPUT_SYMLINK_REFUSED")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-host", type=hostname, required=True)
    parser.add_argument("--owner-host", type=hostname, required=True)
    parser.add_argument("--harness-port", type=port, required=True)
    parser.add_argument("--owner-port", type=port, required=True)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    template = Path(__file__).with_name("Caddyfile.template").read_text(encoding="utf-8")
    payload = render(template, arguments.app_host, arguments.owner_host,
                     arguments.harness_port, arguments.owner_port)
    if arguments.output is None:
        print(payload, end="")
    else:
        write_output(arguments.output, payload)


if __name__ == "__main__":
    main()
