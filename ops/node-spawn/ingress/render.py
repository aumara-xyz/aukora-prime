#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Render each named node only to its own three loopback upstreams."""

import argparse
import json
import os
import re
import stat
import tempfile
from pathlib import Path

DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
NODE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*")
NODE_FIELDS = {"name", "app_host", "owner_host", "harness_port", "owner_port", "claim_port"}
NODE_BEGIN = "# BEGIN AUKORA NODE\n"
NODE_END = "# END AUKORA NODE\n"
MAX_NODES_FILE = 64 * 1024


def hostname(value):
    labels = value.split(".") if isinstance(value, str) else []
    if (not isinstance(value, str) or value != value.lower() or value == "localhost" or "*" in value
            or len(value) > 253 or len(labels) < 2
            or re.search(r"[a-z]", labels[-1]) is None
            or any(DNS_LABEL.fullmatch(label) is None for label in labels)):
        raise argparse.ArgumentTypeError("require a lowercase DNS hostname without wildcard, port or path")
    return value


def port(value):
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise argparse.ArgumentTypeError("port must be in 1024..65535") from error
    if isinstance(value, bool) or not 1024 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("port must be in 1024..65535")
    return parsed


def validate_nodes(nodes):
    if not isinstance(nodes, list) or not nodes:
        raise ValueError("INGRESS_NODES_INVALID")
    validated = []
    names = set()
    hosts = set()
    ports = set()
    for node in nodes:
        if not isinstance(node, dict) or set(node) != NODE_FIELDS:
            raise ValueError("INGRESS_NODE_FIELDS_INVALID")
        name = node["name"]
        if (not isinstance(name, str) or len(name) > 63
                or NODE_NAME.fullmatch(name) is None or name in names):
            raise ValueError("INGRESS_NODE_NAME_INVALID")
        if any(type(node[field]) is not int for field in ("harness_port", "owner_port", "claim_port")):
            raise ValueError("INGRESS_NODE_VALUE_INVALID")
        try:
            app_host = hostname(node["app_host"])
            owner_host = hostname(node["owner_host"])
            harness_port = port(node["harness_port"])
            owner_port = port(node["owner_port"])
            claim_port = port(node["claim_port"])
        except argparse.ArgumentTypeError as error:
            raise ValueError("INGRESS_NODE_VALUE_INVALID") from error
        node_hosts = {app_host, owner_host}
        node_ports = {harness_port, owner_port, claim_port}
        if len(node_hosts) != 2 or hosts & node_hosts:
            raise ValueError("INGRESS_HOSTS_MUST_DIFFER")
        if len(node_ports) != 3 or ports & node_ports:
            raise ValueError("INGRESS_PORTS_MUST_DIFFER")
        names.add(name)
        hosts.update(node_hosts)
        ports.update(node_ports)
        validated.append({"name": name, "app_host": app_host, "owner_host": owner_host,
                          "harness_port": harness_port, "owner_port": owner_port,
                          "claim_port": claim_port})
    return validated


def load_nodes(path, required_uid=0):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError("INGRESS_NODES_FILE_INVALID") from error
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != required_uid
                or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > MAX_NODES_FILE):
            raise ValueError("INGRESS_NODES_FILE_INVALID")
        try:
            with os.fdopen(descriptor, "r", encoding="utf-8") as source:
                descriptor = -1
                payload = source.read(MAX_NODES_FILE + 1)
        except UnicodeError as error:
            raise ValueError("INGRESS_NODES_JSON_INVALID") from error
        if len(payload.encode("utf-8")) > MAX_NODES_FILE:
            raise ValueError("INGRESS_NODES_FILE_INVALID")
        try:
            return validate_nodes(json.loads(payload))
        except json.JSONDecodeError as error:
            raise ValueError("INGRESS_NODES_JSON_INVALID") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _render_nodes(template, nodes, hsts_include_subdomains=False):
    if template.count(NODE_BEGIN) != 1 or template.count(NODE_END) != 1:
        raise ValueError("INGRESS_TEMPLATE_INCOMPLETE")
    prefix, remainder = template.split(NODE_BEGIN)
    node_template, suffix = remainder.split(NODE_END)
    blocks = []
    for node in validate_nodes(nodes):
        block = node_template
        for marker, value in {
            "__NODE_NAME__": node["name"],
            "__APP_HOST__": node["app_host"],
            "__OWNER_HOST__": node["owner_host"],
            "__HARNESS_PORT__": str(node["harness_port"]),
            "__OWNER_PORT__": str(node["owner_port"]),
            "__CLAIM_PORT__": str(node["claim_port"]),
        }.items():
            block = block.replace(marker, value)
        blocks.append(block)
    result = (prefix + "".join(blocks) + suffix).replace(
        "__HSTS_INCLUDE_SUBDOMAINS__", "; includeSubDomains" if hsts_include_subdomains else "")
    if re.search(r"__[A-Z_]+__", result):
        raise ValueError("INGRESS_TEMPLATE_INCOMPLETE")
    return result


def render(template, app_host, owner_host, harness_port, owner_port, claim_port,
           hsts_include_subdomains=False):
    return _render_nodes(template, [{"name": "single", "app_host": app_host,
                                     "owner_host": owner_host, "harness_port": harness_port,
                                     "owner_port": owner_port, "claim_port": claim_port}],
                         hsts_include_subdomains=hsts_include_subdomains)


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
    parser.add_argument("--app-host", type=hostname)
    parser.add_argument("--owner-host", type=hostname)
    parser.add_argument("--harness-port", type=port)
    parser.add_argument("--owner-port", type=port)
    parser.add_argument("--claim-port", type=port)
    parser.add_argument("--nodes", type=Path)
    parser.add_argument("--check", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--hsts-include-subdomains", action="store_true")
    arguments = parser.parse_args()
    single = (arguments.app_host, arguments.owner_host, arguments.harness_port,
              arguments.owner_port, arguments.claim_port)
    if arguments.nodes is None:
        if any(value is None for value in single) or arguments.check is not None:
            parser.error("single-node mode requires all five host and port flags")
        nodes = [{"name": "single", "app_host": arguments.app_host,
                  "owner_host": arguments.owner_host, "harness_port": arguments.harness_port,
                  "owner_port": arguments.owner_port, "claim_port": arguments.claim_port}]
    else:
        if any(value is not None for value in single):
            parser.error("--nodes cannot be combined with single-node flags")
        if arguments.check is not None and arguments.output is not None:
            parser.error("--check cannot be combined with --output")
        nodes = load_nodes(arguments.nodes)
    template = Path(__file__).with_name("Caddyfile.template").read_text(encoding="utf-8")
    payload = _render_nodes(template, nodes, hsts_include_subdomains=arguments.hsts_include_subdomains)
    if arguments.check is not None:
        try:
            actual = arguments.check.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise ValueError("INGRESS_CHECK_FILE_INVALID") from error
        if actual != payload:
            raise ValueError("INGRESS_RENDERED_MISMATCH")
        print(f"PASS ingress: rendered file matches {len(nodes)} nodes")
    elif arguments.output is None:
        print(payload, end="")
    else:
        write_output(arguments.output, payload)


if __name__ == "__main__":
    main()
