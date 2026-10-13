# Operations

This directory contains procedures for relays, nodes, the pilot and systemd units.
These commands can describe or change installed systems when an operator runs them.
Each subdirectory documents its own prerequisites and refusal conditions.
Source presence does not mean an operation ran on a live node.
Run the subdirectory check without contacting a remote machine unless authorized.

For a fresh restricted node reached from a normal browser, use the [browser-node installer runbook](node-spawn/browser/README.md); its public application, owner and one-use claim routes are configured through the separate [HTTPS ingress runbook](node-spawn/ingress/README.md). Those procedures have their own prerequisites and acceptance limits and do not qualify the general member-node installer.
