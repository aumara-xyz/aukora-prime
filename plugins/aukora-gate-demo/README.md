# aukora-gate-demo: a fixture, not a feature

`hello-governed.mjs` is a one-file test fixture for the composition gate's **governed-grant lane**: an entry admitted
by a one-use grant signed by the installation's governor key, bound to the entry's bytes
(`plugins/aukora-composition-gate/GOVERNED.md`). The materializer copies it into a release so that lane can be
exercised (`scripts/materialize-aukora-release.py`, `scripts/launch-dsh.py`). It is not mounted as a plugin, grants
nothing by itself and has no user-facing behaviour.
