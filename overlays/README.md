# Composition overlays

This directory contains declarative patches applied to harness composition.
The release materializer and plugin checks consume these files.
An overlay changes assembly input; it is not proof that a release was installed.
Keep paths release-relative and review changes with their consuming check.
Run `node scripts/check-next-composition.mjs` after editing an overlay.
