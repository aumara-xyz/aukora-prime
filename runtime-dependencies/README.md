# Runtime dependency closures

This directory holds lockfiles and provenance for dependencies needed at runtime.
`pg/` records the PostgreSQL driver closure used by staged acceptance work.
The materializer script installs from these locked inputs into a named destination.
Do not treat a lockfile as evidence that a service or database ran.
Check `licenses/inventory.json` and the focused staging checks after updates.
