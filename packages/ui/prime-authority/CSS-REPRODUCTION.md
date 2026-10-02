# Owner CSS filename reproduction repair

Base: `d424300de06c470c6fd5f36258d5d6d469e9ac0b`.

**RAN · retained raw reproduction FAIL:** H's handoff
`build-handoff-d424300.json` has SHA256
`760da123dcb84b270aa2e9b190a921afc4ec802b2d9bd1817906a9b92bf66b3f`.
Its 90 source records and pinned build records match. Of 52 output artifacts,
51 are byte-identical; only the 225,030-byte owner client differs:

- Committed: `4335a321a639a7b32e76fe0bca61cfdc0da8b5932cdd7de1725985d51a97710d`.
- Fresh: `b1727eb6fb9f2983f4d64d4ad5df58af0509cef66a5e82ef76779c8e58f35d66`.

The two CSS module prefixes account for all differing bytes. The source map and
region comments are identical. An in-memory prefix comparison diagnosed the
cause; it did not make raw reproduction pass. The retained committed artifact,
original failed comparison and H's handoff remain untouched.

**SOURCE-ONLY · recipe repair:** the generated owner configuration uses the
existing pinned LightningCSS 1.32.0 `projectRoot` option. Its value is the physical
DSH overlay root, so the CSS hash filename becomes the stable owned relative path
under `packages/client/aukora-prime-authority/`. The patch covers only
`OwnerSurface.module.css` and `PrimeProviderEditor.module.css`.

The original preset resolves physical virtual IDs. The wrapper retains those IDs,
watch files, sorted class map, style injection and the other plugins, and delegates
other CSS loads unchanged. It adds no generated-output substitution. Existing
receipt checks bind the exact generated configuration and both changed source
scripts. The preset excerpt's MIT notice remains in `licenses/DSH-MIT-LICENSE`.

**RAN · focused compiler regression PASS:** the command is:

```sh
node packages/ui/prime-authority/checks/css-reproduction.mjs --dsh <existing-pinned-dsh>
```

This check compares real pinned CSS compiler output and the generated hook across
two disposable physical seats. Both generated hook strings, CSS payloads and
complete class maps are byte-identical. The unadapted upstream loader reproduces
the original physical-path variation. Physical resolution/watch, other preset
hooks, host configuration and unselected-load delegation remain unchanged.

The first check attempt failed because its temporary seat used macOS's `/var`
alias while native module loading used the physical `/private/var` path. The
fixture now uses `realpath` for its physical root, as the build recipe already
does. No source recipe change or prefix substitution followed that check failure.
This check does not rebuild the complete owner plugin or establish served or
runtime behavior.

**UNPERFORMED:** the patched owner-only rebuild and full raw bundle reproduction,
pending parent allocation of the single necessary build. Frozen faces, retained
outputs, composition, activation, browser interaction, credentials and inference
are outside this source patch.
