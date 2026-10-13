# Five minutes with the local example

This starts a release you can inspect in a browser, then exercises a refusal, an owner approval and verification. The first harness build can take several minutes; the five-minute tour starts when the address appears.

Have Node **24.11.1** with its development headers, Python 3.9 or later, git, `cc` and the pinned package manager (`pnpm@11.7.0`) in `PATH`. A first build needs access to the pinned archive and package registry. The commands install no global packages and need no root privileges.

## 1. Clone and start

```sh
git clone --branch main https://github.com/aumara-xyz/aukora-prime.git
cd aukora-prime
./prime up --example
```

Git creates `aukora-prime`. The start command prints build and verification rows, followed by these lines. `<port>` and `<state>` are values from your run:

```text
ADDRESS | http://127.0.0.1:<port>
SIGN-IN FILE | <state>/support/state/launch-url.json
STOP | ./prime down --example --dir <state>
REAL | boundary gate, action gate, approval path, signed ledger, release floor, screens and apps
STAND-IN | throwaway owner key on this same user; no model key (assistant cannot answer); no containment; no relay
PASS | example up
```

It stays up after the command returns. The default state directory is `$XDG_STATE_HOME/aukora-prime-example`, or `~/.local/state/aukora-prime-example` when that variable is unset. It has mode `0700`; state and the build cache stay there. Running the command again resumes that state. A state directory belongs to its original checkout and `HEAD`; after changing `HEAD`, choose a new `--dir`.

## 2. Open the screens

Open the printed loopback address. Open the file named by `SIGN-IN FILE` privately in an editor and use its `url` value to sign in in your browser. The command never prints that link or its token. Do not share the file or paste its contents into a terminal or report.

Look in the apps panel and open Auma Lingwa. Open the Aura Coherence page to inspect its source status and ledger picture. The screens and stock apps are served by this release. There is no model key, so asking the assistant a question cannot produce a model answer.

## 3. Watch an action be refused

```sh
./prime example refuse
```

Expected output includes:

```text
REFUSAL | <tool result containing authority:tool-not-approved>
REFUSAL ENTRY | <the corresponding action ledger entry>
PASS | example refuse
```

This calls a fixed demonstration tool through the running action gate. Its body must remain unrun. The command shows the refusal and its recorded entry.

## 4. Approve one exact change

```sh
./prime example approve
```

Expected output includes:

```text
PENDING CARD | <the gate's pending card facts>
PASS | example owner command and exact theme bytes
SIGNED RECEIPT | <receipt and receipt_sig>
PASS | example approve
```

The proposal changes only `plugins/auma-theme/theme.json` under this example's target directory. Read the gate's target, old and new hashes, change and scope. The command uses the real owner review and decision path with the example's throwaway key, then shows the signed receipt. This tour checks the applied target bytes; it does not claim you observed a browser theme change.

## 5. Check the evidence, then stop

```sh
./prime example verify
```

Expected output:

```text
PASS | example receipt names exact theme change
PASS | example receipt signature
PASS | example signed ledger
PASS | example receipt in signed ledger
PASS | example release floor
PASS | example action ledger chain
LIMIT | local keys and heads do not prove owner custody containment or an external ledger anchor
PASS | example verify
```

The command uses the repository's receipt and ledger verifier and prints `PASS` or `FAIL` for each check. Then stop the example:

```sh
./prime down --example
```

Expect `PASS | example down`. Repeating it prints `PASS | example down (already stopped)`. State and receipts remain for the next start; shutdown stops the processes owned by this example. The gold change is approved once per state directory; a later approval attempt reports `example-theme-already-approved`.

## Other inputs

You can select a private state directory, a hash-checked archive, a verified built harness and a loopback port:

```sh
./prime up --example --dir "$HOME/.local/state/aukora-prime-tour" --archive /path/to/dsh-source.tar.gz --built /path/to/built/dsh --port 17791
./prime example refuse --dir "$HOME/.local/state/aukora-prime-tour"
./prime example approve --dir "$HOME/.local/state/aukora-prime-tour"
./prime example verify --dir "$HOME/.local/state/aukora-prime-tour"
./prime down --example --dir "$HOME/.local/state/aukora-prime-tour"
```

Expect the same command `PASS` lines. `--built` also prints `SKIP | harness build (--built; fresh build NOT PROVED)`. The state directory must be private, owned by you, outside the checkout and not a symlink. A dirty checkout refuses with `example-dirty-tree`. Development use can explicitly add `--allow-dirty`; its warning says the private snapshot is **NOT what is committed**.

## What this is not

The real boundary gate, action gate, approval path, signed ledger and release floor operate here, with the release's screens and apps. The owner is a throwaway key on the same operating-system user. There is no enrolled human owner, protected key custody, containment, model key or relay. A signature verifies exact recorded bytes under the supplied local key; it does not prove a unique person, informed approval, an external event or that this is the latest complete ledger. This is a local example, not qualification of a production installation or the live pilot.
