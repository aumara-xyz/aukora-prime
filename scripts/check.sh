#!/bin/sh
# The README reviewer packet. Each independent check gets 55 seconds, including
# its subprocesses. Logs and timings are collected separately, printed in order.
set -eu
# Reject preloads and external fixture selectors before starting any Node child.
if [ "${NODE_OPTIONS+x}" = x ]; then
    printf '%s\n' 'FAIL: review:node-options-forbidden' >&2
    exit 1
fi
if [ "${AUKORA_TEST_KIRA_SOURCE+x}" = x ] || [ "${AUKORA_TEST_AURA_SOURCE+x}" = x ]; then
    printf '%s\n' 'FAIL: review:source-override-forbidden' >&2
    exit 1
fi
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

for tool in perl python3 node ssh-keygen; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'FAIL: required command not found: %s\n' "$tool" >&2
        exit 1
    }
done
node -e 'const v=process.versions.node.split(".").map(Number); process.exit(v[0]>24 || (v[0]===24 && (v[1]>11 || (v[1]===11 && v[2]>=1))) ? 0 : 1)' || {
    printf 'FAIL: Node.js 24.11.1 or newer is required; found %s\n' "$(node -v)" >&2
    exit 1
}

# Inline so the TODO list is visible, not swallowed by the parallel runner's last-line summary.
python3 - <<'PY_FACE_COLOURS'
from pathlib import Path
import re
root = Path("plugins/aukora-face")
tokens = "layout/src/client/spatial-tokens.css"
legacy = {
    "aumlok/src/client/Aumlok.module.css",
    "apps/src/client/StockApps.module.css",
    "documents/src/client/Documents.module.css",
    "layout/src/client/Approvals.module.css",
    "layout/src/client/FirstRun.module.css",
    "layout/src/client/Health.module.css",
    "layout/src/client/Why.module.css",
    "settings/src/client/AuraCoherenceSurface.module.css",
    "settings/src/client/GeneralSection.module.css",
    "settings/src/client/SettingsDocumentAction.module.css",
    "settings/src/client/SettingsRoot.module.css",
    "sidebar/src/client/SidebarRoot.module.css",
    "threads/src/client/ThreadHeaderActions.module.css",
    "threads/src/client/ThreadListHeaderActions.module.css",
    "threads/src/client/WorkspaceBrowser.module.css",
    "threads/src/client/WorkspacePicker.module.css",
    "threads/src/client/rows/Rows.module.css",
}
print("TODO face colour migration (paths under plugins/aukora-face): " + ", ".join(sorted(legacy)))
raw = re.compile(r"(?:#[0-9a-f]{8}|#[0-9a-f]{6}|#[0-9a-f]{4}|#[0-9a-f]{3})(?![\w-])|\brgba?\s*\(", re.I)
failures = []
for path in sorted(root.glob("*/src/**/*")):
    if path.suffix.lower() not in {".css", ".scss", ".sass", ".less"} or "vendor" in path.parts:
        continue
    name = path.relative_to(root).as_posix()
    if name in legacy:
        continue
    source = re.sub(r"/\*.*?\*/", "", path.read_text(encoding="utf-8"), flags=re.S)
    source = re.sub(r'''url\([^)]*\)|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*' ''', "", source, flags=re.I | re.X)
    for declaration in re.finditer(r"(?:^|[;{])\s*([\w-]+)\s*:\s*([^;{}]+)", source):
        property_name, value = declaration.groups()
        if name == tokens and property_name.startswith("--"):
            continue
        if raw.search(value):
            failures.append(str(path))
            break
if failures:
    raise SystemExit("FAIL face raw colours: " + ", ".join(failures))
print("PASS face stylesheet colours")
PY_FACE_COLOURS

started=$(perl -MTime::HiRes=time -e 'print time')
work=$(mktemp -d /tmp/ac.XXXXXX)
mkdir -m 700 "$work/tmp"
# Short socket paths on macOS; no bytecode files racing the vendor pin check.
TMPDIR="$work/tmp"
PYTHONDONTWRITEBYTECODE=1
export TMPDIR PYTHONDONTWRITEBYTECODE
pids=
active=0
index=0
count=0
passed=0
failed=0
skipped=0
platform_skipped=0
unperformed=0
cleanup() {
    trap '' HUP INT TERM
    for pid in $pids; do kill -TERM "$pid" 2>/dev/null || :; done
    for pid in $pids; do wait "$pid" 2>/dev/null || :; done
    rm -rf "$work/tmp"
    if [ "$failed" -eq 0 ]; then rm -rf "$work"; fi
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

collect_checks() {
    for pid in $pids; do
        index=$((index + 1))
        child_exit=0
        wait "$pid" || child_exit=$?
        disposition=
        if [ -f "$work/$index.status" ]; then
            IFS= read -r disposition < "$work/$index.status" || disposition=
        fi
        expected_exit=
        case "$disposition" in
            PASS) expected_exit=0 ;;
            FAIL) expected_exit=1 ;;
            UNPERFORMED) expected_exit=2 ;;
            SKIP) expected_exit=3 ;;
        esac
        if [ ! -f "$work/$index.row" ] || [ -z "$expected_exit" ] || [ "$child_exit" -ne "$expected_exit" ]; then
            failed=$((failed + 1))
            printf 'FAIL      ?s | check %s | missing or inconsistent runner result (exit %s)\n' "$index" "$child_exit"
        else
            case "$disposition" in
                PASS) passed=$((passed + 1)) ;;
                FAIL) failed=$((failed + 1)) ;;
                SKIP) skipped=$((skipped + 1)) ;;
                UNPERFORMED) unperformed=$((unperformed + 1)) ;;
            esac
            cat "$work/$index.row"
        fi
    done
    pids=
    active=0
}

# Formats describe fixed source commands; report text never selects executable argv.
run_check() {
    count=$((count + 1))
    perl -MTime::HiRes=time -e '
        use strict;
        use warnings;
        use Errno qw(EINTR);
        my ($prefix, $command, $run, $format) = @ARGV;
        $format //= "plain";
        die "report format" unless $format =~ /\A(?:plain|tap|unittest|injection)\z/;
        # Only this source-owned court declares exit 2 as incomplete acceptance.
        # An arbitrary failing command must not acquire the same exemption.
        if ($format eq "injection") {
            die "injection command" unless $command eq "node tests/kira-injection.test.mjs --mutate" && $run eq $command;
        }
        my $start = time;
        open my $log, ">", "$prefix.log" or die "log: $!";
        my $pid = fork();
        defined $pid or die "fork: $!";
        if ($pid == 0) {
            $SIG{$_} = "DEFAULT" for qw(HUP INT TERM ALRM);
            setpgrp(0, 0) or die "setpgrp: $!";
            open STDOUT, ">&", $log or die "stdout: $!";
            open STDERR, ">&", $log or die "stderr: $!";
            delete $ENV{$_} for grep { /_MUTANT\z/ } keys %ENV;
            delete @ENV{qw(AUKORA_RECORDS_MODULE AUKORA_PRIME_CHECK_GIT)};
            delete @ENV{qw(AUKORA_AURA_CHECK_GIT AUKORA_AURA_CITATION_BASE NODE_TEST_CONTEXT)};
            delete @ENV{qw(NODE_OPTIONS AUKORA_TEST_KIRA_SOURCE AUKORA_TEST_AURA_SOURCE)};
            $ENV{GIT_NO_LAZY_FETCH} = "1";
            exec "sh", "-c", $run;
            die "exec: $!";
        }
        close $log;
        my $stop = sub {
            kill "KILL", -$pid;
            kill "KILL", $pid; # Also covers a signal before setpgrp in the child.
        };
        my $reason = "";
        $SIG{ALRM} = sub { $reason = "timeout after 55s"; $stop->() };
        for my $signal (qw(HUP INT TERM)) {
            $SIG{$signal} = sub { $reason = "interrupted by $signal"; $stop->() };
        }
        alarm 55;
        my $waited;
        do { $waited = waitpid($pid, 0) } while $waited == -1 && $! == EINTR;
        my $status = $?;
        alarm 0;
        kill "KILL", -$pid; # Stop any lingering signer or verifier descendants.
        die "waitpid: $!" if $waited == -1;
        my $ok = $status == 0 && $reason eq "";
        if (!$ok && $reason eq "") {
            $reason = ($status & 127) ? "signal " . ($status & 127) : "exit " . ($status >> 8);
        }
        open my $output, "<", "$prefix.log" or die "read log: $!";
        my $last = "(no output)";
        my (@tail, $private, %totals, %seen);
        my $reported_failure = 0;
        my ($unit_tests, $unit_skipped, $unit_expected, $unit_unexpected, $unit_ok) = (undef, 0, 0, 0, 0);
        my ($unit_runs, $unit_summaries, $unit_invalid, $unit_failed) = (0, 0, 0, 0);
        my ($court_reports, $court_invalid, $court_failure) = (0, 0, 0);
        my ($court_pass, $court_arms, $court_fail, $court_unperformed, $court_dsh);
        while (<$output>) {
            chomp;
            if ($format eq "injection") {
                $court_failure = 1 if /\A[ \t]*FAIL\s+[^\n]+:/;
                if (/\A[ \t]*[0-9]+\/[0-9]+ arms passed\b/) {
                    $court_reports++;
                    if (/\A  ([0-9]{1,6})\/([0-9]{1,6}) arms passed, ([0-9]{1,6}) failed; ([0-9]{1,6}) unperformed checks; DSH source dispatch (RAN|UNPERFORMED); installed profile UNPERFORMED\.\z/) {
                        ($court_pass, $court_arms, $court_fail, $court_unperformed, $court_dsh) = (0 + $1, 0 + $2, 0 + $3, 0 + $4, $5);
                        $court_failure = 1 if $court_fail > 0;
                    } else { $court_invalid = 1 }
                }
            }
            if (/\A# (tests|pass|fail|cancelled|skipped|todo) ([0-9]+)\s*\z/) {
                my ($name, $number) = ($1, 0 + $2);
                $totals{$name} = $number; $seen{$name}++;
                $reported_failure = 1 if ($name eq "fail" || $name eq "cancelled") && $number > 0;
            }
            if (/\ARan ([0-9]+) tests? in /) {
                $unit_tests = 0 + $1; $unit_runs++;
            }
            $unit_failed = 1 if /\AFAILED\b/;
            if (/\AOK\b/) {
                $unit_summaries++;
                if (/\AOK(?: \(([^)]*)\))?\s*\z/) {
                    $unit_ok = 1;
                    my $details = $1 // "";
                    my %attributes;
                    if ($details ne "") {
                        for my $attribute (split /, /, $details, -1) {
                            if ($attribute =~ /\A(skipped|expected failures|unexpected successes)=([0-9]+)\z/) {
                                my ($name, $number) = ($1, 0 + $2);
                                $unit_invalid = 1 if exists $attributes{$name};
                                $attributes{$name} = $number;
                                $unit_failed = 1 if $name eq "unexpected successes" && $number > 0;
                            } else {
                                $unit_invalid = 1;
                                $unit_failed = 1 if $attribute =~ /\A(?:failures|errors)=([0-9]+)\z/ && $1 > 0;
                            }
                        }
                    }
                    $unit_skipped = $attributes{"skipped"} // 0;
                    $unit_expected = $attributes{"expected failures"} // 0;
                    $unit_unexpected = $attributes{"unexpected successes"} // 0;
                    $unit_failed = 1 if $unit_unexpected > 0;
                } else { $unit_invalid = 1 }
            }
            my $end_private = /-----END .*PRIVATE KEY-----/;
            $private ||= /-----BEGIN .*PRIVATE KEY-----/;
            $_ = "[private key omitted]" if $private;
            $private = 0 if $end_private;
            s{(https?://)[^/\s]+\@}{${1}[redacted]\@}giu;
            s{\b(Bearer\s+)\S+}{${1}[redacted]}giu;
            $_ = "[sensitive or environment field omitted]" if
                /(?:password|secret|token|authorization|cookie|api[_-]?key|private[_-]?key)[a-z0-9_-]*\s*["\x27]?\s*[:=]/iu ||
                /^\s*["\x27]?[A-Z][A-Z0-9_]*["\x27]?\s*[:=]/u;
            $_ = substr($_, 0, 512);
            $last = $_ if /\S/;
            if (/\S/) { push @tail, $_; shift @tail if @tail > 32 }
        }
        close $output;
        my $disposition = $ok ? "PASS" : "FAIL";
        my $reported = "";
        # Process failures take precedence over an incomplete or contradictory report.
        # Native direct Node tests are recognized by their footer even in plain rows.
        if ($format eq "injection") {
            $reported = " | injection arms=" . ($court_arms // "?") . " passed=" . ($court_pass // "?")
                . " failed=" . ($court_fail // "?") . " unperformed=" . ($court_unperformed // "?")
                . " DSH=" . ($court_dsh // "?") . " installed=UNPERFORMED";
            # Exit 1, signals and watchdog failures remain failures. Even a
            # wrong exit 0/2 cannot conceal a reported failed arm or open join.
            if ($ok || ($status == (2 << 8) && $reason eq "exit 2")) {
                if ($court_failure || $reported_failure) {
                    $disposition = "FAIL"; $reason = "reported failing injection arms";
                } elsif ($court_reports != 1 || $court_invalid || !defined($court_arms)
                    || $court_arms == 0 || $court_pass != $court_arms || $court_fail != 0
                    || $court_unperformed == 0 || ($court_dsh eq "UNPERFORMED" && $court_unperformed < 2)) {
                    $disposition = "FAIL"; $reason = "missing or inconsistent injection court totals";
                } else {
                    $disposition = "UNPERFORMED"; $reason = "reported unperformed injection checks";
                }
            }
        } elsif (%totals || $format eq "tap") {
            $reported = " | TAP " . join(" ", map { "$_=" . (exists $totals{$_} ? $totals{$_} : "?") } qw(tests pass fail cancelled skipped todo));
            if ($ok && $reported_failure) {
                $disposition = "FAIL"; $reason = "reported failing or cancelled tests";
            } elsif ($ok) {
                my $complete = keys(%totals) == 6 && !grep { ($seen{$_} // 0) != 1 } qw(tests pass fail cancelled skipped todo);
                if (!$complete) {
                    $disposition = "UNPERFORMED"; $reason = "missing complete TAP totals";
                } elsif ($totals{tests} != $totals{pass} + $totals{fail} + $totals{cancelled} + $totals{skipped} + $totals{todo}) {
                    $disposition = "FAIL"; $reason = "inconsistent TAP totals";
                } elsif ($totals{tests} == 0) {
                    $disposition = "UNPERFORMED"; $reason = "zero reported tests";
                } elsif ($totals{skipped} == $totals{tests}) {
                    $disposition = "SKIP"; $reason = "all reported tests skipped";
                } elsif ($totals{skipped} > 0 || $totals{todo} > 0) {
                    $disposition = "UNPERFORMED"; $reason = "reported skipped or todo tests";
                }
            }
        } elsif ($format eq "unittest") {
            $reported = " | unittest tests=" . ($unit_tests // "?") . " skipped=$unit_skipped expected_failures=$unit_expected unexpected_successes=$unit_unexpected";
            if ($ok) {
                if ($unit_failed) {
                    $disposition = "FAIL"; $reason = "reported failed unittest or unexpected success";
                } elsif ($unit_invalid || $unit_runs > 1 || $unit_summaries > 1) {
                    $disposition = "UNPERFORMED"; $reason = "invalid or duplicate unittest totals";
                } elsif (!defined($unit_tests) || !$unit_ok) {
                    $disposition = "UNPERFORMED"; $reason = "missing successful unittest totals";
                } elsif ($unit_skipped + $unit_expected + $unit_unexpected > $unit_tests) {
                    $disposition = "FAIL"; $reason = "inconsistent unittest totals";
                } elsif ($unit_tests == 0) {
                    $disposition = "UNPERFORMED"; $reason = "zero reported tests";
                } elsif ($unit_skipped == $unit_tests) {
                    $disposition = "SKIP"; $reason = "all reported tests skipped";
                } elsif ($unit_skipped > 0 || $unit_expected > 0) {
                    $disposition = "UNPERFORMED"; $reason = "reported skipped or expected-failure tests";
                }
            }
        }
        open my $row, ">", "$prefix.row" or die "row: $!";
        printf {$row} "%s %6.2fs | %s%s%s | %s\n",
            $disposition, time - $start, $command,
            $reason eq "" ? "" : " [$reason]", $reported, $last;
        if ($disposition eq "FAIL") {
            print {$row} "  failed-check output (last 32 nonempty lines, up to 512 bytes each):\n";
            print {$row} "  | $_\n" for @tail;
        }
        close $row or die "close row: $!";
        open my $result, ">", "$prefix.status" or die "status: $!";
        print {$result} "$disposition\n";
        close $result or die "close status: $!";
        exit($disposition eq "PASS" ? 0 : $disposition eq "FAIL" ? 1 : $disposition eq "UNPERFORMED" ? 2 : 3);
    ' "$work/$count" "$1" "$2" "${3:-plain}" &
    pids="$pids $!"
    active=$((active + 1))
    # Bound fixture contention; each watchdog still starts only when its check launches.
    if [ "$active" -eq 4 ]; then collect_checks; fi
}
# The precard caller supplies a private interpreter dispatcher from the base.
# Standalone checks use their normal interpreters and make no confinement claim.
check_self_confined() { run_check "$1" "$1"; }
check() { run_check "$1" "$1"; }
check_injection() { run_check "$1" "$1" injection; }
check_tap() { run_check "$1" "$1" tap; }
check_unittest() { run_check "$1" "$1" unittest; }

# Unavailable Seatbelt checks are explicit skips, never counted as passes.
skip() {
    printf 'SKIP      -  | %s | %s\n' "$1" "$2"
    skipped=$((skipped + 1))
    platform_skipped=$((platform_skipped + 1))
}
os=$(uname -s)
check_darwin() {
    if [ "$os" = Darwin ]; then check_self_confined "$1"
    else skip "$1" "macOS only: needs Seatbelt (/usr/bin/sandbox-exec); on $os it proves nothing"; fi
}

check 'python3 vendor/append-only/verify.py --selftest'
check 'python3 scripts/phase0-check-pins.py'
check 'node plugins/aukora-kira/lib/wasm-cell/courts/harness/wasm-proposal-cell/run.mjs'
check 'node tests/kira-diamond-cold.test.mjs'
check_injection 'node tests/kira-injection.test.mjs --mutate'
check 'node tests/public-evidence.test.mjs'
check 'node tests/receipt-v3.test.mjs'
check 'node tests/aukora-aumlok-verify.test.mjs'
check 'node tests/aukora-dual-verifier.test.mjs'
check 'node tests/aukora-precard-check.test.mjs'
check 'node tests/aukora-approval-roundtrip.test.mjs'
check 'node tests/aukora-trusted-state.test.mjs'
check 'node tests/aukora-airlock.test.mjs'
check 'node tests/aukora-aumlok-cold-root.test.mjs'
check 'node tests/aukora-aumlok-fresh-bind.test.mjs'
check 'node tests/aukora-gate-require-grant.test.mjs'
check 'node tests/aukora-commit-bind-custody.test.mjs'
check 'node tests/aukora-commit-bind-proof-store.test.mjs'
check 'node tests/aukora-commit-ssh-sign.test.mjs'
check 'node tests/kira-control-admission.test.mjs'
check 'node tests/aukora-restore-scope.test.mjs'
check 'node tests/aukora-witness-four.test.mjs'
check 'node tests/kira-consolidate.test.mjs'
check 'node tests/kira-partial-failure.test.mjs --mutate'
check 'node tests/kira-consequential-gate.test.mjs'
check 'node tests/aukora-linux-read-fence.test.mjs'
check_tap 'node --test --test-reporter=tap tests/aukora-filetool-secret-denial.test.mjs'
check 'node tests/aukora-fence-r2.test.mjs'
check 'node tests/aukora-fence-r3.test.mjs'
check 'node tests/aukora-fence-r4.test.mjs'
check 'node tests/aukora-auma-theme.test.mjs'
check 'node tests/aukora-relay-auma.test.mjs'
check_tap 'node --test --test-reporter=tap tests/aukora-openshell-confinement.test.mjs'
check 'node tests/gate-ledger-anchor.test.mjs'
check_tap 'node --test --test-reporter=tap packages/boundary-gate/checks/selfcheck-bin.mjs'
check_tap 'node --test --test-reporter=tap tests/aukora-plugin-set-gate-signer.test.mjs'
check_tap 'node --test --test-reporter=tap tests/kira-gate-capture-host.test.mjs'
check_tap 'node --test --test-reporter=tap tests/aukora-plugin-set-trusted-verifier.test.mjs'
check 'node plugins/aukora-nostr/checks/records.mjs'
check 'node scripts/audit/security-review.mjs --source-prerequisite aura && node scripts/aura/checks/collector.mjs'
check 'node labs/pq-hybrid/checks/hybrid.mjs'
check_tap 'node --test --test-reporter=tap tests/aukora-owner-card-model-fence.test.mjs'
check_tap 'node --test --test-reporter=tap tests/aukora-owner-card-no-friction.test.mjs'
check_tap 'node --test --test-reporter=tap tests/aukora-owner-card-clarity.test.mjs'
check_tap 'node scripts/audit/security-review.mjs --source-prerequisite kira && node --test --test-reporter=tap tests/kira-aura-recall.test.mjs'
check_tap 'node --test --test-reporter=tap packages/boundary-gate/src/vendor/check-sequence-floor.mjs'
check_tap 'node --test --test-reporter=tap packages/boundary-gate/src/vendor/check-ordered-approval.mjs'
check 'node packages/boundary-gate/src/vendor/check-preview-policy.mjs'
check_unittest '/usr/bin/python3 -I -S packages/boundary-gate/host/install/check-bootstrap.py'
check_tap 'node --test --test-reporter=tap packages/owner-key/checks/owner-key.test.mjs'
check_tap 'node --test --test-reporter=tap tests/security-review-runner.test.mjs'
check_tap 'node --test --test-reporter=tap tests/aukora-plugin-set-floor-card.test.mjs'
check_tap 'node --test --test-reporter=tap tests/aukora-containment.test.mjs tests/aukora-auma-firewall.test.mjs'
check 'node packages/boundary-gate/src/vendor/check-trusted-verifier.mjs --mutations'
check 'node tests/aukora-kira-ask-recall.test.mjs'
check 'node tests/aukora-l3-memory-linux.test.mjs'
check 'python3 tests/openviking-load-mode.test.py'
check 'node tests/aukora-kira-support-root-identity.test.mjs'
check 'node tests/kira-recall-output-seam.test.mjs'
check 'node tests/kira-a1-ledger-availability.test.mjs'
check 'node tests/kira-a1-legacy-forget.test.mjs'
check 'node tests/kira-openviking-governed.test.mjs'
check 'node tests/kira-reserved-slots.test.mjs'
check 'node tests/kira-a4-window-tier.test.mjs'
check 'node tests/kira-a4-window-size.test.mjs'
check 'node tests/kira-continuity-metrics.test.mjs'
check 'node tests/kira-memory-live-path.test.mjs --plugin-only'
check 'node tests/kira-memory-law.test.mjs'
check 'node tests/kira-memory-reader.test.mjs'
check 'node tests/kira-openviking-recall.test.mjs --red'
check 'node tests/broker-grant.test.mjs'
check 'node tests/aukora-auma-live-fresh-install.test.mjs --mutate'
# r4c3: previously unwired tests, each RAN green standalone before wiring
# (dispositions posted on the relay; the still-red remainder stays out and named).
check 'node tests/aukora-action-gate-assembled-path.test.mjs'
check 'node tests/aukora-owner-authority.test.mjs'
check 'node tests/aukora-owner-authorization.test.mjs'
check 'node tests/aukora-owner-ingress.test.mjs'
check 'node tests/aukora-owner-protocol.test.mjs'
check 'node tests/aukora-witness-commits.test.mjs'
check 'node tests/check-shell-status.test.mjs'
check 'node tests/evidence-secret-gate.test.mjs'
check 'node tests/lane-door-message-id.test.mjs'
check 'node tests/relay-post-gate-return.test.mjs'
check 'node tests/kira-remember-append-return.test.mjs'
check 'node tests/kira-hash-domains.test.mjs'
check 'node tests/kira-injection-exit-status.test.mjs'
check 'node tests/kira-openviking-parts.test.mjs'
check 'node tests/kira-project-identity.test.mjs'
check 'node tests/kira-recall-state.test.mjs'
check 'node tests/kira-retrieval-failures.test.mjs'
check 'node tests/kira-search-ranking.test.mjs'
check 'node tests/desktop-first-run.test.mjs'
check 'node tests/desktop-preview-config-migration.test.mjs'
check 'node tests/desktop-restart-health.test.mjs'
check 'python3 tests/openviking-llama-pin.test.py'
check 'python3 plugins/aukora-face/apps/vendor/auma-live/voice/test_aurora_prompt.py'
check 'python3 vendor/aukora-membrane/minimal/tour.py'
check 'node vendor/authority/conformance.mjs'
check_darwin 'node scripts/aukora/box-confinement-check.mjs'
check_darwin 'node scripts/aukora/caged-worker.mjs'
check_darwin 'node scripts/aukora/caged-broker-effect.mjs'

collect_checks
perl -MTime::HiRes=time -e '
    printf "TOTAL %.2fs | %d/%d passed | %d failed | %d skipped (%d platform) | %d unperformed",
        time - $ARGV[0], $ARGV[1], $ARGV[2] + $ARGV[5], $ARGV[3], $ARGV[4], $ARGV[5], $ARGV[6];
    print " | logs: $ARGV[7]" if $ARGV[3];
    print "\n";
' "$started" "$passed" "$count" "$failed" "$skipped" "$platform_skipped" "$unperformed" "$work"
if [ "$failed" -ne 0 ]; then exit 1; fi
if [ "$skipped" -ne 0 ] || [ "$unperformed" -ne 0 ]; then exit 2; fi
exit 0
