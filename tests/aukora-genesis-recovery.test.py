#!/usr/bin/python3
"""SOURCE_FIXTURE, not installed qualification: retained private fixtures, no systemd.

The production recovery helper runs as a child through a fixture-only loader.
Only fixed paths and root UID metadata are adapted. Fake systemctl implements a
declared service-state protocol; the actual Node selfcheck main and retry wrapper
run with synthetic probe/sandbox/RPC results. Wrapper adaptations are exactly its
Node/entry/lock paths, a real-fcntl adapter for unavailable util-linux flock, and
removal of the 45 second fixture delay, never its retry logic or fence behavior.
"""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
UNIT_ROOT = ROOT / "packages/boundary-gate/host/systemd"
SOURCE = UNIT_ROOT / "genesis-recover-probe"
HOME_FIXTURES = Path.home() / ".aukora-h-recovery-fixtures"
GENESIS = "aukora-genesis.service"
LATCH = "aukora-selfcheck.service"
PERIODIC = "aukora-selfcheck-periodic.service"
PROVIDERS = ("aukora-boundary-gate.service", "aukora-auma-local-deny.service",
             "aukora-auma-podman.service", "aukora-openshell-gateway.service",
             "aukora-auma-sandbox.service")
ONESHOT_PROVIDERS = {"aukora-auma-local-deny.service", "aukora-auma-sandbox.service"}


def write(path, data, mode=0o600):
    path.write_text(data)
    path.chmod(mode)  # Only new fixture-owned files, never existing external data.


def service(index, active="active", exited=False):
    return {"LoadState": "loaded", "ActiveState": active,
            "SubState": "exited" if exited else "running" if active == "active" else "dead",
            "Result": "success", "InvocationID": ("%032x" % index),
            "InactiveEnterTimestampMonotonic": "0", "ExecMainStartTimestampMonotonic": "100",
            "ExecMainExitTimestampMonotonic": "0", "StateChangeTimestampMonotonic": "100",
            "MainPID": "0" if exited or active != "active" else str(1000 + index),
            "Job": "", "NeedDaemonReload": "no"}


class World:
    def __init__(self, source=SOURCE):
        if not HOME_FIXTURES.exists():
            HOME_FIXTURES.mkdir(mode=0o700)
        metadata = HOME_FIXTURES.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise RuntimeError("fixture root must already be current-user 0700 real directory")
        self.root = Path(tempfile.mkdtemp(prefix="source-", dir=str(HOME_FIXTURES)))
        self.world = self.root / "world.json"
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.config = self.root / "config"
        self.config.mkdir(mode=0o700)
        self.release = self.config / "release.env"
        write(self.release, "AUKORA_RELEASE_DIR=/opt/aukora-genesis/release-abcdef0\n"
              "AUKORA_APPROVAL_ROOT=/etc/aukora-approvals/" + "a" * 40 + "/state\n"
              "AUKORA_RECORD_SHA=" + "b" * 64 + "\n")
        self.boot = self.root / "boot-id"
        write(self.boot, "11111111-2222-3333-4444-555555555555\n")
        units = {GENESIS: service(1), LATCH: service(2, exited=True), PERIODIC: service(3, active="inactive")}
        units.update({unit: service(10 + i, exited=unit in ONESHOT_PROVIDERS)
                      for i, unit in enumerate(PROVIDERS)})
        self.put({"units": units, "calls": [], "selfchecks": [], "selfcheck_ok": True,
                  "boot_ok": True, "ready_ok": True, "floor_ok": True, "start_ok": True,
                  "stop_notice_ok": True})
        self.loader = self.root / "loader.py"
        self.fake_systemctl = self.root / "fake-systemctl"
        self.bootstrap = self.root / "fake-bootstrap.py"
        self.runner = self.root / "fake-runuser"
        self.node_driver = self.root / "selfcheck-source-driver.mjs"
        self.wrapper = self.root / "selfcheck-with-retry"
        self.self_lock = self.root / "selfcheck.lock"
        self.flock = self.root / "fixture-flock"
        self.events = self.root / "selfcheck-events.jsonl"
        write(self.events, "")
        node = shutil.which("node")
        if not node:
            raise RuntimeError("Node required")
        self.node = node
        write(self.loader, """import os, runpy, stat, sys
g = runpy.run_path(SOURCE, run_name='recovery_source_fixture')
g = g['main'].__globals__
def fixture_trusted(m, directory=False):
    g['require'](m.st_uid in (0, os.getuid()) and not m.st_mode & 0o022, 'custody')
    g['require'](stat.S_ISDIR(m.st_mode) if directory else stat.S_ISREG(m.st_mode) and m.st_nlink == 1, 'file-type')
g.update(PATHS)
g['trusted'] = fixture_trusted
os.geteuid = lambda: 0
raise SystemExit(g['main']())
""".replace("SOURCE", repr(str(source))).replace("PATHS", repr({
            "SYSTEMCTL": str(self.fake_systemctl), "PYTHON": sys.executable,
            "BOOTSTRAP": str(self.bootstrap), "RUNUSER": str(self.runner),
            "SELFCHECK": str(self.wrapper), "STATE": str(self.state),
            "INHIBITOR": str(self.config / "operator.json"), "RELEASE": str(self.release),
            "BOOT_ID": str(self.boot), "SELF_LOCK": str(self.self_lock)})))
        write(self.fake_systemctl, """#!/usr/bin/python3
import json, os, subprocess, sys
from pathlib import Path
p = Path(WORLD)
w = json.loads(p.read_text()); args = sys.argv[1:]
w['calls'].append(['systemctl', *args])
unit = args[-1]
if args[0] == 'show':
    p.write_text(json.dumps(w)); value = w['units'][unit]
    for key, item in value.items(): print(key + '=' + item)
elif args[0] == 'stop':
    u = w['units'][unit]
    hook_result = 0
    if u['ActiveState'] == 'active':
        p.write_text(json.dumps(w))
        env = dict(os.environ, INVOCATION_ID=u['InvocationID'], SERVICE_RESULT='success')
        if w['stop_notice_ok']:
            result = subprocess.run([PYTHON, '-I', '-S', '-B', LOADER, 'stop-notice'], env=env)
            hook_result = result.returncode
        w = json.loads(p.read_text()); u = w['units'][unit]
        u.update(ActiveState='inactive', SubState='dead', MainPID='0',
                 InactiveEnterTimestampMonotonic='500', ExecMainExitTimestampMonotonic='499',
                 StateChangeTimestampMonotonic='500')
    p.write_text(json.dumps(w))
    raise SystemExit(hook_result)
elif args[0] == 'start':
    if not w['start_ok']:
        p.write_text(json.dumps(w)); raise SystemExit(1)
    w['units'][unit].update(ActiveState='active', SubState='running', MainPID='2001',
        InvocationID='f'*32, ExecMainStartTimestampMonotonic='600', StateChangeTimestampMonotonic='600')
    w['launches'] = w.get('launches', 0) + 1
    p.write_text(json.dumps(w))
else:
    p.write_text(json.dumps(w)); raise SystemExit(99)
""".replace("WORLD", repr(str(self.world))).replace("PYTHON", repr(sys.executable))
            .replace("LOADER", repr(str(self.loader))), 0o700)
        write(self.bootstrap, """import json, sys
from pathlib import Path
p = Path(WORLD); w = json.loads(p.read_text()); args = sys.argv[1:]
w['calls'].append(['bootstrap', *args]); p.write_text(json.dumps(w))
key = {'check-boot':'boot_ok', 'check-ready':'ready_ok', 'floor':'floor_ok'}[args[0]]
raise SystemExit(0 if w[key] else 1)
""".replace("WORLD", repr(str(self.world))))
        write(self.runner, """#!/usr/bin/python3
import os, sys
assert sys.argv[1:5] == ['-u', 'aukora-host', '--', WRAPPER]
os.execv('/bin/bash', ['/bin/bash', *sys.argv[4:]])
""".replace("WRAPPER", repr(str(self.wrapper))), 0o700)
        write(self.node_driver, """import fs from 'node:fs'
import { main } from ENTRY
const path = WORLD
const read = () => JSON.parse(fs.readFileSync(path, 'utf8'))
const w = read()
const events = EVENTS
const event = phase => fs.appendFileSync(events, JSON.stringify({phase,pid:process.pid}) + '\\n')
const refused = () => { throw Object.assign(new Error('source fixture refusal'), {code:'EACCES'}) }
const rpc = async (sock, op, args) => {
  if (op !== 'selfcheck') return refused()
  const current = read(); current.selfchecks.push(args.result)
  fs.writeFileSync(path, JSON.stringify(current)); return {ok:true}
}
const run = async () => {
  if (w.selfcheck_delay_ms) await new Promise(r => setTimeout(r, w.selfcheck_delay_ms))
  return {exit_code:0, stdout:'PROBE_DONE fail=0\\n', stderr:''}
}
const probesFor = () => [['synthetic forbidden action', w.selfcheck_ok ? refused : () => 'SUCCEEDED']]
// Every path passed to the real selfcheck is scoped to this new private fixture.
const argv = process.argv.slice(2).map(a => a.startsWith('/') ? FIXTURE : a)
event('enter')
try { process.exitCode = await main(argv, {run, rpc, probesFor}) } finally { event('exit') }
""".replace("ENTRY", json.dumps((ROOT / "packages/boundary-gate/bin/selfcheck.mjs").as_uri()))
            .replace("WORLD", json.dumps(str(self.world))).replace("FIXTURE", json.dumps(str(self.root)))
            .replace("EVENTS", json.dumps(str(self.events))))
        write(self.flock, """#!/usr/bin/python3
import fcntl, os, sys
args = sys.argv[1:]
if args == ['--exclusive', '9']:
    fcntl.flock(9, fcntl.LOCK_EX)
else:
    assert args[:2] == ['--exclusive', '--no-fork']
    fd = os.open(args[2], os.O_RDONLY)
    fcntl.flock(fd, fcntl.LOCK_EX); os.set_inheritable(fd, True)
    os.execv(args[3], args[3:])
""", 0o700)
        wrapper = (UNIT_ROOT / "selfcheck-with-retry").read_text()
        old = "/opt/aukora-node/bin/node /opt/aukora-boundary-gate/bin/selfcheck.mjs"
        assert wrapper.count(old) == 1 and wrapper.count("sleep 45") == 1
        wrapper = wrapper.replace(old, json.dumps(node) + " " + json.dumps(str(self.node_driver)))
        assert wrapper.count("/run/aukora-boundary-selfcheck.lock") == 1
        assert wrapper.count("/usr/bin/flock --exclusive 9") == 1
        wrapper = wrapper.replace("/run/aukora-boundary-selfcheck.lock", str(self.self_lock))
        wrapper = wrapper.replace("/usr/bin/flock --exclusive 9", json.dumps(str(self.flock)) + " --exclusive 9")
        write(self.wrapper, wrapper.replace("sleep 45", "sleep 0"), 0o700)

    def get(self):
        return json.loads(self.world.read_text())

    def put(self, value):
        write(self.world, json.dumps(value))

    def change(self, **values):
        w = self.get(); w.update(values); self.put(w)

    def helper(self, *argv, monitored=True, expect=0, monitor_unit=PERIODIC):
        env = {"PATH": "/usr/bin:/bin", "HOME": "/", "LANG": "C", "LC_ALL": "C"}
        if monitored:
            env.update(MONITOR_UNIT=monitor_unit, MONITOR_INVOCATION_ID="3".zfill(32),
                       MONITOR_SERVICE_RESULT="exit-code")
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(self.loader), *argv],
                                env=env, capture_output=True, text=True, timeout=30)
        if result.returncode != expect:
            raise AssertionError((argv, result.returncode, result.stdout, result.stderr))
        return result

    def periodic_failure(self, monitored=True):
        # Execute the real bin/selfcheck main before modeling timer OnFailure dispatch.
        self.change(selfcheck_ok=False)
        result = subprocess.run([self.node, str(self.node_driver), "--run", str(self.state),
            "--gate-home", str(self.config), "--target-root", str(self.state),
            "--release-parent", str(self.root)], capture_output=True, text=True, timeout=10)
        assert result.returncode == 1 and self.get()["selfchecks"][-1]["ok"] is False
        w = self.get(); w["units"][PERIODIC].update(ActiveState="failed", SubState="failed",
                Result="exit-code", InactiveEnterTimestampMonotonic="400", StateChangeTimestampMonotonic="400")
        self.put(w)
        self.helper("failclosed", PERIODIC, monitored=monitored)
        self.change(selfcheck_ok=True)

    def eligibility(self):
        return json.loads((self.state / "eligibility.json").read_text())

    def starts(self):
        return [c for c in self.get()["calls"] if c[:2] == ["systemctl", "start"]]

    def concurrent_checks(self, remove_wrapper_fence=False):
        self.helper("prepare-selfcheck-lock")
        self.change(selfcheck_delay_ms=350)
        argv = ["--run", str(self.state), "--gate-home", str(self.config),
                "--target-root", str(self.state), "--release-parent", str(self.root)]
        wrapper = self.wrapper
        if remove_wrapper_fence:
            wrapper = self.root / "mutant-unfenced-wrapper"
            before = json.dumps(str(self.flock)) + " --exclusive 9 || exit 1"
            source = self.wrapper.read_text()
            assert source.count(before) == 1
            write(wrapper, source.replace(before, ": # source fixture guard removal"), 0o700)
        first = subprocess.Popen(["/bin/bash", str(wrapper), "--", *argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # The periodic source ExecStart has this same fixed no-fork fence around Node.
        second = subprocess.Popen([str(self.flock), "--exclusive", "--no-fork", str(self.self_lock),
                                   self.node, str(self.node_driver), *argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for child in (first, second):
            out, err = child.communicate(timeout=10)
            assert child.returncode == 0, (child.returncode, out, err)
        depth = maximum = 0
        for line in self.events.read_text().splitlines():
            depth += 1 if json.loads(line)["phase"] == "enter" else -1
            maximum = max(maximum, depth)
        assert depth == 0
        return maximum


class RecoveryChecks(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def test_actual_code_periodic_failure_stop_recover_with_active_startup_latch(self):
        self.w.periodic_failure()
        self.assertTrue(self.w.eligibility()["eligible"])
        self.assertEqual(self.w.get()["units"][GENESIS]["ActiveState"], "inactive")
        self.assertEqual(self.w.get()["units"][LATCH]["ActiveState"], "active")
        self.w.helper("recover")
        self.assertEqual(self.w.get()["units"][GENESIS]["ActiveState"], "active")
        self.assertFalse(self.w.eligibility()["eligible"])
        self.assertEqual(len(self.w.starts()), 1)
        self.assertTrue(self.w.get()["selfchecks"][-1]["ok"])
        self.assertFalse(any(c[:2] == ["systemctl", "reset-failed"] for c in self.w.get()["calls"]))
        self.w.helper("recover")
        self.assertEqual(len(self.w.starts()), 1)

    def test_source_provider_types_match_oneshot_fixture_and_reject_running_sandbox(self):
        sandbox = (UNIT_ROOT / "aukora-auma-sandbox.service").read_text()
        self.assertIn("Type=oneshot\n", sandbox)
        self.assertIn("RemainAfterExit=yes\n", sandbox)
        self.assertEqual(self.w.get()["units"]["aukora-auma-sandbox.service"]["SubState"], "exited")
        self.w.periodic_failure(); v = self.w.get()
        v["units"]["aukora-auma-sandbox.service"].update(SubState="running", MainPID="9010")
        self.w.put(v); result = self.w.helper("recover", expect=1)
        self.assertIn("provider-unready", result.stderr); self.assertEqual(self.w.starts(), [])

    def test_absent_actual_stop_notice_cannot_arm_despite_inactive_timestamp(self):
        self.w.periodic_failure(); self.w.change(stop_notice_ok=False)
        v = self.w.get(); v["units"][GENESIS] = service(1); self.w.put(v)
        result = self.w.helper("failclosed", PERIODIC, expect=1)
        self.assertIn("stop-witness-missing", result.stderr)
        self.assertFalse(self.w.eligibility()["eligible"])
        self.w.helper("recover"); self.assertEqual(self.w.starts(), [])

    def test_inactive_operator_stopped_unit_never_acquires_recovery_authority(self):
        w = self.w.get(); w["units"][GENESIS] = service(1, active="inactive"); self.w.put(w)
        self.w.helper("recover")
        self.assertEqual(self.w.starts(), [])
        self.w.periodic_failure()
        self.assertFalse(self.w.eligibility()["eligible"])
        self.w.helper("recover")
        self.assertEqual(self.w.starts(), [])

    def test_missing_failure_provenance_stops_without_arming(self):
        self.w.periodic_failure(monitored=False)
        self.assertFalse(self.w.eligibility()["eligible"])
        self.assertEqual(self.w.get()["units"][GENESIS]["ActiveState"], "inactive")
        self.w.helper("recover")
        self.assertEqual(self.w.starts(), [])

    def test_wrong_monitored_unit_cannot_arm_recovery(self):
        self.w.periodic_failure(monitored=False)
        w = self.w.get(); w["units"][GENESIS] = service(1); self.w.put(w)
        self.w.helper("failclosed", PERIODIC, monitor_unit=LATCH)
        self.assertFalse(self.w.eligibility()["eligible"])
        self.w.helper("recover"); self.assertEqual(self.w.starts(), [])

    def test_readiness_failure_during_stop_can_recover_only_after_fresh_readiness(self):
        self.w.change(ready_ok=False)
        self.w.periodic_failure()
        self.assertTrue(self.w.eligibility()["eligible"])
        self.w.helper("recover", expect=1); self.assertEqual(self.w.starts(), [])
        self.w.change(ready_ok=True)
        self.w.helper("recover"); self.assertEqual(len(self.w.starts()), 1)

    def test_query_failure_still_stops_but_cannot_arm(self):
        self.w.periodic_failure(monitored=False)
        v = self.w.get(); v["units"][GENESIS] = service(1)
        v["units"][GENESIS]["NeedDaemonReload"] = "yes"; self.w.put(v)
        self.w.helper("failclosed", PERIODIC, expect=1)
        self.assertEqual(self.w.get()["units"][GENESIS]["ActiveState"], "inactive")
        self.assertFalse(self.w.eligibility()["eligible"])

    def test_state_custody_and_write_refusals_still_request_mandatory_stop(self):
        for mode in (0o777, 0o500):
            with self.subTest(mode=oct(mode)):
                w = World(); w.state.chmod(mode)
                result = w.helper("failclosed", PERIODIC, expect=1)
                self.assertIn("REFUSED", result.stderr)
                self.assertEqual(w.get()["units"][GENESIS]["ActiveState"], "inactive")
                self.assertTrue(any(c[:2] == ["systemctl", "stop"] for c in w.get()["calls"]))
                self.assertEqual(w.starts(), [])

    def test_actual_shared_execution_fence_prevents_timer_wrapper_overlap(self):
        self.assertEqual(self.w.concurrent_checks(), 1)
        mutant = World()
        self.assertEqual(mutant.concurrent_checks(remove_wrapper_fence=True), 2,
                         "removing the wrapper lock must permit real concurrent Node selfchecks")

    def test_operator_inhibit_consumes_failure_authority_even_while_already_inactive(self):
        self.w.periodic_failure(); self.w.helper("inhibit"); self.w.helper("recover")
        self.assertEqual(self.w.starts(), [])
        self.assertFalse(self.w.eligibility()["eligible"])
        self.w.helper("operator-start")
        self.assertEqual(len(self.w.starts()), 1)

    def test_ordinary_stop_notice_invalidates_eligibility(self):
        self.w.periodic_failure(); self.w.helper("stop-notice", monitored=False)
        self.assertFalse(self.w.eligibility()["eligible"])
        self.w.helper("recover"); self.assertEqual(self.w.starts(), [])

    def test_recovery_guards_refuse_before_any_start(self):
        for key, reason in (("boot_ok", "boot-refused"), ("ready_ok", "readiness-refused"),
                            ("floor_ok", "floor-refused"), ("selfcheck_ok", "selfcheck-refused")):
            with self.subTest(key=key):
                w = World(); w.periodic_failure(); w.change(**{key: False})
                result = w.helper("recover", expect=1)
                self.assertIn(reason, result.stderr); self.assertEqual(w.starts(), [])

    def test_retry_wrapper_really_attempts_twice_when_selfcheck_refuses(self):
        self.w.periodic_failure(); before = len(self.w.get()["selfchecks"])
        self.w.change(selfcheck_ok=False); self.w.helper("recover", expect=1)
        self.assertEqual(len(self.w.get()["selfchecks"]) - before, 2)
        self.assertEqual(self.w.starts(), [])

    def test_changed_release_or_stopped_invocation_refuses(self):
        for change in ("release", "invocation", "boot"):
            with self.subTest(change=change):
                w = World(); w.periodic_failure()
                if change == "release": write(w.release, w.release.read_text().replace("abcdef0", "abcdef1"))
                elif change == "boot": write(w.boot, "22222222-2222-3333-4444-555555555555\n")
                else:
                    v = w.get(); v["units"][GENESIS]["ExecMainStartTimestampMonotonic"] = "550"; w.put(v)
                w.helper("recover", expect=1); self.assertEqual(w.starts(), [])

    def test_unsafe_or_executing_provider_refuses_without_implicit_start(self):
        for unit in (*PROVIDERS, PERIODIC, LATCH):
            with self.subTest(unit=unit):
                w = World(); w.periodic_failure(); v = w.get()
                v["units"][unit].update(ActiveState="activating", SubState="start", MainPID="9000")
                w.put(v); w.helper("recover", expect=1); self.assertEqual(w.starts(), [])

    def test_rate_limited_start_consumes_token_without_reset_or_rearm(self):
        self.w.periodic_failure(); self.w.change(start_ok=False)
        self.w.helper("recover", expect=1); self.assertFalse(self.w.eligibility()["eligible"])
        self.w.change(start_ok=True); self.w.helper("recover")
        self.assertEqual(len(self.w.starts()), 1)

    def test_closed_release_data_refuses_shell_and_duplicate_fields(self):
        for addition in ("AUKORA_RECORD_SHA=$(touch /no-source-fixture-effect)\n", "export BAD=1\n"):
            with self.subTest(addition=addition):
                w = World(); w.periodic_failure(); write(w.release, w.release.read_text() + addition)
                v = w.get(); v["units"][GENESIS] = service(1); w.put(v)
                result = w.helper("failclosed", PERIODIC, expect=1)
                self.assertIn("release-format", result.stderr)
                self.assertEqual(w.starts(), [])

    def test_guard_removals_have_executable_unsafe_witnesses(self):
        original = SOURCE.read_text()
        mutations = (
            ("boot", 'require(command([PYTHON, "-I", "-S", BOOTSTRAP, "check-boot"]).returncode == 0, "boot-refused")', 'pass', "boot_ok"),
            ("readiness", 'require(command([PYTHON, "-I", "-S", BOOTSTRAP, "check-ready"]).returncode == 0, "readiness-refused")', 'pass', "ready_ok"),
            ("selfcheck", 'timeout=300).returncode == 0, "selfcheck-refused")', 'timeout=300).returncode in (0, 1), "selfcheck-refused")', "selfcheck_ok"),
            ("floor", 'configuration["AUKORA_APPROVAL_ROOT"]], timeout=60).returncode == 0, "floor-refused")', 'configuration["AUKORA_APPROVAL_ROOT"]], timeout=60).returncode in (0, 1), "floor-refused")', "floor_ok"),
        )
        for name, before, after, flag in mutations:
            with self.subTest(name=name):
                self.assertEqual(original.count(before), 1)
                path = self.w.root / ("mutant-" + name + ".py")
                write(path, original.replace(before, after))
                w = World(source=path); w.periodic_failure(); w.change(**{flag: False})
                w.helper("recover"); self.assertEqual(len(w.starts()), 1)
        before = "    if inhibited():\n        return\n"
        self.assertEqual(original.count(before), 1)
        mutant = self.w.root / "mutant-inhibit.py"
        write(mutant, original.replace(before, ""))
        w = World(source=mutant); w.periodic_failure()
        # Preserve an eligible token while introducing the explicit durable inhibitor.
        write(w.config / "operator.json", '{"version":1,"inhibited":true}')
        # The final recheck is also part of the inhibit guard; remove both edges.
        text = mutant.read_text().replace("and release()[1] == digest and not inhibited()", "and release()[1] == digest")
        write(mutant, text); w.helper("recover"); self.assertEqual(len(w.starts()), 1)
        before = 'proven = os.environ.get("MONITOR_UNIT") == source and HEX32.fullmatch(monitored_id)'
        self.assertEqual(original.count(before), 1)
        mutant = self.w.root / "mutant-failure-provenance.py"
        write(mutant, original.replace(before, 'proven = HEX32.fullmatch(monitored_id)'))
        w = World(source=mutant); w.periodic_failure(monitored=False)
        v = w.get(); v["units"][GENESIS] = service(1); w.put(v)
        w.helper("failclosed", PERIODIC, monitor_unit=LATCH)
        self.assertTrue(w.eligibility()["eligible"])
        w.helper("recover"); self.assertEqual(len(w.starts()), 1)


if __name__ == "__main__":
    print("SOURCE_FIXTURE: real recovery helper, retry wrapper and bin/selfcheck main; fake systemctl;")
    print("synthetic UID custody, readiness, sandbox and unsigned recording; installed systemd UNPERFORMED.")
    print("Retained private fixtures under ~/.aukora-h-recovery-fixtures; no old fixture deletion.")
    unittest.main(verbosity=2)
