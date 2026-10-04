"""The embedder's load flag follows the llama-server it runs (2026-10-04, Nebius pilot: b11381 refused --mmap).

Fails if the supervisor passes --mmap to a build that only knows --load-mode, drops memory-mapping, or guesses.
"""
import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location("sup", pathlib.Path(__file__).resolve().parent.parent / "scripts" / "openviking-supervisor.py")
sup = importlib.util.module_from_spec(spec); spec.loader.exec_module(sup)
n = 0
def check(cond, label):
    global n
    assert cond, label
    n += 1
NEW = "-lm,   --load-mode MODE   model loading mode (default: auto)\n  - mmap: memory-map model\n--no-mmap"
OLD = "--mmap                  memory-map model\n--no-mmap               do not memory-map model"
check(sup.load_mode_args(NEW) == ["--load-mode", "mmap"], "new llama.cpp uses --load-mode mmap")
check(sup.load_mode_args(OLD) == ["--mmap"], "old llama.cpp keeps --mmap")
check("--mmap" not in sup.load_mode_args(NEW), "never --mmap to a --load-mode build")
try:
    sup.load_mode_args("usage: llama-server [options]")
    check(False, "unknown help must refuse")
except sup.SetupError:
    check(True, "unknown help refuses")
src = (pathlib.Path(__file__).resolve().parent.parent / "scripts" / "openviking-supervisor.py").read_text()
check('"--cache-ram", "0", *self.load_mode,' in src, "the embedder command uses the probed flag")
print(f"openviking-load-mode: {n}/{n} PASS")
