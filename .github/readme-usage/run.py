"""One hosted usage recording. No retry, dependency install or substitute output."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path.cwd()
OUT = Path(os.environ["USAGE_OUT"])
OUT.mkdir(parents=True, exist_ok=True)
RAW = OUT / "commands"
RAW.mkdir(exist_ok=True)
# Every command form in the README, including alternatives not selected by P9.
DOCS = {
    "clone": "git clone https://github.com/evandukss/edge-observer.git",
    "cd": "cd edge-observer",
    "build": "CGO_ENABLED=0 go build -trimpath -o observer ./cmd/observer",
    "cross-build": "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o observer ./cmd/observer",
    "archive-checksum": "sha256sum -c observer-linux-amd64.sha256",
    "configure": "cp contract/config/examples/no-rules.config.json observer.config.json",
    "pgrep": "pgrep -a <program name>",
    "exe": "readlink /proc/<pid>/exe",
    "args": "tr '\\0' '\\n' < /proc/<pid>/cmdline",
    "dry-run": "./observer dry-run observer.config.json --text",
    "library": "sudo awk '/libssl[.]so/ {print $NF}' /proc/<pid>/maps | sort -u",
    "preflight": "sudo systemd-run --scope -p MemoryMax=512M -p MemorySwapMax=0 ./observer preflight observer.config.json --text",
    "container-preflight": "docker run ... ./observer preflight observer.config.json --text",
    "start": "sudo systemd-run --scope -p MemoryMax=512M -p MemorySwapMax=0 ./observer start observer.config.json",
    "start-stdout": "./observer start observer.config.json --stdout (same memory envelope)",
    "invalid-daemon-stdout": "start --daemonize --stdout",
    "invalid-restart-stdout": "restart --stdout",
    "inspect-running": "sudo ./observer inspect observer.config.json --text",
    "inspect-running-records": "sudo ./observer inspect observer.config.json --text --session <session>",
    "stop": "sudo ./observer stop observer.config.json",
    "interrupt": "Ctrl-C in foreground terminal (alternative to stop)",
    "restart": "sudo ./observer restart observer.config.json (same memory envelope)",
    "inspect-sealed": "sudo ./observer inspect /var/lib/observer/sessions/<session> --text",
    "inspect-rotated": "./observer inspect ./session --text --file ./approved.jsonl.1 --file ./approved.jsonl --session <session>",
    "inspect-json": "./observer inspect <session directory> (without --text)",
    "reopen": "observer reopen <configuration> (logrotate alternative)",
}
SELECTED = {"build", "configure", "pgrep", "exe", "args", "dry-run", "library", "preflight", "start", "inspect-running", "stop", "inspect-sealed"}
ledger = {k: {"documented": v, "grade": "not attempted", "reason": "not reached" if k in SELECTED else "alternative outside selected single systemd usage path"} for k, v in DOCS.items()}
processes = {}
threads = []
activation = {}
service_ready = {}
activated = threading.Event()
listening = threading.Event()
failures = []
service_termination_sent = False


def save():
    (OUT / "command-grades.json").write_text(json.dumps(ledger, indent=2) + "\n")


def prepare(name, command, kind):
    entry = ledger.setdefault(name, {})
    entry.update(kind=kind, command=command, grade="attempted", reason="started", started=time.time())
    save()
    (RAW / (name + ".command.json")).write_text(json.dumps(command) + "\n")


def finish(name, code, reason="exited"):
    ledger[name].update(exit=code, grade="attempted" if code == 0 else "failed", reason=reason, ended=time.time())
    (RAW / (name + ".exit")).write_text("unknown\n" if code is None else str(code) + "\n")
    save()


def command(name, argv, kind="documented", check=True, env=None, within=60):
    prepare(name, argv, kind)
    reason = "exited"
    with (RAW / (name + ".stdout")).open("wb") as stdout, (RAW / (name + ".stderr")).open("wb") as stderr:
        try:
            result = subprocess.run(argv, stdout=stdout, stderr=stderr, env=env, timeout=within)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = None
            reason = "recording allowance expired; actual exit unavailable"
        except OSError as error:
            code = None
            reason = "could not start command: " + str(error)
    finish(name, code, reason)
    if check and code != 0:
        raise RuntimeError(f"{name} failed with exit {code}; see raw output")
    return (RAW / (name + ".stdout")).read_text(errors="replace")


def launch(name, argv, kind, event, record):
    prepare(name, argv, kind)
    stderr = (RAW / (name + ".stderr")).open("wb")
    try:
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=stderr)
    except OSError as error:
        stderr.close()
        (RAW / (name + ".stdout")).touch()
        finish(name, None, "could not start child: " + str(error))
        raise
    processes[name] = child

    def collect():
        with (RAW / (name + ".stdout")).open("wb") as dest:
            for line in child.stdout:
                dest.write(line)
                dest.flush()
                try:
                    value = json.loads(line)
                except (ValueError, UnicodeError):
                    continue
                if name == "service" or value.get("record") == "activation-completed":
                    record.update(value)
                    event.set()
        child.stdout.close()
        child.wait()
        stderr.close()

    thread = threading.Thread(target=collect, daemon=True)
    threads.append(thread)
    thread.start()
    if not event.wait(40):
        raise RuntimeError(f"{name} produced no readiness record within 40 seconds; no retry")
    return child


def main():
    save()
    if os.environ.get("GITHUB_RUN_ATTEMPT") != "1":
        raise RuntimeError("a rerun needs a new reviewed plan; this recorder allows attempt 1 only")
    (OUT / "run-identity.json").write_text(json.dumps({key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_REPOSITORY", "CANDIDATE_SHA", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion")}, indent=2) + "\n")
    command("host", ["uname", "-srm"], "setup")
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise RuntimeError("requires the GitHub-hosted ubuntu-24.04 x64 runner")
    head = command("source-head", ["git", "rev-parse", "HEAD"], "setup").strip()
    if head != os.environ["CANDIDATE_SHA"]:
        raise RuntimeError("checkout is not the exact PR head")
    if command("source-status", ["git", "status", "--porcelain"], "setup").strip():
        raise RuntimeError("source checkout is not clean")
    command("source-archive", ["git", "archive", "--format=tar", "-o", str(OUT / "source.tar"), "HEAD"], "setup")
    command("source-tree", ["git", "ls-tree", "-r", "HEAD"], "setup")
    shutil.copyfile(ROOT / "README.md", OUT / "README-before-run.md")
    command("systemd", ["systemctl", "--version"], "setup")
    command("openssl", ["openssl", "version", "-a"], "setup")
    # Use only an already present Go toolchain. GOTOOLCHAIN=local forbids auto-install.
    available = list(Path("/opt/hostedtoolcache/go").glob("*/x64/bin/go"))
    existing = shutil.which("go")
    if existing:
        available.append(Path(existing))
    chosen = None
    for index, executable in enumerate(sorted(set(available), reverse=True)):
        version = command(f"go-version-{index}", [str(executable), "version"], "setup", env=dict(os.environ, GOTOOLCHAIN="local"))
        match = re.search(r"go1\.(\d+)(?:\.|\s)", version)
        if match and int(match[1]) >= 27:
            chosen = executable
            break
    if chosen is None:
        raise RuntimeError("no installed Go >= 1.27; no installation or fallback attempted")
    env = dict(os.environ, CGO_ENABLED="0", GOTOOLCHAIN="local")
    env["PATH"] = str(chosen.parent) + os.pathsep + env["PATH"]
    command("build", ["go", "build", "-trimpath", "-o", "observer", "./cmd/observer"], env=env, within=300)
    command("build-identity", ["go", "version", "-m", "observer"], "setup", env=env)
    command("binary-sha256", ["sha256sum", "observer"], "setup")
    command("binary-format", ["file", "observer"], "setup")
    shutil.copyfile(ROOT / "observer", OUT / "observer")
    command("configure", ["cp", "contract/config/examples/no-rules.config.json", "observer.config.json"])
    with tempfile.TemporaryDirectory(prefix="readme-local-tls-") as tls:
        cert, key = Path(tls) / "cert.pem", Path(tls) / "key.pem"
        command("certificate", ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost", "-days", "1", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], "setup")
        shutil.copyfile(cert, OUT / "public-cert.pem")
        child = launch("service", ["/usr/bin/python3", "-u", str(ROOT / ".github/readme-usage/service.py"), str(cert), str(key)], "setup", listening, service_ready)
        if not service_ready["openssl"].startswith("OpenSSL 3."):
            raise RuntimeError("service does not use OpenSSL 3")
        pid = child.pid
        command("pgrep", ["pgrep", "-a", "python3"])
        exe = command("exe", ["readlink", f"/proc/{pid}/exe"]).strip()
        command("args", ["bash", "-o", "pipefail", "-c", f"tr '\\0' '\\n' < /proc/{pid}/cmdline"])
        service_cgroup = command("service-cgroup", ["cat", f"/proc/{pid}/cgroup"], "setup").strip().split("0::", 1)[1]
        config = json.loads((ROOT / "observer.config.json").read_text())
        config["output"] = str(OUT / "output")
        config["log"] = str(OUT / "observer.log")
        config["watch"] = [{"name": "usage-service", "exe": exe, "args": Path(f"/proc/{pid}/cmdline").read_bytes().decode().split("\0")[1:-1], "children": "none"}]
        (ROOT / "observer.config.json").write_text(json.dumps(config, indent=2) + "\n")
        shutil.copyfile(ROOT / "observer.config.json", OUT / "observer.config.json")
        (OUT / "config.sha256").write_text(hashlib.sha256((ROOT / "observer.config.json").read_bytes()).hexdigest() + "  observer.config.json\n")
        ledger["configure-values"] = {"kind": "setup", "grade": "attempted", "reason": "set output, log, exe and exact arguments for this run's service; configuration retained"}
        save()
        selected = command("dry-run", ["./observer", "dry-run", "observer.config.json", "--text"])
        if not re.search(rf"^\s+root pid {pid}, ", selected, re.M):
            raise RuntimeError("dry-run did not select the fixture process")
        mappings = command("library", ["bash", "-o", "pipefail", "-c", f"sudo awk '/libssl[.]so/ {{print $NF}}' /proc/{pid}/maps | sort -u"])
        if "libssl.so.3" not in mappings:
            raise RuntimeError("no mapped libssl.so.3 in the selected service")
        scope = ["sudo", "systemd-run", "--scope", "-p", "MemoryMax=512M", "-p", "MemorySwapMax=0"]
        ready = command("preflight", scope + ["./observer", "preflight", "observer.config.json", "--text"])
        if not re.search(r"^verdict\s+READY$", ready, re.M):
            raise RuntimeError("preflight did not say READY; start not attempted")
        observer = launch("start", scope + ["./observer", "start", "observer.config.json"], "documented", activated, activation)
        (OUT / "activation.json").write_text(json.dumps(activation, indent=2) + "\n")
        observer_cgroup = command("observer-cgroup", ["sudo", "cat", f"/proc/{activation['pid']}/cgroup"], "setup").strip().split("0::", 1)[1]
        if service_cgroup == observer_cgroup or service_cgroup.startswith(observer_cgroup.rstrip("/") + "/"):
            raise RuntimeError("service is inside observer scope")
        envelope = Path("/sys/fs/cgroup") / observer_cgroup.lstrip("/")
        command("observer-envelope", ["sudo", "cat", str(envelope / "memory.max"), str(envelope / "memory.swap.max"), str(envelope / "cgroup.type")], "setup")
        # A fresh curl process makes a NEW TLS connection, only after activation.
        marker = "readme-usage-" + os.environ["GITHUB_RUN_ID"]
        command("request", ["curl", "--http1.1", "--cacert", str(cert), "--max-time", "10", "--include", f"https://localhost:{service_ready['port']}/{marker}"], "setup traffic")
        command("inspect-running", ["sudo", "./observer", "inspect", "observer.config.json", "--text"])
        # Continue through inspection even when stop fails: failures remain failures.
        command("stop", ["sudo", "./observer", "stop", "observer.config.json"], check=False, within=40)
        observer.wait(timeout=30)
        session = activation["session"]
        command("inspect-sealed", ["sudo", "./observer", "inspect", str(OUT / "output/sessions" / session), "--text"], check=False)
        approved = OUT / "output/approved.jsonl"
        command("approved-copy", ["sudo", "cat", str(approved)], "setup evidence", check=False)
        rows = [json.loads(line) for line in (RAW / "approved-copy.stdout").read_text().splitlines()]
        matched = [row for row in rows if row.get("session") == session and row.get("record") == "exchange" and marker in json.dumps(row)]
        (OUT / "exchange-check.json").write_text(json.dumps({"session": session, "marker": marker, "records": len(rows), "matching_exchanges": len(matched)}, indent=2) + "\n")
        if len(matched) != 1:
            raise RuntimeError("the identifiable request did not produce exactly one approved exchange; retain finding")


def attempt(label, action):
    try:
        action()
    except Exception as error:
        failures.append(f"{label}: {type(error).__name__}: {error}")


def cleanup_observer():
    observer = processes.get("start")
    if observer and observer.poll() is None:
        if ledger["stop"]["grade"] == "not attempted":
            command("cleanup-stop", ["sudo", "./observer", "stop", "observer.config.json"], "cleanup", check=False, within=40)
        try:
            observer.wait(timeout=30)
        except subprocess.TimeoutExpired as error:
            # A failed stop is not retried. Remove only this invocation's scope.
            failures.append("observer exceeded cleanup allowance: " + str(error))
            raw = (RAW / "start.stderr").read_text()
            units = re.findall(r"\b(run-[A-Za-z0-9_-]+\.scope)\b", raw)
            if units:
                command("cleanup-scope", ["sudo", "systemctl", "kill", "--kill-whom=all", "--signal=SIGKILL", units[0]], "cleanup", check=False, within=15)
                observer.wait(timeout=10)
            else:
                failures.append("observer scope was not identified; scope kill not attempted")


def cleanup_service():
    global service_termination_sent
    server = processes.get("service")
    if server and server.poll() is None:
        server.send_signal(signal.SIGTERM)
        service_termination_sent = True
        server.wait(timeout=10)


def cleanup():
    attempt("observer cleanup", cleanup_observer)
    attempt("service cleanup", cleanup_service)
    for index, thread in enumerate(threads):
        attempt(f"collector {index} join", lambda: thread.join(timeout=5))
        if thread.is_alive():
            failures.append(f"collector {index} still running; raw output may be incomplete")


def process_status(name, child, residue):
    try:
        code = child.poll()
        state = "still running" if code is None else "exited"
        reason = "still running after cleanup; exit unavailable" if code is None else "exited"
    except Exception as error:
        code, state = None, "unknown"
        reason = f"exit status unavailable: {type(error).__name__}: {error}"
        failures.append(name + ": " + reason)
    residue[name].update(state=state, exit=code, reason=reason)
    attempt(name + " exit receipt", lambda: finish(name, code, reason))
    if name == "service" and service_termination_sent and code == -signal.SIGTERM:
        ledger[name].update(grade="attempted", reason="terminated by cleanup after recording")


def finalize():
    # Every cleanup is independent. Even an unexpected resource error must not
    # skip ownership repair or the remaining process/command evidence.
    attempt("cleanup", cleanup)
    attempt("artifact ownership", lambda: command("artifact-permissions", ["sudo", "chown", "-R", f"{os.getuid()}:{os.getgid()}", str(OUT)], "cleanup", check=False))
    residue = {}
    for name, child in processes.items():
        residue[name] = {"pid": child.pid, "state": "unknown", "exit": None, "reason": "status collection did not complete"}
        attempt(name + " status collection", lambda: process_status(name, child, residue))
    for name, row in ledger.items():
        if row.get("reason") == "started":
            row.update(grade="failed", exit=None, reason="result unavailable when recorder finalized")
            attempt(name + " unavailable exit receipt", lambda: (RAW / (name + ".exit")).write_text("unknown\n"))
    attempt("process residue", lambda: (OUT / "process-residue.json").write_text(json.dumps(residue, indent=2) + "\n"))
    failures.extend(name + ": " + row["reason"] for name, row in ledger.items() if row.get("grade") == "failed")
    attempt("command grades", save)
    attempt("findings", lambda: (OUT / "findings.json").write_text(json.dumps(failures, indent=2) + "\n"))
    # Keep write failures visible in the job log even if evidence storage failed.
    for failure in failures:
        print(failure, file=sys.stderr)


try:
    main()
except Exception as error:
    failures.append(str(error))
finally:
    finalize()
sys.exit(1 if failures else 0)
