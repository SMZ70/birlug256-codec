#!/usr/bin/env python3
"""Grade every entry in participants.json and write SCOREBOARD.md.

    python3 evaluate.py

Each participant lists a git URL (or a local path for the built-in example).
We clone their repo, then build and run with --network none.

    docker build --network none --pull=false
    docker run  --network none IMAGE --compress   /data/in /data/out
    docker run  --network none IMAGE --decompress /data/out /data/back

Score = size(compressed output) + size(their tree, except Dockerfile and .git).
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.request
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CHALLENGE = ROOT / "challenge.b64"
CHALLENGE_URL = os.environ.get(
    "CHALLENGE_URL",
    "https://github.com/birlug/256/releases/download/files/challenge.b64",
)
PARTICIPANTS = ROOT / "participants.json"
SCOREBOARD = ROOT / "SCOREBOARD.md"
TIMEOUT = 60
BUILD_TIMEOUT = 300
CLONE_TIMEOUT = 120


def human(n: int) -> str:
    return f"{n:,}"


def ensure_challenge() -> str | None:
    """Use a local challenge.b64, or download it from the GitHub release."""
    if CHALLENGE.is_file() and CHALLENGE.stat().st_size > 0:
        return None
    print(f"downloading {CHALLENGE_URL}", flush=True)
    try:
        urllib.request.urlretrieve(CHALLENGE_URL, CHALLENGE)
    except OSError as exc:
        return f"missing challenge.b64 ({exc})"
    if not CHALLENGE.is_file() or CHALLENGE.stat().st_size == 0:
        return "missing challenge.b64 (empty download)"
    return None


def solution_bytes(path: Path) -> int:
    """Whole folder except the Dockerfile. Everything else counts."""
    total = 0
    root = path.resolve()
    for p in root.rglob("*"):
        if not p.is_file() and not p.is_symlink():
            continue
        if p.name.lower() == "dockerfile":
            continue
        if ".git" in p.parts:
            continue
        if p.suffix == ".pyc" or "__pycache__" in p.parts:
            continue
        try:
            total += p.stat().st_size
        except OSError:
            total += p.lstat().st_size
    return total


def image_tag(name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "-", name).strip("-").lower() or "sol"
    return f"ujc-{safe}"


def tail(text: str) -> str:
    lines = [ln for ln in text.strip().splitlines() if ln.strip()]
    return " | ".join(lines[-3:]) if lines else ""


def docker(args: list[str], timeout: int, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args],
        cwd=cwd,
        timeout=timeout,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def build_image(sol_dir: Path, tag: str) -> tuple[str | None, float]:
    t0 = time.monotonic()
    try:
        proc = docker(
            ["build", "--network", "none", "--pull=false", "-t", tag, "."],
            timeout=BUILD_TIMEOUT,
            cwd=sol_dir,
        )
    except subprocess.TimeoutExpired:
        return f"build: timeout ({BUILD_TIMEOUT}s)", BUILD_TIMEOUT
    except OSError as exc:
        return f"build: {exc}", 0.0
    elapsed = time.monotonic() - t0
    if proc.returncode != 0:
        hint = tail(proc.stdout or "") or f"exit {proc.returncode}"
        return f"build: {hint}", elapsed
    return None, elapsed


def run_phase(tag: str, args: list[str], work: Path, label: str) -> tuple[str | None, float]:
    uid, gid = os.getuid(), os.getgid()
    name = f"{tag}-{label}-{os.getpid()}"
    cmd = [
        "run", "--name", name, "--rm", "--network", "none",
        "--user", f"{uid}:{gid}",
        "-v", f"{work}:/data",
        tag, *args,
    ]
    t0 = time.monotonic()
    try:
        proc = docker(cmd, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return f"{label}: timeout ({TIMEOUT}s)", TIMEOUT
    except OSError as exc:
        return f"{label}: {exc}", 0.0
    elapsed = time.monotonic() - t0
    if proc.returncode != 0:
        hint = tail(proc.stdout or "") or f"exit {proc.returncode}"
        return f"{label}: {hint}", elapsed
    return None, elapsed


def drop_image(tag: str) -> None:
    subprocess.run(["docker", "rmi", "-f", tag],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def clone_repo(url: str, branch: str | None, dest: Path) -> tuple[str | None, float]:
    ssh = re.match(r"^git@([^:]+):(.+)$", url)
    if ssh:
        url = f"https://{ssh.group(1)}/{ssh.group(2)}"
    if not url.startswith("https://"):
        return "clone: only https:// URLs", 0.0
    cmd = ["git", "clone", "--depth", "1", "--quiet"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [url, str(dest)]
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            cmd, timeout=CLONE_TIMEOUT,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
    except subprocess.TimeoutExpired:
        return f"clone: timeout ({CLONE_TIMEOUT}s)", CLONE_TIMEOUT
    except OSError as exc:
        return f"clone: {exc}", 0.0
    elapsed = time.monotonic() - t0
    if proc.returncode != 0:
        hint = tail(proc.stdout or "") or f"exit {proc.returncode}"
        return f"clone: {hint}", elapsed
    return None, elapsed


def prepare(entry: dict, tmp: Path) -> tuple[Path | None, str | None, float]:
    """Return (dir to build, error, seconds spent cloning)."""
    name = entry.get("name") or "?"
    sub = entry.get("dir") or "."
    if entry.get("path"):
        src = (ROOT / entry["path"]).resolve()
        if not src.is_dir():
            return None, f"path not found: {entry['path']}", 0.0
        built = (src / sub).resolve()
        if built != src and src not in built.parents:
            return None, "dir escapes the solution path", 0.0
        return built, None, 0.0
    url = entry.get("repository")
    if not url:
        return None, "no repository or path", 0.0
    dest = tmp / image_tag(str(name))
    err, elapsed = clone_repo(str(url), entry.get("branch"), dest)
    if err:
        return None, err, elapsed
    built = (dest / sub).resolve()
    if built != dest and dest not in built.parents:
        return None, "dir escapes the cloned repo", 0.0
    return built, None, elapsed


def grade(sol_dir: Path, name: str | None = None) -> dict:
    code = solution_bytes(sol_dir)
    row = {
        "name": name or sol_dir.name,
        "code": code,
        "compressed": None,
        "score": None,
        "time": 0.0,
        "status": "ok",
    }
    if not (sol_dir / "Dockerfile").is_file():
        row["status"] = "no Dockerfile"
        return row
    if not shutil.which("docker"):
        row["status"] = "docker not installed"
        return row

    tag = image_tag(row["name"])
    err, t_b = build_image(sol_dir, tag)
    row["time"] += t_b
    if err:
        row["status"] = err
        return row

    target = hashlib.sha256(CHALLENGE.read_bytes()).digest()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            src = work / "in.b64"
            out = work / "output.out"
            back = work / "restored.b64"
            shutil.copy2(CHALLENGE, src)
            err, t_c = run_phase(tag, ["--compress", "/data/in.b64", "/data/output.out"],
                                 work, "compress")
            row["time"] += t_c
            if err:
                row["status"] = err
                return row
            if not out.is_file():
                row["status"] = "compress: no /data/output.out"
                return row
            row["compressed"] = out.stat().st_size
            err, t_d = run_phase(tag, ["--decompress", "/data/output.out", "/data/restored.b64"],
                                 work, "decompress")
            row["time"] += t_d
            if err:
                row["status"] = err
                return row
            if not back.is_file():
                row["status"] = "decompress: no /data/restored.b64"
                return row
            got = hashlib.sha256(back.read_bytes()).digest()
            if got != target or back.stat().st_size != CHALLENGE.stat().st_size:
                row["status"] = "round-trip mismatch"
                return row
    finally:
        drop_image(tag)

    row["score"] = row["compressed"] + code
    return row


def write_scoreboard(rows: list[dict]) -> None:
    ok = sorted((r for r in rows if r["status"] == "ok"), key=lambda r: r["score"])
    bad = sorted((r for r in rows if r["status"] != "ok"), key=lambda r: r["name"])
    lines = [
        "# Scoreboard",
        "",
        f"Lower is better. `score = compressed + folder` (Dockerfile not counted). "
        f"Timeout is {TIMEOUT}s per run, {BUILD_TIMEOUT}s for the image build. "
        f"Build and run have no network.",
        "",
        "| # | name | score | compressed | code | time | status |",
        "|---|------|------:|-----------:|-----:|-----:|--------|",
    ]
    for i, r in enumerate(ok, 1):
        lines.append(
            f"| {i} | {r['name']} | {human(r['score'])} "
            f"| {human(r['compressed'])} | {human(r['code'])} "
            f"| {r['time']:.1f}s | ok |"
        )
    for r in bad:
        lines.append(
            f"| — | {r['name']} | — | — | {human(r['code'])} "
            f"| {r['time']:.1f}s | {r['status']} |"
        )
    lines.append("")
    SCOREBOARD.write_text("\n".join(lines))


def main() -> int:
    err = ensure_challenge()
    if err:
        sys.stderr.write(f"{err}\n")
        return 1
    if not PARTICIPANTS.is_file():
        sys.stderr.write(f"missing {PARTICIPANTS}\n")
        return 1
    try:
        people = json.loads(PARTICIPANTS.read_text())
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"participants.json: {exc}\n")
        return 1
    if not isinstance(people, list):
        sys.stderr.write("participants.json must be a list\n")
        return 1
    rows = []
    for entry in people:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "?")
        print(f"grading {name} ...", flush=True)
        with tempfile.TemporaryDirectory() as tmp:
            sol, err, t_clone = prepare(entry, Path(tmp))
            if err:
                row = {"name": name, "code": 0, "compressed": None,
                       "score": None, "time": t_clone, "status": err}
            else:
                row = grade(sol, name=name)
                row["time"] += t_clone
        rows.append(row)
        if row["status"] == "ok":
            print(f"  score {row['score']:,}  ({row['time']:.1f}s)", flush=True)
        else:
            print(f"  fail  {row['status']}", flush=True)
    if os.environ.get("GITHUB_ACTIONS"):
        write_scoreboard(rows)
        print(f"wrote {SCOREBOARD.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
