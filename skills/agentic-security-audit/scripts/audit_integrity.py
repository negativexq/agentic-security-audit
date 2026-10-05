"""Canonical audit bindings and read-only source snapshots; never run target code."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

ATTACK_CLASS_INVARIANTS = {
    "01": (1, 2, 10), "02": (2, 9, 10), "03": (1, 2),
    "04": (5, 11), "05": (5, 11), "06": (5, 6), "07": (7, 8),
    "08": (2, 3, 4, 11), "09": (3, 11), "10": (4, 2),
    "11": (1, 2, 9), "12": (2, 9, 10), "13": (2, 9),
    "14": (2, 9, 12), "15": (9, 10, 11), "16": (2, 9, 10),
    "17": (2, 9), "18": (9, 10), "19": (12,), "20": (10,),
}
ATTACK_CLASS_INVARIANTS = {key: {f"AGENT-INV-{n:03}" for n in values}
                           for key, values in ATTACK_CLASS_INVARIANTS.items()}
ALLEGATION_FIELDS = (
    "title", "invariant", "source", "control", "sink", "attacker", "principal",
    "execution_identity", "affected_resource", "boundary", "control_failure",
    "impact", "preconditions", "source_manifest_hash",
)
COVERAGE_FIELDS = ("subsystem", "boundary", "path_variant", "attack_class", "invariant")


def canonical_hash(value) -> str:
    """Project canonical JSON: sorted keys, compact UTF-8, no nonfinite numbers."""
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False,
                     separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def candidate_hash(candidate: dict) -> str:
    # Adjudication is the only mutable bookkeeping field; all allegations bind.
    return canonical_hash({k: v for k, v in candidate.items() if k != "status"})


def is_link(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024))


def source_files(root: Path, excluded_output: Path | None = None) -> dict:
    """Hash all regular working-tree files, including ignored/untracked files.

    Exclude only .git administration. Reject links/reparse points and special files
    rather than reading outside the source or blocking on devices. No Git filters.
    """
    if is_link(root):
        raise ValueError(f"Source root must not be a link/reparse point: {root}")
    files = {}
    for directory, names, filenames in os.walk(root, followlinks=False):
        base = Path(directory)
        names[:] = sorted(name for name in names if not (base == root and name == ".git")
                          and not (excluded_output and base / name == excluded_output))
        for name in names:
            if is_link(base / name):
                raise ValueError(f"Linked source directory is unsupported: {base / name}")
        for name in sorted(filenames):
            if base == root and name == ".git":
                continue
            path = base / name
            if is_link(path) or not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError(f"Non-regular source file is unsupported: {path}")
            before = path.stat()
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            after = path.stat()
            if (before.st_size, before.st_mtime_ns, before.st_ino) != (
                    after.st_size, after.st_mtime_ns, after.st_ino):
                raise ValueError(f"Source changed while hashing: {path}")
            files[path.relative_to(root).as_posix()] = {
                "sha256": digest.hexdigest(), "size": after.st_size}
    return dict(sorted(files.items()))


def git_identity(root: Path, files: dict) -> dict:
    identity = {"git_commit": None, "dirty": None, "diff_sha256": None}
    if not (root / ".git").exists():
        return identity
    git = shutil.which("git")
    if not git:
        raise ValueError("Git metadata exists but trusted host Git is unavailable")
    if Path(git).resolve().is_relative_to(root.resolve()):
        raise ValueError("Host Git executable must be outside untrusted source")
    # Host Git only, no inherited Git config/env, fsmonitor, pager, external diff
    # or textconv. Git is optional for plain source directories.
    env = {key: value for key, value in os.environ.items()
           if key in {"PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GIT_PAGER="cat")
    command = [git, "--no-pager", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
               "-c", "core.untrackedCache=false", "-c", "safe.directory=" + str(root), "-C", str(root)]

    def run(args):
        result = subprocess.run(command + args, env=env, capture_output=True, timeout=20)
        if result.returncode:
            raise ValueError("Cannot establish Git source identity with trusted host Git")
        return result.stdout

    identity["git_commit"] = run(["rev-parse", "--verify", "HEAD"]).decode("ascii").strip()
    algorithm = run(["rev-parse", "--show-object-format"]).decode("ascii").strip()
    if algorithm not in {"sha1", "sha256"}:
        raise ValueError("Unsupported Git object format")
    head = {}
    for entry in run(["ls-tree", "-r", "-z", "HEAD"]).split(b"\0"):
        if entry:
            info, raw_path = entry.split(b"\t", 1)
            mode, kind, oid = info.decode("ascii").split()
            path = raw_path.decode("utf-8")
            if any(part in {"..", "."} for part in path.split("/")) or Path(path).is_absolute():
                raise ValueError("Unsafe path in Git tree")
            head[path] = {"mode": mode, "oid": oid}
    # Worktree diff commands can invoke repository-defined clean filters even
    # with --no-ext-diff/--no-textconv. Use raw Git plumbing and hash bytes ourselves.
    delta = {}
    for path, entry in head.items():
        actual = files.get(path)
        oid = None
        if actual:
            digest = hashlib.new(algorithm)
            digest.update(f"blob {actual['size']}\0".encode("ascii"))
            with (root / path).open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            oid = digest.hexdigest()
        if oid != entry["oid"]:
            delta[path] = {"head": entry, "working_file": actual}
    index = {}
    for entry in run(["ls-files", "--stage", "-z"]).split(b"\0"):
        if entry:
            info, raw_path = entry.split(b"\t", 1)
            mode, oid, stage = info.decode("ascii").split()
            index.setdefault(raw_path.decode("utf-8"), []).append({"mode": mode, "oid": oid, "stage": stage})
    expected_index = {p: [{**entry, "stage": "0"}] for p, entry in head.items()}
    index_delta = {p: {"head": expected_index.get(p), "index": index.get(p)}
                   for p in sorted(head.keys() | index.keys()) if expected_index.get(p) != index.get(p)}
    untracked = run(["ls-files", "--others", "--exclude-standard", "-z"])
    identity["dirty"] = bool(delta or index_delta or untracked)
    identity["diff_sha256"] = canonical_hash({"tracked_byte_delta": delta, "index_delta": index_delta})
    return identity


def capture_source(root: Path, excluded_output: Path | None = None) -> dict:
    root = root.absolute()
    if not root.is_dir():
        raise ValueError(f"Source directory unavailable: {root}")
    files = source_files(root, excluded_output)
    identity = git_identity(root, files)
    if files != source_files(root, excluded_output) or identity != git_identity(root, files):
        raise ValueError("Source changed during snapshot capture")
    return {"schema_version": 1, "repository": str(root.resolve()),
            **identity, "files": files}


def check_output(root: Path, output: Path, allow_in_target: bool = False) -> None:
    root, output = root.resolve(), output.resolve()
    if output == root or root.is_relative_to(output):
        raise ValueError("Audit output must not contain or replace the source repository")
    if output.is_relative_to(root) and not allow_in_target:
        raise ValueError("Audit output is inside target; choose isolated output or explicitly use --allow-in-target-output")


def verify_source(manifest: dict, root: Path, output: Path | None = None) -> list[str]:
    """Recompute current source identity; output opt-in excludes only that run dir."""
    try:
        root = root.resolve()
        excluded = output.resolve() if output and output.resolve().is_relative_to(root) else None
        current = capture_source(root, excluded)
        expected = manifest["files"]
        actual = current["files"]
        if output and output.resolve().is_relative_to(root.resolve()):
            prefix = output.resolve().relative_to(root.resolve()).as_posix() + "/"
            actual = {k: v for k, v in actual.items() if not k.startswith(prefix)}
        errors = []
        if actual != expected:
            errors.append("source snapshot drift: files added, removed or changed")
        for key in ("git_commit", "diff_sha256"):
            if current[key] != manifest[key]:
                errors.append(f"source snapshot drift: {key}")
        # In-target output can itself make Git dirty; bytes and HEAD still bind.
        if not (output and output.resolve().is_relative_to(root.resolve())):
            if current["dirty"] != manifest["dirty"]:
                errors.append("source snapshot drift: dirty state")
        return errors
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return [str(error)]
