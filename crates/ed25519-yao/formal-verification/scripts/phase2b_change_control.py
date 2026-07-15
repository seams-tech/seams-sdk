#!/usr/bin/env python3
"""Fail-closed change control for the Phase 2B external-evidence checkpoint."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Sequence


SCHEMA: Final = "seams:router-ab:ed25519-yao:phase2b-change-control:v2"
ZERO_COMMIT: Final = "0" * 40
COMMIT_RE: Final = re.compile(r"[0-9a-f]{40}\Z")
OBJECT_ID_RE: Final = re.compile(rb"[0-9a-f]{40}\Z")
MAX_GIT_OUTPUT_BYTES: Final = 1_048_576
MAX_GIT_STDERR_BYTES: Final = 65_536

EVIDENCE_PATHS: Final = (
    "crates/ed25519-yao/formal-verification/review/phase2b-cryptographic-review-v1.md",
    "crates/ed25519-yao/formal-verification/review/phase2b-independent-host-reproduction-v1.json",
    "crates/ed25519-yao/formal-verification/review/phase2b-review-approval-v1.json",
    "crates/ed25519-yao/formal-verification/review/phase2b-review-subject-v1.json",
)

EXACT_COVERED_PATHS: Final = frozenset(
    {
        ".github/workflows/phase2b-change-control.yml",
        "docs/yaos-ab.md",
        "justfile",
    }
)
COVERED_PREFIXES: Final = (
    ".cargo/",
    "crates/ed25519-yao/",
    "tools/ed25519-yao-generator/",
    "tools/ed25519-yao-verifier/",
)


class ChangeControlError(Exception):
    """An invalid invocation, repository state, or checkpoint transition."""


@dataclass(frozen=True)
class GitResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class StreamCapture:
    data: bytes
    overflow: bool


def _hardened_git_environment() -> dict[str, str]:
    environment: dict[str, str] = {}
    for name in ("PATH", "TMPDIR"):
        value = os.environ.get(name)
        if value is not None:
            environment[name] = value

    environment.update(
        {
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_LITERAL_PATHSPECS": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_COUNT": "4",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": "false",
            "GIT_CONFIG_KEY_1": "core.untrackedCache",
            "GIT_CONFIG_VALUE_1": "false",
            "GIT_CONFIG_KEY_2": "core.attributesFile",
            "GIT_CONFIG_VALUE_2": os.devnull,
            "GIT_CONFIG_KEY_3": "core.excludesFile",
            "GIT_CONFIG_VALUE_3": os.devnull,
        }
    )
    return environment


def _capture_stream(
    stream: object,
    limit: int,
    process: subprocess.Popen[bytes],
    captures: list[StreamCapture],
    index: int,
) -> None:
    data = bytearray()
    overflow = False
    while True:
        chunk = stream.read(min(65_536, limit + 1 - len(data)))  # type: ignore[attr-defined]
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > limit:
            overflow = True
            process.kill()
            break
    captures[index] = StreamCapture(bytes(data[:limit]), overflow)


def _run_git(
    arguments: Sequence[str],
    *,
    root: Path | None = None,
    allowed_returncodes: frozenset[int] = frozenset({0}),
    stdout_limit: int = MAX_GIT_OUTPUT_BYTES,
) -> GitResult:
    command = ["git"]
    if root is not None:
        command.extend(("-C", os.fspath(root)))
    command.extend(arguments)

    try:
        process = subprocess.Popen(
            command,
            env=_hardened_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise ChangeControlError("unable to execute hardened Git") from error

    if process.stdout is None or process.stderr is None:
        process.kill()
        raise ChangeControlError("unable to capture hardened Git output")

    captures = [StreamCapture(b"", False), StreamCapture(b"", False)]
    stdout_thread = threading.Thread(
        target=_capture_stream,
        args=(process.stdout, stdout_limit, process, captures, 0),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_capture_stream,
        args=(process.stderr, MAX_GIT_STDERR_BYTES, process, captures, 1),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    returncode = process.wait()
    stdout_thread.join()
    stderr_thread.join()

    stdout_capture, stderr_capture = captures
    if stdout_capture.overflow or stderr_capture.overflow:
        raise ChangeControlError("hardened Git output exceeded its fixed bound")
    if returncode not in allowed_returncodes:
        raise ChangeControlError("hardened Git command failed")
    return GitResult(returncode, stdout_capture.data, stderr_capture.data)


def _parse_single_line(value: bytes, field: str) -> str:
    try:
        decoded = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise ChangeControlError(f"Git returned non-ASCII {field}") from error
    if not decoded.endswith("\n") or "\n" in decoded[:-1] or "\r" in decoded:
        raise ChangeControlError(f"Git returned malformed {field}")
    return decoded[:-1]


def _repository_root() -> Path:
    result = _run_git(("rev-parse", "--show-toplevel"))
    root_text = _parse_single_line(result.stdout, "repository root")
    root = Path(root_text)
    if not root.is_absolute():
        raise ChangeControlError("Git returned a non-absolute repository root")
    return root


def _require_commit(root: Path, expression: str, field: str) -> str:
    resolved = _parse_single_line(
        _run_git(("rev-parse", "--verify", expression), root=root).stdout,
        field,
    )
    if COMMIT_RE.fullmatch(resolved) is None:
        raise ChangeControlError(f"Git returned malformed {field}")
    object_type = _parse_single_line(
        _run_git(("cat-file", "-t", resolved), root=root).stdout,
        f"{field} object type",
    )
    if object_type != "commit":
        raise ChangeControlError(f"{field} is not a commit")
    return resolved


def _require_clean_checkout(root: Path) -> None:
    status = _run_git(
        ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
        root=root,
    ).stdout
    if status:
        raise ChangeControlError("HEAD checkout is not clean")


def _require_ancestor(root: Path, ancestor: str, descendant: str) -> None:
    result = _run_git(
        ("merge-base", "--is-ancestor", ancestor, descendant),
        root=root,
        allowed_returncodes=frozenset({0, 1}),
        stdout_limit=0,
    )
    if result.returncode != 0 or result.stdout or result.stderr:
        raise ChangeControlError("base commit is not an ancestor of the checked transition")


def _parse_nul_paths(raw: bytes, field: str) -> tuple[str, ...]:
    if raw == b"":
        return ()
    if not raw.endswith(b"\0"):
        raise ChangeControlError(f"Git returned malformed {field}")
    paths: list[str] = []
    for encoded_path in raw[:-1].split(b"\0"):
        if not encoded_path:
            raise ChangeControlError(f"Git returned malformed {field}")
        try:
            paths.append(encoded_path.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise ChangeControlError(f"Git returned a non-UTF-8 {field}") from error
    return tuple(paths)


def _classify_evidence(root: Path, commit: str) -> str:
    raw = _run_git(
        ("ls-tree", "-z", "--full-tree", commit, "--", *EVIDENCE_PATHS),
        root=root,
    ).stdout
    if raw and not raw.endswith(b"\0"):
        raise ChangeControlError("Git returned malformed evidence tree entries")

    present_paths: list[str] = []
    for entry in raw[:-1].split(b"\0") if raw else ():
        try:
            metadata, encoded_path = entry.split(b"\t", 1)
            metadata_parts = metadata.split(b" ")
        except ValueError as error:
            raise ChangeControlError("Git returned malformed evidence tree entries") from error
        if (
            len(metadata_parts) != 3
            or metadata_parts[0] != b"100644"
            or metadata_parts[1] != b"blob"
            or OBJECT_ID_RE.fullmatch(metadata_parts[2]) is None
            or metadata_parts[2] == b"0" * 40
        ):
            raise ChangeControlError("Git returned malformed evidence tree entries")
        try:
            path = encoded_path.decode("ascii")
        except UnicodeDecodeError as error:
            raise ChangeControlError("Git returned non-ASCII evidence path") from error
        if path not in EVIDENCE_PATHS or path in present_paths:
            raise ChangeControlError("Git returned unexpected evidence tree entries")
        present_paths.append(path)

    count = len(present_paths)
    if count == 0:
        return "absent"
    if count == len(EVIDENCE_PATHS):
        return "complete"
    raise ChangeControlError("Phase 2B evidence set is partial")


def _is_covered(path: str) -> bool:
    return (
        path in EVIDENCE_PATHS
        or path in EXACT_COVERED_PATHS
        or any(path.startswith(prefix) for prefix in COVERED_PREFIXES)
    )


def _covered_change(root: Path, base: str, head: str) -> bool:
    if base == ZERO_COMMIT:
        raw_paths = _run_git(
            ("ls-tree", "-r", "-z", "--name-only", "--full-tree", head),
            root=root,
        ).stdout
    else:
        raw_paths = _run_git(
            ("diff", "--name-only", "-z", "--no-renames", base, head, "--"),
            root=root,
        ).stdout
    return any(_is_covered(path) for path in _parse_nul_paths(raw_paths, "changed paths"))


def _sole_parent(root: Path, head: str) -> str:
    raw_commit = _run_git(
        ("cat-file", "commit", head),
        root=root,
        stdout_limit=MAX_GIT_OUTPUT_BYTES,
    ).stdout
    header, separator, _message = raw_commit.partition(b"\n\n")
    if not separator:
        raise ChangeControlError("HEAD has a malformed raw commit object")
    parents = [line[7:] for line in header.split(b"\n") if line.startswith(b"parent ")]
    try:
        parent = parents[0].decode("ascii") if len(parents) == 1 else ""
    except UnicodeDecodeError as error:
        raise ChangeControlError("HEAD evidence commit has a non-ASCII parent") from error
    if len(parents) != 1 or COMMIT_RE.fullmatch(parent) is None:
        raise ChangeControlError("HEAD evidence commit must have exactly one valid parent")
    return parent


def _require_exact_evidence_diff(root: Path, candidate: str, evidence: str) -> None:
    raw = _run_git(
        (
            "diff-tree",
            "--raw",
            "-z",
            "-r",
            "--no-renames",
            "--full-index",
            candidate,
            evidence,
        ),
        root=root,
        stdout_limit=MAX_GIT_OUTPUT_BYTES,
    ).stdout
    if not raw.endswith(b"\0"):
        raise ChangeControlError("Git returned malformed raw evidence diff")
    fields = raw[:-1].split(b"\0")
    if len(fields) != len(EVIDENCE_PATHS) * 2:
        raise ChangeControlError("evidence commit must add exactly four paths")

    observed_paths: list[str] = []
    expected_header = re.compile(
        rb":000000 100644 0{40} ([0-9a-f]{40}) A\Z"
    )
    for index in range(0, len(fields), 2):
        header = fields[index]
        encoded_path = fields[index + 1]
        match = expected_header.fullmatch(header)
        if match is None or match.group(1) == b"0" * 40:
            raise ChangeControlError("evidence diff contains a non-regular or non-addition entry")
        try:
            observed_paths.append(encoded_path.decode("ascii"))
        except UnicodeDecodeError as error:
            raise ChangeControlError("evidence diff contains a non-ASCII path") from error

    if tuple(observed_paths) != EVIDENCE_PATHS:
        raise ChangeControlError("evidence diff paths are not the exact ordered fixed set")


def _verify_required_checkpoint(root: Path, base: str, head: str) -> str:
    candidate = _sole_parent(root, head)
    if base != ZERO_COMMIT:
        _require_ancestor(root, base, candidate)
    _require_exact_evidence_diff(root, candidate, head)
    return candidate


def evaluate_change_control(base: str) -> dict[str, object]:
    if COMMIT_RE.fullmatch(base) is None:
        raise ChangeControlError("base commit must be exactly forty lowercase hexadecimal digits")

    root = _repository_root()
    head = _require_commit(root, "HEAD", "HEAD commit")
    _require_clean_checkout(root)

    if base == ZERO_COMMIT:
        base_evidence = "absent"
    else:
        resolved_base = _require_commit(root, base, "base commit")
        if resolved_base != base:
            raise ChangeControlError("base commit did not resolve to itself")
        _require_ancestor(root, base, head)
        base_evidence = _classify_evidence(root, base)

    head_evidence = _classify_evidence(root, head)
    covered_change = _covered_change(root, base, head)

    if base_evidence == "complete" and head_evidence == "absent":
        raise ChangeControlError("a complete evidence checkpoint cannot disappear")

    external_verification_required = head_evidence == "complete" and (
        base_evidence == "absent" or covered_change
    )
    if base_evidence == "complete" and covered_change and head_evidence != "complete":
        raise ChangeControlError("covered descendants require a complete replacement checkpoint")

    result: dict[str, object] = {
        "schema": SCHEMA,
        "base_evidence": base_evidence,
        "head_evidence": head_evidence,
        "covered_change": covered_change,
        "external_verification_required": external_verification_required,
    }
    if external_verification_required:
        candidate = _verify_required_checkpoint(root, base, head)
        result["candidate_commit"] = candidate
        result["evidence_commit"] = head
    return result


def _main(arguments: Sequence[str]) -> int:
    if len(arguments) != 2:
        print(
            "phase2b change-control failed: expected exactly one base commit",
            file=sys.stderr,
        )
        return 2
    try:
        result = evaluate_change_control(arguments[1])
    except ChangeControlError as error:
        print(f"phase2b change-control failed: {error}", file=sys.stderr)
        return 1
    sys.stdout.write(json.dumps(result, separators=(",", ":"), ensure_ascii=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
