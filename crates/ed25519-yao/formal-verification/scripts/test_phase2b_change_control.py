#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("phase2b_change_control.py")
ZERO_COMMIT = "0" * 40
EVIDENCE_PATHS = (
    "crates/ed25519-yao/formal-verification/review/phase2b-cryptographic-review-v1.md",
    "crates/ed25519-yao/formal-verification/review/phase2b-independent-host-reproduction-v1.json",
    "crates/ed25519-yao/formal-verification/review/phase2b-review-approval-v1.json",
    "crates/ed25519-yao/formal-verification/review/phase2b-review-subject-v1.json",
)


class Repository:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.git("init", "-q")
        self.git("config", "user.name", "Phase 2B Test")
        self.git("config", "user.email", "phase2b@example.invalid")

    def git(self, *arguments: str) -> str:
        result = subprocess.run(
            ("git", "-C", os.fspath(self.root), *arguments),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout.strip()

    def write(self, path: str, contents: bytes) -> None:
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(contents)

    def remove(self, path: str) -> None:
        destination = self.root / path
        if destination.is_symlink() or destination.is_file():
            destination.unlink()

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def seed_candidate(self) -> str:
        self.write("README.md", b"candidate\n")
        return self.commit("candidate")

    def add_evidence(self, marker: bytes = b"evidence\n") -> None:
        for index, path in enumerate(EVIDENCE_PATHS):
            self.write(path, marker + str(index).encode("ascii") + b"\n")

    def remove_evidence(self) -> None:
        for path in EVIDENCE_PATHS:
            self.remove(path)


class Phase2bChangeControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.repository = Repository(Path(self.temporary_directory.name))

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def run_check(self, base: str, *extra_arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            (sys.executable, os.fspath(SCRIPT), base, *extra_arguments),
            cwd=self.repository.root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def require_success(self, base: str) -> dict[str, object]:
        result = self.run_check(base)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertTrue(result.stdout.endswith("\n"))
        self.assertEqual(result.stdout.count("\n"), 1)
        decoded = json.loads(result.stdout)
        self.assertEqual(
            result.stdout,
            json.dumps(decoded, separators=(",", ":"), ensure_ascii=True) + "\n",
        )
        return decoded

    def require_failure(self, base: str, *extra_arguments: str) -> None:
        result = self.run_check(base, *extra_arguments)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertTrue(result.stderr.startswith("phase2b change-control failed: "))

    def create_checkpoint(self, marker: bytes = b"evidence\n") -> tuple[str, str]:
        candidate = self.repository.seed_candidate()
        self.repository.add_evidence(marker)
        evidence = self.repository.commit("evidence")
        return candidate, evidence

    def test_zero_through_four_evidence_paths_are_classified_fail_closed(self) -> None:
        candidate = self.repository.seed_candidate()
        absent = self.require_success(ZERO_COMMIT)
        self.assertEqual(absent["base_evidence"], "absent")
        self.assertEqual(absent["head_evidence"], "absent")

        for count in range(1, 4):
            with self.subTest(count=count):
                self.repository.git("reset", "-q", "--hard", candidate)
                for path in EVIDENCE_PATHS[:count]:
                    self.repository.write(path, b"partial\n")
                self.repository.commit(f"partial {count}")
                self.require_failure(ZERO_COMMIT)

        self.repository.git("reset", "-q", "--hard", candidate)
        self.repository.add_evidence(b"complete\n")
        complete_head = self.repository.commit("complete")
        complete = self.require_success(ZERO_COMMIT)
        self.assertEqual(complete["head_evidence"], "complete")
        self.assertEqual(complete["evidence_commit"], complete_head)

    def test_pre_evidence_covered_and_uncovered_changes_are_informational(self) -> None:
        base = self.repository.seed_candidate()
        self.repository.write("notes/uncovered.txt", b"uncovered\n")
        self.repository.commit("uncovered")
        uncovered = self.require_success(base)
        self.assertFalse(uncovered["covered_change"])
        self.assertFalse(uncovered["external_verification_required"])

        self.repository.write("docs/router-ab/ed25519-yao/implementation-plan.md", b"covered\n")
        self.repository.commit("covered")
        covered = self.require_success(base)
        self.assertTrue(covered["covered_change"])
        self.assertFalse(covered["external_verification_required"])

    def test_exact_candidate_to_evidence_transition_requires_external_verification(self) -> None:
        candidate, evidence = self.create_checkpoint()
        result = self.require_success(candidate)
        self.assertEqual(
            result,
            {
                "schema": "seams:router-ab:ed25519-yao:phase2b-change-control:v2",
                "base_evidence": "absent",
                "head_evidence": "complete",
                "covered_change": True,
                "external_verification_required": True,
                "candidate_commit": candidate,
                "evidence_commit": evidence,
            },
        )

    def test_partial_base_and_partial_head_are_rejected(self) -> None:
        self.repository.seed_candidate()
        self.repository.write(EVIDENCE_PATHS[0], b"partial\n")
        partial_base = self.repository.commit("partial base")
        self.repository.write("notes/descendant.txt", b"descendant\n")
        self.repository.commit("partial descendant")
        self.require_failure(partial_base)

        self.repository.write(EVIDENCE_PATHS[1], b"partial\n")
        self.repository.commit("partial head")
        self.require_failure(ZERO_COMMIT)

    def test_extra_evidence_commit_path_is_rejected(self) -> None:
        candidate = self.repository.seed_candidate()
        self.repository.add_evidence()
        self.repository.write("unrelated-extra.txt", b"fifth change\n")
        self.repository.commit("evidence plus extra")
        self.require_failure(candidate)

    def test_wrong_evidence_mode_is_rejected(self) -> None:
        candidate = self.repository.seed_candidate()
        self.repository.add_evidence()
        symlink_path = self.repository.root / EVIDENCE_PATHS[0]
        symlink_path.unlink()
        symlink_path.symlink_to("phase2b-review-subject-v1.json")
        self.repository.commit("evidence with symlink")
        self.require_failure(candidate)

    def test_unrelated_descendant_keeps_historical_checkpoint(self) -> None:
        _candidate, evidence = self.create_checkpoint()
        self.repository.write("notes/unrelated.txt", b"unrelated\n")
        self.repository.commit("unrelated descendant")
        result = self.require_success(evidence)
        self.assertEqual(result["base_evidence"], "complete")
        self.assertEqual(result["head_evidence"], "complete")
        self.assertFalse(result["covered_change"])
        self.assertFalse(result["external_verification_required"])
        self.assertNotIn("candidate_commit", result)
        self.assertNotIn("evidence_commit", result)

    def test_covered_change_requires_two_commit_rereview(self) -> None:
        _old_candidate, old_evidence = self.create_checkpoint(b"old\n")
        self.repository.remove_evidence()
        self.repository.write("crates/ed25519-yao/src/lib.rs", b"covered change\n")
        new_candidate = self.repository.commit("new candidate")
        self.repository.add_evidence(b"new\n")
        new_evidence = self.repository.commit("new evidence")

        result = self.require_success(old_evidence)
        self.assertTrue(result["covered_change"])
        self.assertTrue(result["external_verification_required"])
        self.assertEqual(result["candidate_commit"], new_candidate)
        self.assertEqual(result["evidence_commit"], new_evidence)

    def test_complete_base_cannot_be_followed_by_absent_head(self) -> None:
        _candidate, evidence = self.create_checkpoint()
        self.repository.remove_evidence()
        self.repository.commit("remove evidence")
        self.require_failure(evidence)

    def test_covered_descendant_without_fresh_evidence_commit_is_rejected(self) -> None:
        _candidate, evidence = self.create_checkpoint()
        self.repository.write("justfile", b"covered change\n")
        self.repository.commit("covered descendant")
        self.require_failure(evidence)

    def test_dirty_checkout_and_invalid_arguments_are_rejected(self) -> None:
        self.repository.seed_candidate()
        self.repository.write("dirty.txt", b"dirty\n")
        self.require_failure(ZERO_COMMIT)
        self.repository.remove("dirty.txt")
        self.require_failure("A" * 40)
        self.require_failure(ZERO_COMMIT, ZERO_COMMIT)

    def test_nonancestor_base_is_rejected(self) -> None:
        base = self.repository.seed_candidate()
        self.repository.git("checkout", "-q", "--orphan", "other")
        self.repository.git("rm", "-q", "-rf", ".")
        self.repository.write("other.txt", b"other history\n")
        self.repository.commit("other root")
        result = self.run_check(base)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("base commit is not an ancestor", result.stderr)

    def test_workflow_freezes_the_non_authoritative_staging_boundary(self) -> None:
        repository_root = SCRIPT.parents[4]
        workflow = (
            repository_root / ".github/workflows/phase2b-change-control.yml"
        ).read_text(encoding="utf-8")
        for required in (
            "name: Ed25519 Yao Phase 2B evidence staging",
            "name: Phase 2B evidence-shape staging check",
            "persist-credentials: false",
            "fetch-depth: 0",
            "external_verification_required",
            "GitHub is not the Phase 2 release authority",
        ):
            with self.subTest(required=required):
                self.assertIn(required, workflow)
        for forbidden in (
            "pull_request_target:",
            "workflow_run:",
            "actions/cache",
            "persist-credentials: true",
            "environment:",
            "self-hosted",
            "ED25519_YAO_PHASE2B_REVIEW_POLICY_JSON",
            "ED25519_YAO_PHASE2B_REVIEW_POLICY_SHA256",
            "ED25519_YAO_PHASE2B_REPRODUCTION_CHALLENGE_HEX",
            "phase2b-protected-inputs-check",
            "phase2b-independent-host-record-check",
            "phase2b-review-approval-check",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)


if __name__ == "__main__":
    unittest.main()
