from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from dia2_batch import Dia2PlanError, load_plan


class Dia2BatchPlanTest(unittest.TestCase):
    def test_parses_ordered_subject_disjoint_generation_plan(self) -> None:
        plan = load_value(valid_plan())

        self.assertEqual(plan.dataset_version, "voiceid-synthetic-2026-07")
        self.assertEqual(len(plan.jobs), 2)
        self.assertEqual(plan.jobs[1].prefix.kind, "generated_fixture")

    def test_rejects_generated_prefix_that_has_not_been_created(self) -> None:
        value = valid_plan()
        value["jobs"].reverse()

        with self.assertRaisesRegex(Dia2PlanError, "must appear before"):
            load_value(value)

    def test_rejects_conditioning_without_consented_prefix(self) -> None:
        value = valid_plan()
        value["jobs"][1]["conditioning"] = {
            "sourceSubjectId": "owner",
            "consentReference": "consent_owner_2026_07",
            "retentionClass": "project_indefinite",
        }

        with self.assertRaisesRegex(Dia2PlanError, "allowed only for consented audio"):
            load_value(value)

    def test_rejects_subject_crossing_frozen_partitions(self) -> None:
        value = valid_plan()
        value["jobs"][1]["partition"] = "evaluation"

        with self.assertRaisesRegex(Dia2PlanError, "crosses"):
            load_value(value)


def load_value(value: dict[str, object]):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "plan.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return load_plan(path)


def valid_plan() -> dict[str, object]:
    return {
        "schemaVersion": "voice_id_dia2_generation_plan_v1",
        "datasetVersion": "voiceid-synthetic-2026-07",
        "repositoryRevision": "8687268f4ed3ed20704638fd353b51491de3b476",
        "checkpoint": {
            "repoId": "nari-labs/Dia2-1B",
            "revision": "00042629c61c3268a6473552c911966ec7a5a450",
            "mimiRepoId": "kyutai/mimi",
            "mimiRevision": "89091b3e466eb6a9d11e537bf26b144f194978f7",
        },
        "settings": {
            "dtype": "bfloat16",
            "textTemperature": 0.6,
            "textTopK": 50,
            "audioTemperature": 0.8,
            "audioTopK": 50,
            "cfgScale": 2.0,
            "useCudaGraph": True,
        },
        "capture": {
            "platform": "server",
            "microphone": "digital_generation",
            "room": "none",
            "distanceCm": 0,
            "codec": "pcm_s16le",
            "channelCount": 1,
            "language": "en",
            "accent": "synthetic",
            "noiseProfile": "none",
        },
        "jobs": [
            {
                "fixtureId": "dia2_dev_enrollment",
                "audioFileName": "dia2_dev_enrollment.wav",
                "subjectId": "dia2_dev_subject",
                "sessionId": "dia2_dev_enrollment_session",
                "partition": "development",
                "case": {"kind": "enrollment"},
                "expectedIntent": None,
                "challengeTokens": [],
                "seed": 101,
                "script": "[S1] Cedar compass. River lantern. Harbor sunrise. Silver meadow.",
                "prefix": {"kind": "none"},
                "voice": "dia2_dev_voice",
                "conditioning": None,
            },
            {
                "fixtureId": "dia2_dev_genuine",
                "audioFileName": "dia2_dev_genuine.wav",
                "subjectId": "dia2_dev_subject",
                "sessionId": "dia2_dev_genuine_session",
                "partition": "development",
                "case": {"kind": "genuine_verification"},
                "expectedIntent": "approve",
                "challengeTokens": ["amber", "seven", "kite"],
                "seed": 102,
                "script": "[S1] I approve this request. Amber seven kite.",
                "prefix": {
                    "kind": "generated_fixture",
                    "fixtureId": "dia2_dev_enrollment",
                },
                "voice": "dia2_dev_voice",
                "conditioning": None,
            },
        ],
    }


if __name__ == "__main__":
    unittest.main()
