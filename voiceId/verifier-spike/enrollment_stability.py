from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

VERIFIER_ROOT = Path(__file__).resolve().parents[1] / "verifier"
if str(VERIFIER_ROOT) not in sys.path:
    sys.path.insert(0, str(VERIFIER_ROOT))

from voiceid_verifier.audio_quality import SpeechWindow  # noqa: E402
from voiceid_verifier.embeddings import ExtractedSpeakerEmbedding  # noqa: E402
from voiceid_verifier.enrollment import (  # noqa: E402
    MINIMUM_LEAVE_ONE_OUT_STABILITY,
    aggregate_template,
)
from voiceid_verifier.audio_decode import zero_float_sequence  # noqa: E402
from voiceid_verifier.scoring import cosine_score  # noqa: E402


SCHEMA_VERSION = "voice_id_enrollment_stability_input_v1"
REPORT_SCHEMA_VERSION = "voice_id_enrollment_stability_report_v1"
MINIMUM_DURATION_MS = 12_000
TARGET_DURATION_MS = 18_000
MAXIMUM_DURATION_MS = 30_000
MINIMUM_PROMPT_COUNT = 4
MINIMUM_SPEECH_PER_PROMPT_MS = 2_000
MINIMUM_WINDOWS = 4


class EnrollmentStabilityError(ValueError):
    pass


def evaluate_stability(input_path: Path, output_path: Path) -> dict[str, Any]:
    input_file = input_path.expanduser().resolve()
    value = read_object(input_file)
    if value.get("schemaVersion") != SCHEMA_VERSION:
        raise EnrollmentStabilityError(f"schemaVersion must be {SCHEMA_VERSION}")
    subject_id = require_string(value, "subjectId")
    raw_sessions = value.get("sessions")
    if not isinstance(raw_sessions, list) or len(raw_sessions) < 3:
        raise EnrollmentStabilityError("at least three enrollment sessions are required")
    sessions = tuple(parse_session(session, index) for index, session in enumerate(raw_sessions))
    session_ids = [session["sessionId"] for session in sessions]
    if len(set(session_ids)) != len(session_ids):
        raise EnrollmentStabilityError("sessionId values must be unique")
    days = {session["capturedAt"][:10] for session in sessions}
    if len(days) < 3:
        raise EnrollmentStabilityError("sessions must span at least three capture days")

    session_results: list[dict[str, Any]] = []
    templates: list[list[float]] = []
    try:
        for session in sessions:
            windows = tuple(
                SpeechWindow(
                    start_ms=index * 600,
                    end_ms=(index * 600) + window["speechMs"],
                    speech_ms=window["speechMs"],
                    signal_score=window["signalScore"],
                    samples=[],
                )
                for index, window in enumerate(session["windows"])
            )
            embeddings = [
                ExtractedSpeakerEmbedding(vector=list(window["embedding"]), speaker_label="unknown_speaker")
                for window in session["windows"]
            ]
            aggregation = aggregate_template(windows, embeddings)
            template = list(aggregation.embedding)
            templates.append(template)
            session_results.append(
                {
                    "sessionId": session["sessionId"],
                    "capturedAt": session["capturedAt"],
                    "durationMs": session["durationMs"],
                    "usableSpeechMs": session["usableSpeechMs"],
                    "promptCoverage": session["promptCoverage"],
                    "windowCount": len(session["windows"]),
                    "minimumLeaveOneOutSimilarity": round(
                        aggregation.minimum_leave_one_out_similarity, 6
                    ),
                    "stable": session_is_stable(session, aggregation.minimum_leave_one_out_similarity),
                }
            )
            zero_float_sequence(aggregation.embedding)
            for embedding in embeddings:
                zero_float_sequence(embedding.vector)
    except Exception as error:
        for template in templates:
            zero_float_sequence(template)
        if isinstance(error, EnrollmentStabilityError):
            raise
        raise EnrollmentStabilityError(f"failed to aggregate enrollment session: {error}") from error

    similarities = [
        cosine_score(left, right)
        for index, left in enumerate(templates)
        for right in templates[index + 1 :]
    ]
    for template in templates:
        zero_float_sequence(template)
    if len(similarities) == 0:
        raise EnrollmentStabilityError("at least two session templates are required")
    reliable_sessions = [
        result for result in session_results if result["stable"]
    ]
    reliable_durations = [result["durationMs"] for result in reliable_sessions]
    shortest_reliable = min(reliable_durations) if reliable_durations else None
    report = {
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "inputSha256": sha256_file(input_file),
        "subjectId": subject_id,
        "sessionCount": len(sessions),
        "captureDayCount": len(days),
        "sessions": session_results,
        "crossSessionSimilarity": {
            "minimum": round(min(similarities), 6),
            "p50": round(percentile(sorted(similarities), 0.5), 6),
            "pairs": len(similarities),
        },
        "shortestReliableDurationMs": shortest_reliable,
        "requirements": {
            "minimumDurationMs": MINIMUM_DURATION_MS,
            "targetDurationMs": TARGET_DURATION_MS,
            "maximumDurationMs": MAXIMUM_DURATION_MS,
            "minimumPromptCount": MINIMUM_PROMPT_COUNT,
            "minimumSpeechPerPromptMs": MINIMUM_SPEECH_PER_PROMPT_MS,
            "minimumWindows": MINIMUM_WINDOWS,
            "minimumPromptCoverage": 1.0,
            "minimumLeaveOneOutStability": MINIMUM_LEAVE_ONE_OUT_STABILITY,
            "maximumQualityRetries": 1,
        },
        "reliable": (
            len(reliable_sessions) == len(sessions)
            and all(result["durationMs"] <= MAXIMUM_DURATION_MS for result in session_results)
            and min(similarities) >= MINIMUM_LEAVE_ONE_OUT_STABILITY
        ),
    }
    write_json(output_path.expanduser().resolve(), report)
    return report


def parse_session(value: object, index: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EnrollmentStabilityError(f"sessions[{index}] must be an object")
    session_id = require_string(value, "sessionId")
    captured_at = require_string(value, "capturedAt")
    require_iso_date_time(captured_at)
    duration_ms = require_positive_int(value, "durationMs")
    usable_speech_ms = require_positive_int(value, "usableSpeechMs")
    prompt_count = require_positive_int(value, "promptCount")
    prompt_coverage = require_probability(value, "promptCoverage")
    windows = value.get("windows")
    if not isinstance(windows, list) or len(windows) < MINIMUM_WINDOWS:
        raise EnrollmentStabilityError(
            f"session {session_id} requires at least {MINIMUM_WINDOWS} windows"
        )
    if prompt_count < MINIMUM_PROMPT_COUNT:
        raise EnrollmentStabilityError(f"session {session_id} has too few prompts")
    if usable_speech_ms < prompt_count * MINIMUM_SPEECH_PER_PROMPT_MS:
        raise EnrollmentStabilityError(f"session {session_id} has insufficient usable speech")
    return {
        "sessionId": session_id,
        "capturedAt": captured_at,
        "durationMs": duration_ms,
        "usableSpeechMs": usable_speech_ms,
        "promptCount": prompt_count,
        "promptCoverage": prompt_coverage,
        "windows": tuple(parse_window(window, index) for index, window in enumerate(windows)),
    }


def parse_window(value: object, index: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EnrollmentStabilityError(f"window {index} must be an object")
    speech_ms = require_positive_int(value, "speechMs")
    signal_score = require_probability(value, "signalScore")
    embedding = value.get("embedding")
    if not isinstance(embedding, list) or len(embedding) == 0:
        raise EnrollmentStabilityError("window embedding must be non-empty")
    if not all(isinstance(item, int | float) and not isinstance(item, bool) for item in embedding):
        raise EnrollmentStabilityError("window embedding values must be numbers")
    return {
        "speechMs": speech_ms,
        "signalScore": signal_score,
        "embedding": tuple(float(item) for item in embedding),
    }


def session_is_stable(session: dict[str, Any], leave_one_out: float) -> bool:
    return (
        MINIMUM_DURATION_MS <= session["durationMs"] <= MAXIMUM_DURATION_MS
        and session["promptCount"] >= MINIMUM_PROMPT_COUNT
        and session["promptCoverage"] >= 1.0
        and session["usableSpeechMs"] >= session["promptCount"] * MINIMUM_SPEECH_PER_PROMPT_MS
        and len(session["windows"]) >= MINIMUM_WINDOWS
        and leave_one_out >= MINIMUM_LEAVE_ONE_OUT_STABILITY
    )


def percentile(values: list[float], quantile: float) -> float:
    if len(values) == 1:
        return values[0]
    position = (len(values) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    return values[lower] + (values[upper] - values[lower]) * (position - lower)


def read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EnrollmentStabilityError(f"failed to read input: {error}") from error
    if not isinstance(value, dict):
        raise EnrollmentStabilityError("input must be an object")
    return value


def require_string(data: dict[str, Any], field_name: str) -> str:
    value = data.get(field_name)
    if not isinstance(value, str) or value.strip() == "":
        raise EnrollmentStabilityError(f"{field_name} must be a non-empty string")
    return value


def require_positive_int(data: dict[str, Any], field_name: str) -> int:
    value = data.get(field_name)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise EnrollmentStabilityError(f"{field_name} must be a positive integer")
    return value


def require_probability(data: dict[str, Any], field_name: str) -> float:
    value = data.get(field_name)
    if not isinstance(value, int | float) or isinstance(value, bool) or not 0 <= value <= 1:
        raise EnrollmentStabilityError(f"{field_name} must be a probability")
    return float(value)


def require_iso_date_time(value: str) -> None:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise EnrollmentStabilityError("capturedAt must be an ISO date-time") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EnrollmentStabilityError("capturedAt must include a UTC offset")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    encoded = (json.dumps(value, indent=2) + "\n").encode("utf-8")
    if path.exists():
        if path.is_file() and path.read_bytes() == encoded:
            return
        raise EnrollmentStabilityError(f"immutable stability output collision: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(encoded)


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure VoiceID enrollment stability across owner sessions.")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    evaluate_stability(args.input, args.output)


if __name__ == "__main__":
    main()
