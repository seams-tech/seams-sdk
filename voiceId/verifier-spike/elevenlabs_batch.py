from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import wave
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Protocol

from dia2_batch import (
    BENCHMARK_SCHEMA_VERSION,
    inspect_wav,
    parse_capture,
    parse_case,
    parse_challenge_tokens,
    parse_expected_intent,
    require_exact_keys,
    require_file_name,
    require_identifier,
    require_non_negative_int,
    require_non_negative_number,
    require_object,
    require_one_of,
    require_positive_number,
    require_string,
    sha256_json,
)


PLAN_SCHEMA_VERSION = "voice_id_elevenlabs_generation_plan_v1"
REPORT_SCHEMA_VERSION = "voice_id_elevenlabs_generation_report_v1"
VOICE_KINDS = frozenset({"voice_design", "owner_clone"})
OUTPUT_FORMAT = "pcm_16000"


class ElevenLabsPlanError(ValueError):
    pass


@dataclass(frozen=True)
class VoiceDesign:
    kind: Literal["voice_design"]
    voice_key: str
    name: str
    description: str
    preview_text: str
    preview_index: int
    model_id: str


@dataclass(frozen=True)
class OwnerClone:
    kind: Literal["owner_clone"]
    voice_key: str
    name: str
    description: str
    reference_audio_file_name: str
    source_subject_id: str
    consent_reference: str
    retention_class: str


VoiceSpec = VoiceDesign | OwnerClone


@dataclass(frozen=True)
class ElevenLabsJob:
    fixture_id: str
    audio_file_name: str
    subject_id: str
    session_id: str
    partition: str
    case: dict[str, Any]
    expected_intent: str | None
    challenge_tokens: tuple[str, ...]
    voice_key: str
    text: str
    seed: int


@dataclass(frozen=True)
class ElevenLabsPlan:
    dataset_version: str
    tts_model_id: str
    settings: dict[str, float | bool]
    capture: dict[str, Any]
    voices: tuple[VoiceSpec, ...]
    jobs: tuple[ElevenLabsJob, ...]


class ElevenLabsApi(Protocol):
    def design_voice(self, spec: VoiceDesign) -> str:
        ...

    def clone_voice(self, spec: OwnerClone, reference_path: Path) -> str:
        ...

    def synthesize(
        self,
        *,
        voice_id: str,
        text: str,
        model_id: str,
        settings: dict[str, float | bool],
        seed: int,
    ) -> bytes:
        ...


class ElevenLabsHttpClient:
    def __init__(self, api_key: str) -> None:
        if api_key.strip() == "":
            raise ElevenLabsPlanError("ELEVENLABS_API_KEY is required")
        self._api_key = api_key.strip()

    def design_voice(self, spec: VoiceDesign) -> str:
        response = self._json_request(
            "/v1/text-to-voice/design",
            {
                "model_id": spec.model_id,
                "voice_description": spec.description,
                "text": spec.preview_text,
            },
        )
        previews = response.get("previews")
        if not isinstance(previews, list) or spec.preview_index >= len(previews):
            raise ElevenLabsPlanError("voice design response is missing the selected preview")
        preview = require_object(previews[spec.preview_index], "voice design preview")
        generated_voice_id = require_string(preview, "generated_voice_id")
        created = self._json_request(
            "/v1/text-to-voice",
            {
                "voice_name": spec.name,
                "voice_description": spec.description,
                "generated_voice_id": generated_voice_id,
            },
        )
        return require_string(created, "voice_id")

    def clone_voice(self, spec: OwnerClone, reference_path: Path) -> str:
        if not reference_path.is_file():
            raise ElevenLabsPlanError(
                f"owner clone reference is missing: {reference_path.name}"
            )
        boundary = f"voiceid-{hashlib.sha256(reference_path.read_bytes()).hexdigest()[:24]}"
        body = multipart_body(
            boundary=boundary,
            fields={
                "name": spec.name,
                "description": spec.description,
                "remove_background_noise": "false",
            },
            file_name=reference_path.name,
            file_bytes=reference_path.read_bytes(),
        )
        response = self._request(
            "/v1/voices/add",
            body,
            content_type=f"multipart/form-data; boundary={boundary}",
        )
        value = parse_json_response(response, "owner clone")
        return require_string(value, "voice_id")

    def synthesize(
        self,
        *,
        voice_id: str,
        text: str,
        model_id: str,
        settings: dict[str, float | bool],
        seed: int,
    ) -> bytes:
        query = urllib.parse.urlencode({"output_format": OUTPUT_FORMAT})
        return self._request(
            f"/v1/text-to-speech/{urllib.parse.quote(voice_id)}?{query}",
            json.dumps(
                {
                    "text": text,
                    "model_id": model_id,
                    "voice_settings": settings,
                    "seed": seed,
                },
                separators=(",", ":"),
            ).encode("utf-8"),
            content_type="application/json",
        )

    def _json_request(self, path: str, value: object) -> dict[str, Any]:
        response = self._request(
            path,
            json.dumps(value, separators=(",", ":")).encode("utf-8"),
            content_type="application/json",
        )
        return parse_json_response(response, path)

    def _request(self, path: str, body: bytes, *, content_type: str) -> bytes:
        request = urllib.request.Request(
            f"https://api.elevenlabs.io{path}",
            data=body,
            method="POST",
            headers={
                "xi-api-key": self._api_key,
                "Content-Type": content_type,
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            raise ElevenLabsPlanError(
                f"ElevenLabs request failed with HTTP {exc.code}"
            ) from exc
        except urllib.error.URLError as exc:
            raise ElevenLabsPlanError("ElevenLabs request failed") from exc


def load_plan(path: Path) -> ElevenLabsPlan:
    value = json.loads(path.expanduser().resolve().read_text(encoding="utf-8"))
    data = require_object(value, "plan")
    require_exact_keys(
        data,
        "plan",
        {
            "schemaVersion",
            "datasetVersion",
            "ttsModelId",
            "settings",
            "capture",
            "voices",
            "jobs",
        },
    )
    if require_string(data, "schemaVersion") != PLAN_SCHEMA_VERSION:
        raise ElevenLabsPlanError(f"schemaVersion must be {PLAN_SCHEMA_VERSION}")
    voices_value = data["voices"]
    jobs_value = data["jobs"]
    if not isinstance(voices_value, list) or len(voices_value) == 0:
        raise ElevenLabsPlanError("voices must be a non-empty array")
    if not isinstance(jobs_value, list) or len(jobs_value) == 0:
        raise ElevenLabsPlanError("jobs must be a non-empty array")
    voices = tuple(parse_voice(value, index) for index, value in enumerate(voices_value))
    jobs = tuple(parse_job(value, index) for index, value in enumerate(jobs_value))
    validate_plan_relationships(voices, jobs)
    return ElevenLabsPlan(
        dataset_version=require_string(data, "datasetVersion"),
        tts_model_id=require_string(data, "ttsModelId"),
        settings=parse_settings(data["settings"]),
        capture=parse_capture(data["capture"]),
        voices=voices,
        jobs=jobs,
    )


def parse_voice(value: object, index: int) -> VoiceSpec:
    field_name = f"voices[{index}]"
    data = require_object(value, field_name)
    kind = require_one_of(data, "kind", VOICE_KINDS)
    if kind == "voice_design":
        require_exact_keys(
            data,
            field_name,
            {
                "kind",
                "voiceKey",
                "name",
                "description",
                "previewText",
                "previewIndex",
                "modelId",
            },
        )
        description = require_string(data, "description")
        if len(description) < 20:
            raise ElevenLabsPlanError("voice design description must contain 20 characters")
        return VoiceDesign(
            kind="voice_design",
            voice_key=require_identifier(data, "voiceKey"),
            name=require_string(data, "name"),
            description=description,
            preview_text=require_string(data, "previewText"),
            preview_index=require_non_negative_int(data, "previewIndex"),
            model_id=require_string(data, "modelId"),
        )
    require_exact_keys(
        data,
        field_name,
        {
            "kind",
            "voiceKey",
            "name",
            "description",
            "referenceAudioFileName",
            "sourceSubjectId",
            "consentReference",
            "retentionClass",
        },
    )
    return OwnerClone(
        kind="owner_clone",
        voice_key=require_identifier(data, "voiceKey"),
        name=require_string(data, "name"),
        description=require_string(data, "description"),
        reference_audio_file_name=require_file_name(data, "referenceAudioFileName"),
        source_subject_id=require_identifier(data, "sourceSubjectId"),
        consent_reference=require_string(data, "consentReference"),
        retention_class=require_string(data, "retentionClass"),
    )


def parse_job(value: object, index: int) -> ElevenLabsJob:
    field_name = f"jobs[{index}]"
    data = require_object(value, field_name)
    require_exact_keys(
        data,
        field_name,
        {
            "fixtureId",
            "audioFileName",
            "subjectId",
            "sessionId",
            "partition",
            "case",
            "expectedIntent",
            "challengeTokens",
            "voiceKey",
            "text",
            "seed",
        },
    )
    case = parse_case(data["case"], field_name)
    audio_file_name = require_file_name(data, "audioFileName")
    if Path(audio_file_name).suffix.lower() != ".wav":
        raise ElevenLabsPlanError("ElevenLabs output must use .wav")
    return ElevenLabsJob(
        fixture_id=require_identifier(data, "fixtureId"),
        audio_file_name=audio_file_name,
        subject_id=require_identifier(data, "subjectId"),
        session_id=require_identifier(data, "sessionId"),
        partition=require_one_of(
            data,
            "partition",
            frozenset({"development", "calibration", "evaluation"}),
        ),
        case=case,
        expected_intent=parse_expected_intent(data["expectedIntent"], case["kind"]),
        challenge_tokens=parse_challenge_tokens(data["challengeTokens"], case["kind"]),
        voice_key=require_identifier(data, "voiceKey"),
        text=require_string(data, "text"),
        seed=require_non_negative_int(data, "seed"),
    )


def parse_settings(value: object) -> dict[str, float | bool]:
    data = require_object(value, "settings")
    require_exact_keys(
        data,
        "settings",
        {"stability", "similarityBoost", "style", "speed", "useSpeakerBoost"},
    )
    use_speaker_boost = data["useSpeakerBoost"]
    if not isinstance(use_speaker_boost, bool):
        raise ElevenLabsPlanError("useSpeakerBoost must be a boolean")
    settings = {
        "stability": require_positive_number(data, "stability"),
        "similarity_boost": require_positive_number(data, "similarityBoost"),
        "style": require_non_negative_number(data, "style"),
        "speed": require_positive_number(data, "speed"),
        "use_speaker_boost": use_speaker_boost,
    }
    for key in ("stability", "similarity_boost", "style"):
        if float(settings[key]) > 1:
            raise ElevenLabsPlanError(f"{key} must not exceed one")
    return settings


def validate_plan_relationships(
    voices: tuple[VoiceSpec, ...],
    jobs: tuple[ElevenLabsJob, ...],
) -> None:
    voice_keys = {voice.voice_key for voice in voices}
    if len(voice_keys) != len(voices):
        raise ElevenLabsPlanError("voiceKey values must be unique")
    fixture_ids = {job.fixture_id for job in jobs}
    file_names = {job.audio_file_name for job in jobs}
    if len(fixture_ids) != len(jobs) or len(file_names) != len(jobs):
        raise ElevenLabsPlanError("job fixtureId and audioFileName values must be unique")
    if any(job.voice_key not in voice_keys for job in jobs):
        raise ElevenLabsPlanError("every job voiceKey must reference a planned voice")
    subject_partitions: dict[str, str] = {}
    for job in jobs:
        previous = subject_partitions.setdefault(job.subject_id, job.partition)
        if previous != job.partition:
            raise ElevenLabsPlanError(
                f"subject {job.subject_id} crosses frozen partitions"
            )


def generate_plan(
    plan: ElevenLabsPlan,
    *,
    client: ElevenLabsApi,
    asset_dir: Path,
    output_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    voice_ids = provision_voices(plan.voices, client=client, asset_dir=asset_dir)
    entries = []
    report_entries = []
    for job in plan.jobs:
        request = {
            "voiceId": voice_ids[job.voice_key],
            "text": job.text,
            "modelId": plan.tts_model_id,
            "outputFormat": OUTPUT_FORMAT,
            "settings": plan.settings,
            "seed": job.seed,
        }
        started = time.perf_counter()
        pcm = client.synthesize(
            voice_id=voice_ids[job.voice_key],
            text=job.text,
            model_id=plan.tts_model_id,
            settings=plan.settings,
            seed=job.seed,
        )
        output_path = output_dir / job.audio_file_name
        write_pcm_wav(output_path, pcm)
        audio = inspect_wav(output_path)
        request_hash = sha256_json(request)
        captured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        voice = next(voice for voice in plan.voices if voice.voice_key == job.voice_key)
        entries.append(
            benchmark_entry(
                plan=plan,
                job=job,
                voice=voice,
                voice_id=voice_ids[job.voice_key],
                audio=audio,
                request_hash=request_hash,
                captured_at=captured_at,
            )
        )
        report_entries.append(
            {
                "fixtureId": job.fixture_id,
                "voiceKey": job.voice_key,
                "voiceId": voice_ids[job.voice_key],
                "requestHash": request_hash,
                "outputSha256": audio["sha256"],
                "generationMs": round((time.perf_counter() - started) * 1000, 3),
            }
        )
    return (
        {
            "schemaVersion": BENCHMARK_SCHEMA_VERSION,
            "datasetVersion": plan.dataset_version,
            "createdAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "entries": entries,
        },
        {
            "schemaVersion": REPORT_SCHEMA_VERSION,
            "datasetVersion": plan.dataset_version,
            "ttsModelId": plan.tts_model_id,
            "outputFormat": OUTPUT_FORMAT,
            "voiceIds": voice_ids,
            "fixtureCount": len(entries),
            "entries": report_entries,
        },
    )


def provision_voices(
    voices: tuple[VoiceSpec, ...],
    *,
    client: ElevenLabsApi,
    asset_dir: Path,
) -> dict[str, str]:
    result = {}
    for voice in voices:
        if isinstance(voice, VoiceDesign):
            result[voice.voice_key] = client.design_voice(voice)
        else:
            result[voice.voice_key] = client.clone_voice(
                voice,
                (asset_dir / voice.reference_audio_file_name).resolve(),
            )
    return result


def benchmark_entry(
    *,
    plan: ElevenLabsPlan,
    job: ElevenLabsJob,
    voice: VoiceSpec,
    voice_id: str,
    audio: dict[str, Any],
    request_hash: str,
    captured_at: str,
) -> dict[str, Any]:
    conditioning = (
        {
            "sourceSubjectId": voice.source_subject_id,
            "consentReference": voice.consent_reference,
            "retentionClass": voice.retention_class,
        }
        if isinstance(voice, OwnerClone)
        else None
    )
    return {
        "fixtureId": job.fixture_id,
        "audioFileName": job.audio_file_name,
        "audioSha256": audio["sha256"],
        "subjectId": job.subject_id,
        "sessionId": job.session_id,
        "partition": job.partition,
        "case": job.case,
        "expectedIntent": job.expected_intent,
        "challengeTokens": list(job.challenge_tokens),
        "capture": {**plan.capture, "sampleRateHz": audio["sampleRateHz"]},
        "capturedAt": captured_at,
        "durationMs": audio["durationMs"],
        "byteLength": audio["byteLength"],
        "mimeType": "audio/wav",
        "provenance": {
            "kind": "synthetic_generation",
            "generator": "elevenlabs",
            "model": plan.tts_model_id,
            "voice": voice_id,
            "seed": job.seed,
            "license": "ElevenLabs commercial API terms snapshot 2026-07-26",
            "requestHash": request_hash,
            "conditioning": conditioning,
        },
    }


def write_pcm_wav(path: Path, pcm: bytes) -> None:
    if len(pcm) == 0 or len(pcm) % 2 != 0:
        raise ElevenLabsPlanError("ElevenLabs PCM response must contain 16-bit samples")
    with wave.open(str(path), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(16000)
        output.writeframes(pcm)


def multipart_body(
    *,
    boundary: str,
    fields: dict[str, str],
    file_name: str,
    file_bytes: bytes,
) -> bytes:
    chunks = []
    for name, value in fields.items():
        chunks.extend(
            (
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                value.encode(),
                b"\r\n",
            )
        )
    chunks.extend(
        (
            f"--{boundary}\r\n".encode(),
            (
                f'Content-Disposition: form-data; name="files"; '
                f'filename="{file_name}"\r\n'
            ).encode(),
            b"Content-Type: audio/wav\r\n\r\n",
            file_bytes,
            b"\r\n",
            f"--{boundary}--\r\n".encode(),
        )
    )
    return b"".join(chunks)


def parse_json_response(value: bytes, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ElevenLabsPlanError(f"{label} response is malformed") from exc
    return require_object(parsed, f"{label} response")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a provenance-pinned ElevenLabs VoiceID corpus batch."
    )
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--asset-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--manifest-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    args = parser.parse_args()
    api_key = os.environ.get("ELEVENLABS_API_KEY", "")
    manifest, report = generate_plan(
        load_plan(args.plan),
        client=ElevenLabsHttpClient(api_key),
        asset_dir=args.asset_dir,
        output_dir=args.output_dir,
    )
    write_json(args.manifest_out, manifest)
    write_json(args.report_out, report)


if __name__ == "__main__":
    main()
