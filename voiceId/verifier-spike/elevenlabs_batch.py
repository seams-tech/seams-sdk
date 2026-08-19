from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import wave
from contextlib import contextmanager
from dataclasses import dataclass, replace
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
    require_positive_int,
    require_positive_number,
    require_string,
    sha256_json,
)


PLAN_SCHEMA_VERSION = "voice_id_elevenlabs_generation_plan_v1"
REPORT_SCHEMA_VERSION = "voice_id_elevenlabs_generation_report_v1"
STATE_SCHEMA_VERSION = "voice_id_elevenlabs_generation_state_v1"
CAMPAIGN_SCHEMA_VERSION = "voice_id_elevenlabs_campaign_binding_v1"
CAMPAIGN_BINDING_FILE_NAME = ".voiceid-elevenlabs-campaign.json"
CAMPAIGN_LOCK_FILE_NAME = ".voiceid-elevenlabs-campaign.lock"
VOICE_KINDS = frozenset({"voice_design", "owner_clone"})
OUTPUT_FORMAT = "pcm_16000"
MIN_GENERATED_AUDIO_MS = 900


class ElevenLabsPlanError(ValueError):
    pass


class ElevenLabsStateError(ValueError):
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
    plan_sha256: str
    dataset_version: str
    tts_model_id: str
    settings: dict[str, float | bool]
    capture: dict[str, Any]
    voices: tuple[VoiceSpec, ...]
    jobs: tuple[ElevenLabsJob, ...]


@dataclass(frozen=True)
class ResolvedVoiceState:
    voice_key: str
    voice_id: str
    provisioning_sha256: str


@dataclass(frozen=True)
class CompletedJobState:
    fixture_id: str
    request_sha256: str
    output_sha256: str
    output_bytes: int
    duration_ms: int
    sample_rate_hz: int
    captured_at: str
    generation_ms: float


@dataclass(frozen=True)
class PendingVoiceState:
    kind: Literal["provision_voice"]
    voice_key: str
    request_sha256: str


@dataclass(frozen=True)
class PendingJobState:
    kind: Literal["synthesize_job"]
    fixture_id: str
    request_sha256: str


@dataclass(frozen=True)
class MaterializedJobState:
    kind: Literal["materialized_job"]
    completed: CompletedJobState


PendingOperation = PendingVoiceState | PendingJobState | MaterializedJobState


@dataclass(frozen=True)
class GenerationState:
    dataset_version: str
    plan_sha256: str
    created_at: str
    resolved_voices: tuple[ResolvedVoiceState, ...]
    completed_jobs: tuple[CompletedJobState, ...]
    pending_operation: PendingOperation | None


class ElevenLabsApi(Protocol):
    def design_voice(self, spec: VoiceDesign) -> str:
        ...

    def clone_voice(
        self,
        spec: OwnerClone,
        reference_path: Path,
        reference_bytes: bytes,
    ) -> str:
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

    def clone_voice(
        self,
        spec: OwnerClone,
        reference_path: Path,
        reference_bytes: bytes,
    ) -> str:
        if len(reference_bytes) == 0:
            raise ElevenLabsPlanError("owner clone reference is empty")
        boundary = f"voiceid-{hashlib.sha256(reference_bytes).hexdigest()[:24]}"
        body = multipart_body(
            boundary=boundary,
            fields={
                "name": spec.name,
                "description": spec.description,
                "remove_background_noise": "false",
            },
            file_name=reference_path.name,
            file_bytes=reference_bytes,
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
    plan_bytes = path.expanduser().resolve().read_bytes()
    value = json.loads(plan_bytes.decode("utf-8"))
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
        plan_sha256=hashlib.sha256(plan_bytes).hexdigest(),
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


def generation_state_lock_path(state_path: Path) -> Path:
    resolved = state_path.expanduser().resolve()
    return resolved.with_name(f"{resolved.name}.lock")


def generation_campaign_binding_path(output_dir: Path) -> Path:
    return output_dir.expanduser().resolve() / CAMPAIGN_BINDING_FILE_NAME


def generation_campaign_lock_path(output_dir: Path) -> Path:
    return output_dir.expanduser().resolve() / CAMPAIGN_LOCK_FILE_NAME


def require_regular_file_or_absent(
    path: Path,
    label: str,
) -> bool:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return False
    except OSError as error:
        raise ElevenLabsStateError(f"cannot inspect {label}: {path.name}") from error
    if not stat.S_ISREG(mode):
        raise ElevenLabsStateError(f"{label} must be a regular file: {path.name}")
    return True


@contextmanager
def generation_state_lock(state_path: Path):
    lock_path = generation_state_lock_path(state_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    require_regular_file_or_absent(lock_path, "generation state lock")
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


@contextmanager
def generation_campaign_lock(
    *,
    plan: ElevenLabsPlan,
    output_dir: Path,
    state_path: Path,
):
    resolved_output_dir = output_dir.expanduser().resolve()
    resolved_output_dir.mkdir(parents=True, exist_ok=True)
    lock_path = generation_campaign_lock_path(resolved_output_dir)
    require_regular_file_or_absent(lock_path, "generation campaign lock")
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            binding_path = generation_campaign_binding_path(resolved_output_dir)
            campaign_exists = require_regular_file_or_absent(
                binding_path,
                "generation campaign binding",
            )
            if campaign_exists:
                validate_campaign_binding(
                    binding_path,
                    plan=plan,
                    state_path=state_path,
                )
                if not require_regular_file_or_absent(
                    state_path.expanduser(),
                    "generation state",
                ):
                    raise ElevenLabsStateError(
                        "generation campaign bound state is missing"
                    )
            with generation_state_lock(state_path):
                yield campaign_exists
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def bind_generation_campaign(
    *,
    plan: ElevenLabsPlan,
    output_dir: Path,
    state_path: Path,
) -> None:
    binding_path = generation_campaign_binding_path(output_dir)
    binding = {
        "schemaVersion": CAMPAIGN_SCHEMA_VERSION,
        "datasetVersion": plan.dataset_version,
        "planSha256": plan.plan_sha256,
        "statePath": str(state_path.expanduser().resolve()),
    }
    encoded = (json.dumps(binding, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if require_regular_file_or_absent(
        binding_path,
        "generation campaign binding",
    ):
        validate_campaign_binding(
            binding_path,
            plan=plan,
            state_path=state_path,
        )
        return
    temporary_path = binding_path.with_name(
        f".{binding_path.name}.{os.getpid()}.{time.time_ns()}.tmp"
    )
    try:
        with temporary_path.open("xb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary_path, binding_path)
        except FileExistsError:
            require_regular_file_or_absent(
                binding_path,
                "generation campaign binding",
            )
            validate_campaign_binding(
                binding_path,
                plan=plan,
                state_path=state_path,
            )
        sync_directory(output_dir)
    finally:
        temporary_path.unlink(missing_ok=True)


def validate_campaign_binding(
    binding_path: Path,
    *,
    plan: ElevenLabsPlan,
    state_path: Path,
) -> None:
    if not require_regular_file_or_absent(
        binding_path,
        "generation campaign binding",
    ):
        raise ElevenLabsStateError("generation campaign binding is missing")
    try:
        data = require_object(
            json.loads(binding_path.read_text(encoding="utf-8")),
            "generation campaign",
        )
        require_exact_keys(
            data,
            "generation campaign",
            {
                "schemaVersion",
                "datasetVersion",
                "planSha256",
                "statePath",
            },
        )
        if require_string(data, "schemaVersion") != CAMPAIGN_SCHEMA_VERSION:
            raise ElevenLabsStateError(
                "generation campaign schemaVersion is unsupported"
            )
        if require_string(data, "datasetVersion") != plan.dataset_version:
            raise ElevenLabsStateError(
                "generation campaign datasetVersion does not match plan"
            )
        if require_sha256(data, "planSha256") != plan.plan_sha256:
            raise ElevenLabsStateError(
                "generation campaign planSha256 does not match plan"
            )
        if require_string(data, "statePath") != str(
            state_path.expanduser().resolve()
        ):
            raise ElevenLabsStateError(
                "output directory belongs to a different generation campaign state"
            )
    except ElevenLabsStateError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ElevenLabsStateError(
            f"generation campaign binding is corrupt: {error}"
        ) from error


def planned_audio_paths(plan: ElevenLabsPlan, output_dir: Path) -> set[Path]:
    final_paths = {
        (output_dir / job.audio_file_name).expanduser().resolve()
        for job in plan.jobs
    }
    pending_paths = {
        pending_output_path(output_dir, job).expanduser().resolve()
        for job in plan.jobs
    }
    return final_paths | pending_paths


def pending_output_path(output_dir: Path, job: ElevenLabsJob) -> Path:
    return output_dir / f".{job.audio_file_name}.pending"


def owner_asset_paths(plan: ElevenLabsPlan, asset_dir: Path) -> set[Path]:
    return {
        (asset_dir / voice.reference_audio_file_name).expanduser().resolve()
        for voice in plan.voices
        if isinstance(voice, OwnerClone)
    }


def validate_cli_paths(
    *,
    plan_path: Path,
    plan: ElevenLabsPlan,
    asset_dir: Path,
    output_dir: Path,
    state_path: Path,
    manifest_path: Path,
    report_path: Path,
) -> None:
    validate_generation_paths(
        plan=plan,
        asset_dir=asset_dir,
        output_dir=output_dir,
        state_path=state_path,
    )
    durable_outputs = {
        state_path.expanduser().resolve(),
        manifest_path.expanduser().resolve(),
        report_path.expanduser().resolve(),
    }
    if len(durable_outputs) != 3:
        raise ElevenLabsStateError(
            "--state, --manifest-out, and --report-out must be distinct"
        )
    protected_inputs = {plan_path.expanduser().resolve()}
    protected_inputs.update(owner_asset_paths(plan, asset_dir))
    planned_audio = planned_audio_paths(plan, output_dir)
    campaign_paths = {
        generation_campaign_binding_path(output_dir),
        generation_campaign_lock_path(output_dir),
    }
    forbidden = planned_audio | protected_inputs
    forbidden.update(
        {
            output_dir.expanduser().resolve(),
            generation_state_lock_path(state_path),
            *campaign_paths,
        }
    )
    conflicts = durable_outputs & forbidden
    if conflicts:
        conflict = sorted(str(path) for path in conflicts)[0]
        raise ElevenLabsStateError(
            f"durable output path conflicts with audio or input: {conflict}"
        )
    if generation_state_lock_path(state_path) in protected_inputs | planned_audio:
        raise ElevenLabsStateError(
            "generation state lock path conflicts with audio or input"
        )


def load_or_create_generation_state(
    path: Path,
    *,
    plan: ElevenLabsPlan,
    asset_dir: Path,
    output_dir: Path,
) -> GenerationState:
    if not require_regular_file_or_absent(
        path.expanduser(),
        "generation state",
    ):
        state_exists = False
    else:
        state_exists = True
    state_path = path.expanduser().resolve()
    if state_exists:
        state = read_generation_state(state_path)
        state = recover_pending_operation(
            state,
            plan=plan,
            asset_dir=asset_dir,
            output_dir=output_dir,
            state_path=state_path,
        )
        validate_generation_state(
            state,
            plan=plan,
            asset_dir=asset_dir,
            output_dir=output_dir,
        )
        return state
    state = GenerationState(
        dataset_version=plan.dataset_version,
        plan_sha256=plan.plan_sha256,
        created_at=utc_now(),
        resolved_voices=(),
        completed_jobs=(),
        pending_operation=None,
    )
    validate_generation_state(
        state,
        plan=plan,
        asset_dir=asset_dir,
        output_dir=output_dir,
    )
    persist_generation_state(state_path, state)
    return state


def recover_pending_operation(
    state: GenerationState,
    *,
    plan: ElevenLabsPlan,
    asset_dir: Path,
    output_dir: Path,
    state_path: Path,
) -> GenerationState:
    validate_state_identity(state, plan)
    pending = state.pending_operation
    if pending is None:
        return state
    uncommitted_fixture_id = (
        pending.fixture_id
        if isinstance(pending, PendingJobState)
        else (
            pending.completed.fixture_id
            if isinstance(pending, MaterializedJobState)
            else None
        )
    )
    validate_generation_state(
        replace(state, pending_operation=None),
        plan=plan,
        asset_dir=asset_dir,
        output_dir=output_dir,
        uncommitted_fixture_id=uncommitted_fixture_id,
    )
    # This client has no idempotency mechanism, so an unknown POST result needs reconciliation.
    if isinstance(pending, PendingVoiceState):
        voice_index = len(state.resolved_voices)
        if voice_index >= len(plan.voices):
            raise ElevenLabsStateError("pending voice exceeds the generation plan")
        voice = plan.voices[voice_index]
        if (
            pending.voice_key != voice.voice_key
            or pending.request_sha256
            != voice_provisioning_sha256(voice, asset_dir)
        ):
            raise ElevenLabsStateError("pending voice does not match the generation plan")
        raise ElevenLabsStateError(
            "remote operation outcome is ambiguous; preserve the generation "
            "state until an audited recovery operation is available"
        )
    if isinstance(pending, PendingJobState):
        if len(state.resolved_voices) != len(plan.voices):
            raise ElevenLabsStateError("pending job lacks all resolved voices")
        job_index = len(state.completed_jobs)
        if job_index >= len(plan.jobs):
            raise ElevenLabsStateError("pending job exceeds the generation plan")
        job = plan.jobs[job_index]
        voice_ids = {item.voice_key: item.voice_id for item in state.resolved_voices}
        if (
            pending.fixture_id != job.fixture_id
            or pending.request_sha256
            != sha256_json(synthesis_request(plan, job, voice_ids[job.voice_key]))
        ):
            raise ElevenLabsStateError("pending job does not match the generation plan")
        raise ElevenLabsStateError(
            "remote operation outcome is ambiguous; preserve the generation "
            "state until an audited recovery operation is available"
        )
    job_index = len(state.completed_jobs)
    if job_index >= len(plan.jobs):
        raise ElevenLabsStateError("materialized job exceeds the generation plan")
    job = plan.jobs[job_index]
    completed = pending.completed
    if completed.fixture_id != job.fixture_id:
        raise ElevenLabsStateError("materialized job is not the next planned job")
    if len(state.resolved_voices) != len(plan.voices):
        raise ElevenLabsStateError("materialized job lacks all resolved voices")
    voice_ids = {item.voice_key: item.voice_id for item in state.resolved_voices}
    if completed.request_sha256 != sha256_json(
        synthesis_request(plan, job, voice_ids[job.voice_key])
    ):
        raise ElevenLabsStateError("materialized job request hash does not match plan")
    pending_path = pending_output_path(output_dir, job)
    output_path = output_dir / job.audio_file_name
    pending_exists = require_regular_file_or_absent(
        pending_path,
        "materialized pending output",
    )
    output_exists = require_regular_file_or_absent(
        output_path,
        "materialized final output",
    )
    if not pending_exists and not output_exists:
        raise ElevenLabsStateError(
            "materialized job is missing its pending and final WAV"
        )
    publish_materialized_output(
        completed=completed,
        pending_path=pending_path,
        output_path=output_path,
    )
    recovered = add_completed_job(state, completed)
    persist_generation_state(state_path, recovered)
    return recovered


def validate_state_identity(state: GenerationState, plan: ElevenLabsPlan) -> None:
    if state.dataset_version != plan.dataset_version:
        raise ElevenLabsStateError("generation state datasetVersion does not match plan")
    plan_sha256 = require_sha256({"planSha256": plan.plan_sha256}, "planSha256")
    if state.plan_sha256 != plan_sha256:
        raise ElevenLabsStateError("generation state planSha256 does not match plan")


def read_generation_state(path: Path) -> GenerationState:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return parse_generation_state(value)
    except ElevenLabsStateError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, ValueError) as error:
        raise ElevenLabsStateError(
            f"generation state is corrupt: {error}"
        ) from error


def parse_generation_state(value: object) -> GenerationState:
    data = require_object(value, "generation state")
    require_exact_keys(
        data,
        "generation state",
        {
            "schemaVersion",
            "datasetVersion",
            "planSha256",
            "createdAt",
            "resolvedVoices",
            "completedJobs",
            "pendingOperation",
        },
    )
    if require_string(data, "schemaVersion") != STATE_SCHEMA_VERSION:
        raise ElevenLabsStateError(
            f"generation state schemaVersion must be {STATE_SCHEMA_VERSION}"
        )
    resolved_values = data["resolvedVoices"]
    completed_values = data["completedJobs"]
    if not isinstance(resolved_values, list):
        raise ElevenLabsStateError("generation state resolvedVoices must be an array")
    if not isinstance(completed_values, list):
        raise ElevenLabsStateError("generation state completedJobs must be an array")
    resolved_voices = tuple(
        parse_resolved_voice_state(item, index)
        for index, item in enumerate(resolved_values)
    )
    completed_jobs = tuple(
        parse_completed_job_state(item, index)
        for index, item in enumerate(completed_values)
    )
    pending_operation = parse_pending_operation(data["pendingOperation"])
    if len({voice.voice_key for voice in resolved_voices}) != len(resolved_voices):
        raise ElevenLabsStateError("generation state contains duplicate voiceKey values")
    if len({voice.voice_id for voice in resolved_voices}) != len(resolved_voices):
        raise ElevenLabsStateError("generation state contains duplicate voiceId values")
    if len({job.fixture_id for job in completed_jobs}) != len(completed_jobs):
        raise ElevenLabsStateError("generation state contains duplicate fixtureId values")
    return GenerationState(
        dataset_version=require_string(data, "datasetVersion"),
        plan_sha256=require_sha256(data, "planSha256"),
        created_at=require_iso_timestamp(data, "createdAt"),
        resolved_voices=resolved_voices,
        completed_jobs=completed_jobs,
        pending_operation=pending_operation,
    )


def parse_resolved_voice_state(value: object, index: int) -> ResolvedVoiceState:
    field_name = f"generation state resolvedVoices[{index}]"
    data = require_object(value, field_name)
    require_exact_keys(
        data,
        field_name,
        {"voiceKey", "voiceId", "provisioningSha256"},
    )
    return ResolvedVoiceState(
        voice_key=require_identifier(data, "voiceKey"),
        voice_id=require_string(data, "voiceId"),
        provisioning_sha256=require_sha256(data, "provisioningSha256"),
    )


def parse_completed_job_state(value: object, index: int) -> CompletedJobState:
    field_name = f"generation state completedJobs[{index}]"
    data = require_object(value, field_name)
    require_exact_keys(
        data,
        field_name,
        {
            "fixtureId",
            "requestSha256",
            "outputSha256",
            "outputBytes",
            "durationMs",
            "sampleRateHz",
            "capturedAt",
            "generationMs",
        },
    )
    return CompletedJobState(
        fixture_id=require_identifier(data, "fixtureId"),
        request_sha256=require_sha256(data, "requestSha256"),
        output_sha256=require_sha256(data, "outputSha256"),
        output_bytes=require_positive_int(data, "outputBytes"),
        duration_ms=require_positive_int(data, "durationMs"),
        sample_rate_hz=require_positive_int(data, "sampleRateHz"),
        captured_at=require_iso_timestamp(data, "capturedAt"),
        generation_ms=require_non_negative_number(data, "generationMs"),
    )


def parse_pending_operation(value: object) -> PendingOperation | None:
    if value is None:
        return None
    data = require_object(value, "generation state pendingOperation")
    kind = require_one_of(
        data,
        "kind",
        frozenset({"provision_voice", "synthesize_job", "materialized_job"}),
    )
    if kind == "provision_voice":
        require_exact_keys(data, "pending voice", {"kind", "voiceKey", "requestSha256"})
        return PendingVoiceState(
            kind="provision_voice",
            voice_key=require_identifier(data, "voiceKey"),
            request_sha256=require_sha256(data, "requestSha256"),
        )
    if kind == "synthesize_job":
        require_exact_keys(data, "pending job", {"kind", "fixtureId", "requestSha256"})
        return PendingJobState(
            kind="synthesize_job",
            fixture_id=require_identifier(data, "fixtureId"),
            request_sha256=require_sha256(data, "requestSha256"),
        )
    require_exact_keys(data, "materialized job", {"kind", "completed"})
    return MaterializedJobState(
        kind="materialized_job",
        completed=parse_completed_job_state(data["completed"], 0),
    )


def validate_generation_state(
    state: GenerationState,
    *,
    plan: ElevenLabsPlan,
    asset_dir: Path,
    output_dir: Path,
    uncommitted_fixture_id: str | None = None,
) -> None:
    validate_state_identity(state, plan)
    if state.pending_operation is not None:
        raise ElevenLabsStateError("generation state contains an unrecovered operation")
    resolved_count = len(state.resolved_voices)
    if tuple(item.voice_key for item in state.resolved_voices) != tuple(
        voice.voice_key for voice in plan.voices[:resolved_count]
    ):
        raise ElevenLabsStateError(
            "generation state resolved voices are not a plan-order prefix"
        )
    for resolved, voice in zip(state.resolved_voices, plan.voices, strict=False):
        if resolved.provisioning_sha256 != voice_provisioning_sha256(voice, asset_dir):
            raise ElevenLabsStateError(
                f"generation state provisioning hash does not match {resolved.voice_key}"
            )
    completed_count = len(state.completed_jobs)
    if tuple(item.fixture_id for item in state.completed_jobs) != tuple(
        job.fixture_id for job in plan.jobs[:completed_count]
    ):
        raise ElevenLabsStateError(
            "generation state completed jobs are not a plan-order prefix"
        )
    if completed_count > 0 and resolved_count != len(plan.voices):
        raise ElevenLabsStateError(
            "generation state contains jobs before all voices are resolved"
        )
    voice_ids = {item.voice_key: item.voice_id for item in state.resolved_voices}
    for completed, job in zip(state.completed_jobs, plan.jobs, strict=False):
        if completed.request_sha256 != sha256_json(
            synthesis_request(plan, job, voice_ids[job.voice_key])
        ):
            raise ElevenLabsStateError(
                f"generation state request hash does not match {job.fixture_id}"
            )
        validate_completed_output(
            completed,
            path=output_dir / job.audio_file_name,
        )
    completed_ids = {item.fixture_id for item in state.completed_jobs}
    for job in plan.jobs:
        output_path = output_dir / job.audio_file_name
        output_exists = require_regular_file_or_absent(
            output_path,
            "planned final output",
        )
        if (
            output_exists
            and job.fixture_id not in completed_ids
            and job.fixture_id != uncommitted_fixture_id
        ):
            raise ElevenLabsStateError(
                f"existing output lacks matching completed state: {job.audio_file_name}"
            )
        pending_path = pending_output_path(output_dir, job)
        pending_exists = require_regular_file_or_absent(
            pending_path,
            "planned pending output",
        )
        if pending_exists and job.fixture_id != uncommitted_fixture_id:
            raise ElevenLabsStateError(
                f"pending output lacks matching materialized state: {pending_path.name}"
            )


def validate_completed_output(
    completed: CompletedJobState,
    *,
    path: Path,
) -> None:
    if not require_regular_file_or_absent(path, "checkpointed output"):
        raise ElevenLabsStateError(
            f"checkpointed output is missing: {path.name}"
        )
    try:
        audio = inspect_wav(path)
    except (OSError, ValueError, wave.Error) as error:
        raise ElevenLabsStateError(
            f"checkpointed output is invalid: {path.name}"
        ) from error
    expected_audio = (
        completed.output_sha256,
        completed.output_bytes,
        completed.duration_ms,
        completed.sample_rate_hz,
    )
    actual_audio = (
        audio["sha256"],
        audio["byteLength"],
        audio["durationMs"],
        audio["sampleRateHz"],
    )
    if actual_audio != expected_audio or completed.sample_rate_hz != 16000:
        raise ElevenLabsStateError(
            f"checkpointed output does not match state: {path.name}"
        )
    if completed.duration_ms < MIN_GENERATED_AUDIO_MS:
        raise ElevenLabsStateError(
            f"checkpointed output is shorter than {MIN_GENERATED_AUDIO_MS} ms"
        )


def publish_materialized_output(
    *,
    completed: CompletedJobState,
    pending_path: Path,
    output_path: Path,
) -> None:
    pending_exists = require_regular_file_or_absent(
        pending_path,
        "materialized pending output",
    )
    output_exists = require_regular_file_or_absent(
        output_path,
        "materialized final output",
    )
    if pending_exists:
        validate_completed_output(completed, path=pending_path)
    if output_exists:
        validate_completed_output(completed, path=output_path)
    if not pending_exists and not output_exists:
        raise ElevenLabsStateError("materialized output is missing")
    if pending_exists and not output_exists:
        try:
            os.link(pending_path, output_path, follow_symlinks=False)
        except FileExistsError:
            require_regular_file_or_absent(
                output_path,
                "materialized final output",
            )
            validate_completed_output(completed, path=output_path)
    if require_regular_file_or_absent(
        output_path,
        "materialized final output",
    ):
        validate_completed_output(completed, path=output_path)
    if require_regular_file_or_absent(
        pending_path,
        "materialized pending output",
    ):
        pending_path.unlink()
    sync_directory(output_path.parent)


def voice_provisioning_sha256(voice: VoiceSpec, asset_dir: Path) -> str:
    if isinstance(voice, VoiceDesign):
        request = {
            "kind": voice.kind,
            "name": voice.name,
            "description": voice.description,
            "previewText": voice.preview_text,
            "previewIndex": voice.preview_index,
            "modelId": voice.model_id,
        }
        return sha256_json(request)
    _, reference_bytes = load_owner_reference(voice, asset_dir)
    return owner_voice_provisioning_sha256(voice, reference_bytes)


def load_owner_reference(
    voice: OwnerClone,
    asset_dir: Path,
) -> tuple[Path, bytes]:
    reference_path = (asset_dir / voice.reference_audio_file_name).resolve()
    if not reference_path.is_file():
        raise ElevenLabsPlanError(
            f"owner clone reference is missing: {voice.reference_audio_file_name}"
        )
    reference_bytes = reference_path.read_bytes()
    if len(reference_bytes) == 0:
        raise ElevenLabsPlanError("owner clone reference is empty")
    return reference_path, reference_bytes


def owner_voice_provisioning_sha256(
    voice: OwnerClone,
    reference_bytes: bytes,
) -> str:
    request = {
        "kind": voice.kind,
        "name": voice.name,
        "description": voice.description,
        "referenceAudioFileName": voice.reference_audio_file_name,
        "referenceAudioSha256": hashlib.sha256(reference_bytes).hexdigest(),
        "sourceSubjectId": voice.source_subject_id,
        "consentReference": voice.consent_reference,
        "retentionClass": voice.retention_class,
    }
    return sha256_json(request)


def synthesis_request(
    plan: ElevenLabsPlan,
    job: ElevenLabsJob,
    voice_id: str,
) -> dict[str, Any]:
    return {
        "voiceId": voice_id,
        "text": job.text,
        "modelId": plan.tts_model_id,
        "outputFormat": OUTPUT_FORMAT,
        "settings": plan.settings,
        "seed": job.seed,
    }


def add_resolved_voice(
    state: GenerationState,
    resolved: ResolvedVoiceState,
) -> GenerationState:
    pending = state.pending_operation
    if not isinstance(pending, PendingVoiceState) or pending.voice_key != resolved.voice_key:
        raise ElevenLabsStateError("resolved voice lacks matching pending operation")
    if any(item.voice_key == resolved.voice_key for item in state.resolved_voices):
        raise ElevenLabsStateError(f"voice is already resolved: {resolved.voice_key}")
    if any(item.voice_id == resolved.voice_id for item in state.resolved_voices):
        raise ElevenLabsStateError(f"voice id is already resolved: {resolved.voice_id}")
    return replace(
        state,
        resolved_voices=(*state.resolved_voices, resolved),
        pending_operation=None,
    )


def add_completed_job(
    state: GenerationState,
    completed: CompletedJobState,
) -> GenerationState:
    pending = state.pending_operation
    if (
        not isinstance(pending, MaterializedJobState)
        or pending.completed != completed
    ):
        raise ElevenLabsStateError("completed job lacks matching materialized state")
    if any(item.fixture_id == completed.fixture_id for item in state.completed_jobs):
        raise ElevenLabsStateError(f"job is already complete: {completed.fixture_id}")
    return replace(
        state,
        completed_jobs=(*state.completed_jobs, completed),
        pending_operation=None,
    )


def set_pending_operation(
    state: GenerationState,
    pending: PendingOperation,
) -> GenerationState:
    if state.pending_operation is not None:
        raise ElevenLabsStateError("generation state already has a pending operation")
    return replace(state, pending_operation=pending)


def persist_generation_state(path: Path, state: GenerationState) -> None:
    require_regular_file_or_absent(
        path.expanduser(),
        "generation state",
    )
    state_path = path.expanduser().resolve()
    state_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = state_path.with_name(
        f".{state_path.name}.{os.getpid()}.tmp"
    )
    try:
        with temporary_path.open("x", encoding="utf-8") as output:
            output.write(json.dumps(generation_state_to_json(state), indent=2) + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, state_path)
        sync_directory(state_path.parent)
    finally:
        temporary_path.unlink(missing_ok=True)


def generation_state_to_json(state: GenerationState) -> dict[str, Any]:
    return {
        "schemaVersion": STATE_SCHEMA_VERSION,
        "datasetVersion": state.dataset_version,
        "planSha256": state.plan_sha256,
        "createdAt": state.created_at,
        "resolvedVoices": [
            {
                "voiceKey": resolved.voice_key,
                "voiceId": resolved.voice_id,
                "provisioningSha256": resolved.provisioning_sha256,
            }
            for resolved in state.resolved_voices
        ],
        "completedJobs": [
            completed_job_state_to_json(completed)
            for completed in state.completed_jobs
        ],
        "pendingOperation": pending_operation_to_json(state.pending_operation),
    }


def completed_job_state_to_json(completed: CompletedJobState) -> dict[str, Any]:
    return {
        "fixtureId": completed.fixture_id,
        "requestSha256": completed.request_sha256,
        "outputSha256": completed.output_sha256,
        "outputBytes": completed.output_bytes,
        "durationMs": completed.duration_ms,
        "sampleRateHz": completed.sample_rate_hz,
        "capturedAt": completed.captured_at,
        "generationMs": completed.generation_ms,
    }


def pending_operation_to_json(
    pending: PendingOperation | None,
) -> dict[str, Any] | None:
    if pending is None:
        return None
    if isinstance(pending, PendingVoiceState):
        return {
            "kind": pending.kind,
            "voiceKey": pending.voice_key,
            "requestSha256": pending.request_sha256,
        }
    if isinstance(pending, PendingJobState):
        return {
            "kind": pending.kind,
            "fixtureId": pending.fixture_id,
            "requestSha256": pending.request_sha256,
        }
    return {
        "kind": pending.kind,
        "completed": completed_job_state_to_json(pending.completed),
    }


def require_sha256(data: dict[str, Any], field_name: str) -> str:
    value = require_string(data, field_name).lower()
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ElevenLabsStateError(f"{field_name} must be a SHA-256 digest")
    return value


def require_iso_timestamp(data: dict[str, Any], field_name: str) -> str:
    value = require_string(data, field_name)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ElevenLabsStateError(
            f"{field_name} must be an ISO date-time"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ElevenLabsStateError(f"{field_name} must include a UTC offset")
    return value


def require_remote_voice_id(value: str) -> str:
    if not isinstance(value, str) or value.strip() == "":
        raise ElevenLabsPlanError("ElevenLabs returned an invalid voice id")
    return value.strip()


def sync_file_and_parent(path: Path) -> None:
    with path.open("rb") as output:
        os.fsync(output.fileno())
    sync_directory(path.parent)


def sync_directory(path: Path) -> None:
    directory = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def validate_generation_paths(
    *,
    plan: ElevenLabsPlan,
    asset_dir: Path,
    output_dir: Path,
    state_path: Path,
) -> None:
    planned_audio = planned_audio_paths(plan, output_dir)
    owner_assets = owner_asset_paths(plan, asset_dir)
    audio_input_conflicts = planned_audio & owner_assets
    if audio_input_conflicts:
        conflict = sorted(str(path) for path in audio_input_conflicts)[0]
        raise ElevenLabsStateError(
            f"planned audio path conflicts with owner input: {conflict}"
        )
    campaign_paths = {
        generation_campaign_binding_path(output_dir),
        generation_campaign_lock_path(output_dir),
    }
    forbidden_state_paths = planned_audio | owner_assets | campaign_paths
    forbidden_state_paths.add(output_dir.expanduser().resolve())
    if state_path.expanduser().resolve() in forbidden_state_paths:
        raise ElevenLabsStateError(
            "generation state path conflicts with planned audio or input"
        )
    if generation_state_lock_path(state_path) in forbidden_state_paths:
        raise ElevenLabsStateError(
            "generation state lock path conflicts with planned audio or input"
        )


def generate_plan(
    plan: ElevenLabsPlan,
    *,
    client: ElevenLabsApi,
    asset_dir: Path,
    output_dir: Path,
    state_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    validate_generation_paths(
        plan=plan,
        asset_dir=asset_dir,
        output_dir=output_dir,
        state_path=state_path,
    )
    with generation_campaign_lock(
        plan=plan,
        output_dir=output_dir,
        state_path=state_path,
    ) as campaign_exists:
        state = load_or_create_generation_state(
            state_path,
            plan=plan,
            asset_dir=asset_dir,
            output_dir=output_dir,
        )
        if not campaign_exists:
            bind_generation_campaign(
                plan=plan,
                output_dir=output_dir,
                state_path=state_path,
            )
        return generate_plan_with_lock(
            plan,
            client=client,
            asset_dir=asset_dir,
            output_dir=output_dir,
            state_path=state_path,
            state=state,
        )


def generate_plan_with_lock(
    plan: ElevenLabsPlan,
    *,
    client: ElevenLabsApi,
    asset_dir: Path,
    output_dir: Path,
    state_path: Path,
    state: GenerationState,
) -> tuple[dict[str, Any], dict[str, Any]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    voice_ids, state = provision_voices(
        plan.voices,
        client=client,
        asset_dir=asset_dir,
        state=state,
        state_path=state_path,
    )
    completed_jobs = {
        completed.fixture_id: completed for completed in state.completed_jobs
    }
    voices = {voice.voice_key: voice for voice in plan.voices}
    entries: list[dict[str, Any]] = []
    report_entries: list[dict[str, Any]] = []
    for job in plan.jobs:
        completed = completed_jobs.get(job.fixture_id)
        if completed is not None:
            entry, report_entry = completed_job_outputs(
                plan=plan,
                job=job,
                voice=voices[job.voice_key],
                voice_id=voice_ids[job.voice_key],
                completed=completed,
            )
            entries.append(entry)
            report_entries.append(report_entry)
            continue
        request = synthesis_request(plan, job, voice_ids[job.voice_key])
        request_hash = sha256_json(request)
        state = set_pending_operation(
            state,
            PendingJobState(
                kind="synthesize_job",
                fixture_id=job.fixture_id,
                request_sha256=request_hash,
            ),
        )
        persist_generation_state(state_path, state)
        started = time.perf_counter()
        pcm = client.synthesize(
            voice_id=voice_ids[job.voice_key],
            text=job.text,
            model_id=plan.tts_model_id,
            settings=plan.settings,
            seed=job.seed,
        )
        pending_path = pending_output_path(output_dir, job)
        write_pcm_wav(pending_path, pcm)
        sync_file_and_parent(pending_path)
        audio = inspect_wav(pending_path)
        del pcm
        output_path = output_dir / job.audio_file_name
        captured_at = utc_now()
        completed = CompletedJobState(
            fixture_id=job.fixture_id,
            request_sha256=request_hash,
            output_sha256=audio["sha256"],
            output_bytes=audio["byteLength"],
            duration_ms=audio["durationMs"],
            sample_rate_hz=audio["sampleRateHz"],
            captured_at=captured_at,
            generation_ms=round((time.perf_counter() - started) * 1000, 3),
        )
        validate_completed_output(completed, path=pending_path)
        state = replace(
            state,
            pending_operation=MaterializedJobState(
                kind="materialized_job",
                completed=completed,
            ),
        )
        persist_generation_state(state_path, state)
        publish_materialized_output(
            completed=completed,
            pending_path=pending_path,
            output_path=output_path,
        )
        state = add_completed_job(state, completed)
        persist_generation_state(state_path, state)
        completed_jobs[job.fixture_id] = completed
        entries.append(
            benchmark_entry(
                plan=plan,
                job=job,
                voice=voices[job.voice_key],
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
                "generationMs": completed.generation_ms,
            }
        )
    return (
        {
            "schemaVersion": BENCHMARK_SCHEMA_VERSION,
            "datasetVersion": plan.dataset_version,
            "createdAt": state.created_at,
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
    state: GenerationState,
    state_path: Path,
) -> tuple[dict[str, str], GenerationState]:
    result = {
        resolved.voice_key: resolved.voice_id for resolved in state.resolved_voices
    }
    for voice in voices:
        if voice.voice_key in result:
            continue
        if isinstance(voice, VoiceDesign):
            provisioning_sha256 = voice_provisioning_sha256(voice, asset_dir)
            state = set_pending_operation(
                state,
                PendingVoiceState(
                    kind="provision_voice",
                    voice_key=voice.voice_key,
                    request_sha256=provisioning_sha256,
                ),
            )
            persist_generation_state(state_path, state)
            voice_id = require_remote_voice_id(client.design_voice(voice))
        else:
            reference_path, reference_bytes = load_owner_reference(voice, asset_dir)
            provisioning_sha256 = owner_voice_provisioning_sha256(
                voice,
                reference_bytes,
            )
            state = set_pending_operation(
                state,
                PendingVoiceState(
                    kind="provision_voice",
                    voice_key=voice.voice_key,
                    request_sha256=provisioning_sha256,
                ),
            )
            persist_generation_state(state_path, state)
            voice_id = require_remote_voice_id(
                client.clone_voice(
                    voice,
                    reference_path,
                    reference_bytes,
                )
            )
        resolved = ResolvedVoiceState(
            voice_key=voice.voice_key,
            voice_id=voice_id,
            provisioning_sha256=provisioning_sha256,
        )
        state = add_resolved_voice(state, resolved)
        persist_generation_state(state_path, state)
        result[voice.voice_key] = voice_id
    return result, state


def completed_job_outputs(
    *,
    plan: ElevenLabsPlan,
    job: ElevenLabsJob,
    voice: VoiceSpec,
    voice_id: str,
    completed: CompletedJobState,
) -> tuple[dict[str, Any], dict[str, Any]]:
    audio = {
        "sha256": completed.output_sha256,
        "byteLength": completed.output_bytes,
        "durationMs": completed.duration_ms,
        "sampleRateHz": completed.sample_rate_hz,
    }
    return (
        benchmark_entry(
            plan=plan,
            job=job,
            voice=voice,
            voice_id=voice_id,
            audio=audio,
            request_hash=completed.request_sha256,
            captured_at=completed.captured_at,
        ),
        {
            "fixtureId": completed.fixture_id,
            "voiceKey": job.voice_key,
            "voiceId": voice_id,
            "requestHash": completed.request_sha256,
            "outputSha256": completed.output_sha256,
            "generationMs": completed.generation_ms,
        },
    )


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
    duration_ms = (len(pcm) // 2) * 1000 // 16000
    if duration_ms < MIN_GENERATED_AUDIO_MS:
        raise ElevenLabsPlanError(
            f"ElevenLabs PCM response must contain at least {MIN_GENERATED_AUDIO_MS} ms"
        )
    with path.open("xb") as raw_output:
        with wave.open(raw_output, "wb") as output:
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


def load_api_key(*, environment: dict[str, str], env_path: Path) -> str:
    configured = environment.get("ELEVENLABS_API_KEY", "").strip()
    if configured:
        return configured
    if not env_path.is_file():
        return ""
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line == "" or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        name, separator, value = line.partition("=")
        if separator != "=" or name.strip() != "ELEVENLABS_API_KEY":
            continue
        normalized = value.strip()
        if (
            len(normalized) >= 2
            and normalized[0] == normalized[-1]
            and normalized[0] in "'\""
        ):
            normalized = normalized[1:-1]
        return normalized
    return ""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a provenance-pinned ElevenLabs VoiceID corpus batch."
    )
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--asset-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--manifest-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    args = parser.parse_args()
    plan = load_plan(args.plan)
    validate_cli_paths(
        plan_path=args.plan,
        plan=plan,
        asset_dir=args.asset_dir,
        output_dir=args.output_dir,
        state_path=args.state,
        manifest_path=args.manifest_out,
        report_path=args.report_out,
    )
    api_key = load_api_key(
        environment=dict(os.environ),
        env_path=args.plan.parents[2] / ".env.local",
    )
    manifest, report = generate_plan(
        plan,
        client=ElevenLabsHttpClient(api_key),
        asset_dir=args.asset_dir,
        output_dir=args.output_dir,
        state_path=args.state,
    )
    write_json(args.manifest_out, manifest)
    write_json(args.report_out, report)


if __name__ == "__main__":
    main()
