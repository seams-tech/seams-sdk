from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import time
import wave
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal


PLAN_SCHEMA_VERSION = "voice_id_dia2_generation_plan_v1"
REPORT_SCHEMA_VERSION = "voice_id_dia2_generation_report_v1"
STATE_SCHEMA_VERSION = "voice_id_dia2_generation_state_v1"
BENCHMARK_SCHEMA_VERSION = "voice_id_benchmark_manifest_v2"
PARTITIONS = frozenset({"development", "calibration", "evaluation"})
CASE_KINDS = frozenset(
    {
        "enrollment",
        "genuine_verification",
        "zero_effort_impostor",
        "challenge_error",
        "presentation_attack",
    }
)
CHALLENGE_ERROR_KINDS = frozenset(
    {"substitution", "omission", "insertion", "reordering", "ambiguous"}
)
ATTACK_CLASSES = frozenset(
    {"replay", "synthesis", "voice_conversion", "splice", "relay", "digital_injection"}
)
INTENTS = frozenset({"approve", "reject", "cancel", "repeat", "unrelated"})


class Dia2PlanError(ValueError):
    pass


@dataclass(frozen=True)
class Checkpoint:
    repo_id: str
    revision: str
    mimi_repo_id: str
    mimi_revision: str


@dataclass(frozen=True)
class GenerationSettings:
    dtype: str
    text_temperature: float
    text_top_k: int
    audio_temperature: float
    audio_top_k: int
    cfg_scale: float
    use_cuda_graph: bool


@dataclass(frozen=True)
class NoPrefix:
    kind: Literal["none"]


@dataclass(frozen=True)
class GeneratedFixturePrefix:
    kind: Literal["generated_fixture"]
    fixture_id: str


@dataclass(frozen=True)
class ConsentedAudioPrefix:
    kind: Literal["consented_audio"]
    audio_file_name: str


GenerationPrefix = NoPrefix | GeneratedFixturePrefix | ConsentedAudioPrefix


@dataclass(frozen=True)
class Conditioning:
    source_subject_id: str
    consent_reference: str
    retention_class: str


@dataclass(frozen=True)
class Dia2Job:
    fixture_id: str
    audio_file_name: str
    subject_id: str
    session_id: str
    partition: str
    case: dict[str, Any]
    expected_intent: str | None
    challenge_tokens: tuple[str, ...]
    seed: int
    script: str
    prefix: GenerationPrefix
    voice: str
    conditioning: Conditioning | None


@dataclass(frozen=True)
class Dia2Plan:
    path: Path
    dataset_version: str
    repository_revision: str
    checkpoint: Checkpoint
    settings: GenerationSettings
    capture: dict[str, Any]
    jobs: tuple[Dia2Job, ...]


def load_plan(path: Path) -> Dia2Plan:
    plan_path = path.expanduser().resolve()
    value = read_json_object(plan_path)
    require_exact_keys(
        value,
        "plan",
        {
            "schemaVersion",
            "datasetVersion",
            "repositoryRevision",
            "checkpoint",
            "settings",
            "capture",
            "jobs",
        },
    )
    if require_string(value, "schemaVersion") != PLAN_SCHEMA_VERSION:
        raise Dia2PlanError(f"schemaVersion must be {PLAN_SCHEMA_VERSION}")
    jobs_value = value["jobs"]
    if not isinstance(jobs_value, list) or len(jobs_value) == 0:
        raise Dia2PlanError("jobs must be a non-empty array")
    jobs = tuple(parse_job(job, index) for index, job in enumerate(jobs_value))
    enforce_job_order(jobs)
    return Dia2Plan(
        path=plan_path,
        dataset_version=require_string(value, "datasetVersion"),
        repository_revision=require_sha(value, "repositoryRevision"),
        checkpoint=parse_checkpoint(value["checkpoint"]),
        settings=parse_settings(value["settings"]),
        capture=parse_capture(value["capture"]),
        jobs=jobs,
    )


def parse_checkpoint(value: object) -> Checkpoint:
    data = require_object(value, "checkpoint")
    require_exact_keys(
        data,
        "checkpoint",
        {"repoId", "revision", "mimiRepoId", "mimiRevision"},
    )
    return Checkpoint(
        repo_id=require_string(data, "repoId"),
        revision=require_sha(data, "revision"),
        mimi_repo_id=require_string(data, "mimiRepoId"),
        mimi_revision=require_sha(data, "mimiRevision"),
    )


def parse_settings(value: object) -> GenerationSettings:
    data = require_object(value, "settings")
    require_exact_keys(
        data,
        "settings",
        {
            "dtype",
            "textTemperature",
            "textTopK",
            "audioTemperature",
            "audioTopK",
            "cfgScale",
            "useCudaGraph",
        },
    )
    dtype = require_string(data, "dtype")
    if dtype not in {"bfloat16", "float32"}:
        raise Dia2PlanError("settings.dtype must be bfloat16 or float32")
    use_cuda_graph = data["useCudaGraph"]
    if not isinstance(use_cuda_graph, bool):
        raise Dia2PlanError("settings.useCudaGraph must be a boolean")
    return GenerationSettings(
        dtype=dtype,
        text_temperature=require_positive_number(data, "textTemperature"),
        text_top_k=require_positive_int(data, "textTopK"),
        audio_temperature=require_positive_number(data, "audioTemperature"),
        audio_top_k=require_positive_int(data, "audioTopK"),
        cfg_scale=require_positive_number(data, "cfgScale"),
        use_cuda_graph=use_cuda_graph,
    )


def parse_capture(value: object) -> dict[str, Any]:
    data = require_object(value, "capture")
    require_exact_keys(
        data,
        "capture",
        {
            "platform",
            "microphone",
            "room",
            "distanceCm",
            "codec",
            "channelCount",
            "language",
            "accent",
            "noiseProfile",
        },
    )
    if require_string(data, "platform") != "server":
        raise Dia2PlanError("Dia2 capture platform must be server")
    if require_non_negative_number(data, "distanceCm") != 0:
        raise Dia2PlanError("Dia2 digital generation distanceCm must be zero")
    channel_count = require_positive_int(data, "channelCount")
    if channel_count != 1:
        raise Dia2PlanError("Dia2 benchmark capture must be mono")
    return {
        "platform": "server",
        "microphone": require_string(data, "microphone"),
        "room": require_string(data, "room"),
        "distanceCm": 0,
        "codec": require_string(data, "codec"),
        "channelCount": channel_count,
        "language": require_string(data, "language"),
        "accent": require_string(data, "accent"),
        "noiseProfile": require_string(data, "noiseProfile"),
    }


def parse_job(value: object, index: int) -> Dia2Job:
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
            "seed",
            "script",
            "prefix",
            "voice",
            "conditioning",
        },
    )
    case = parse_case(data["case"], field_name)
    expected_intent = parse_expected_intent(data["expectedIntent"], case["kind"])
    challenge_tokens = parse_challenge_tokens(data["challengeTokens"], case["kind"])
    prefix = parse_prefix(data["prefix"], field_name)
    conditioning = parse_conditioning(data["conditioning"], field_name)
    if isinstance(prefix, ConsentedAudioPrefix) and conditioning is None:
        raise Dia2PlanError(f"{field_name} consented prefix requires conditioning metadata")
    if not isinstance(prefix, ConsentedAudioPrefix) and conditioning is not None:
        raise Dia2PlanError(f"{field_name} conditioning is allowed only for consented audio")
    audio_file_name = require_file_name(data, "audioFileName")
    if Path(audio_file_name).suffix.lower() != ".wav":
        raise Dia2PlanError(f"{field_name}.audioFileName must use .wav")
    seed = require_non_negative_int(data, "seed")
    return Dia2Job(
        fixture_id=require_identifier(data, "fixtureId"),
        audio_file_name=audio_file_name,
        subject_id=require_identifier(data, "subjectId"),
        session_id=require_identifier(data, "sessionId"),
        partition=require_one_of(data, "partition", PARTITIONS),
        case=case,
        expected_intent=expected_intent,
        challenge_tokens=challenge_tokens,
        seed=seed,
        script=require_string(data, "script"),
        prefix=prefix,
        voice=require_identifier(data, "voice"),
        conditioning=conditioning,
    )


def parse_case(value: object, field_name: str) -> dict[str, Any]:
    data = require_object(value, f"{field_name}.case")
    kind = require_one_of(data, "kind", CASE_KINDS)
    if kind in {"enrollment", "genuine_verification"}:
        require_exact_keys(data, f"{field_name}.case", {"kind"})
        return {"kind": kind}
    if kind == "zero_effort_impostor":
        require_exact_keys(data, f"{field_name}.case", {"kind", "targetSubjectId"})
        return {"kind": kind, "targetSubjectId": require_identifier(data, "targetSubjectId")}
    if kind == "challenge_error":
        require_exact_keys(data, f"{field_name}.case", {"kind", "errorKind"})
        return {
            "kind": kind,
            "errorKind": require_one_of(data, "errorKind", CHALLENGE_ERROR_KINDS),
        }
    require_exact_keys(
        data,
        f"{field_name}.case",
        {"kind", "targetSubjectId", "attackClass", "attackTool"},
    )
    return {
        "kind": kind,
        "targetSubjectId": require_identifier(data, "targetSubjectId"),
        "attackClass": require_one_of(data, "attackClass", ATTACK_CLASSES),
        "attackTool": require_string(data, "attackTool"),
    }


def parse_expected_intent(value: object, case_kind: str) -> str | None:
    if case_kind == "enrollment":
        if value is not None:
            raise Dia2PlanError("enrollment expectedIntent must be null")
        return None
    if not isinstance(value, str) or value not in INTENTS:
        raise Dia2PlanError("verification expectedIntent is invalid")
    return value


def parse_challenge_tokens(value: object, case_kind: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(token, str) for token in value):
        raise Dia2PlanError("challengeTokens must be an array of strings")
    tokens = tuple(token.strip().lower() for token in value)
    if any(token == "" for token in tokens) or len(tokens) != len(set(tokens)):
        raise Dia2PlanError("challengeTokens must contain unique non-empty strings")
    if case_kind == "enrollment" and len(tokens) != 0:
        raise Dia2PlanError("enrollment challengeTokens must be empty")
    if case_kind != "enrollment" and len(tokens) == 0:
        raise Dia2PlanError("verification challengeTokens must not be empty")
    return tokens


def parse_prefix(value: object, field_name: str) -> GenerationPrefix:
    data = require_object(value, f"{field_name}.prefix")
    kind = require_string(data, "kind")
    if kind == "none":
        require_exact_keys(data, f"{field_name}.prefix", {"kind"})
        return NoPrefix(kind="none")
    if kind == "generated_fixture":
        require_exact_keys(data, f"{field_name}.prefix", {"kind", "fixtureId"})
        return GeneratedFixturePrefix(
            kind="generated_fixture",
            fixture_id=require_identifier(data, "fixtureId"),
        )
    if kind == "consented_audio":
        require_exact_keys(data, f"{field_name}.prefix", {"kind", "audioFileName"})
        return ConsentedAudioPrefix(
            kind="consented_audio",
            audio_file_name=require_file_name(data, "audioFileName"),
        )
    raise Dia2PlanError(f"{field_name}.prefix.kind is invalid")


def parse_conditioning(value: object, field_name: str) -> Conditioning | None:
    if value is None:
        return None
    data = require_object(value, f"{field_name}.conditioning")
    require_exact_keys(
        data,
        f"{field_name}.conditioning",
        {"sourceSubjectId", "consentReference", "retentionClass"},
    )
    return Conditioning(
        source_subject_id=require_identifier(data, "sourceSubjectId"),
        consent_reference=require_string(data, "consentReference"),
        retention_class=require_string(data, "retentionClass"),
    )


def enforce_job_order(jobs: tuple[Dia2Job, ...]) -> None:
    fixture_ids: set[str] = set()
    audio_file_names: set[str] = set()
    subject_partitions: dict[str, str] = {}
    for job in jobs:
        if job.fixture_id in fixture_ids:
            raise Dia2PlanError(f"fixtureId {job.fixture_id} is duplicated")
        if job.audio_file_name in audio_file_names:
            raise Dia2PlanError(f"audioFileName {job.audio_file_name} is duplicated")
        if isinstance(job.prefix, GeneratedFixturePrefix) and job.prefix.fixture_id not in fixture_ids:
            raise Dia2PlanError(
                f"generated prefix {job.prefix.fixture_id} must appear before {job.fixture_id}"
            )
        previous_partition = subject_partitions.setdefault(job.subject_id, job.partition)
        if previous_partition != job.partition:
            raise Dia2PlanError(
                f"subject {job.subject_id} crosses {previous_partition} and {job.partition}"
            )
        fixture_ids.add(job.fixture_id)
        audio_file_names.add(job.audio_file_name)


def generate_plan(
    plan: Dia2Plan,
    *,
    source_root: Path,
    model_dir: Path,
    mimi_dir: Path,
    asset_dir: Path,
    output_dir: Path,
    state_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    output_dir = output_dir.expanduser().resolve()
    state_path = state_path.expanduser().resolve()
    if state_path in {
        output_dir / "manifest.json",
        output_dir / "report.json",
    }:
        raise Dia2PlanError("state path must be distinct from output artifacts")
    output_dir.mkdir(parents=True, exist_ok=True)
    verify_source_revision(source_root, plan.repository_revision)
    verify_snapshot_revision(model_dir, plan.checkpoint.revision)
    verify_snapshot_revision(mimi_dir, plan.checkpoint.mimi_revision)
    state = load_or_create_state(
        state_path,
        plan=plan,
        output_dir=output_dir,
    )
    completed = state["completed"]
    benchmark_entries = [item["benchmarkEntry"] for item in completed]
    report_entries = [item["reportEntry"] for item in completed]
    generated_paths = {
        item["fixtureId"]: output_dir / item["benchmarkEntry"]["audioFileName"]
        for item in completed
    }
    remaining_jobs = plan.jobs[len(completed) :]
    model_load_ms = state["modelLoadMs"]
    engine = None
    try:
        if remaining_jobs:
            Dia2, GenerationConfig, SamplingConfig, torch = load_dia2(source_root)
            model_load_started = time.perf_counter()
            engine = Dia2.from_local(
                config_path=model_dir / "config.json",
                weights_path=model_dir / "model.safetensors",
                device="cuda",
                dtype=plan.settings.dtype,
                tokenizer_id=model_dir,
                mimi_id=str(mimi_dir),
            )
            generation_config = GenerationConfig(
                text=SamplingConfig(
                    temperature=plan.settings.text_temperature,
                    top_k=plan.settings.text_top_k,
                ),
                audio=SamplingConfig(
                    temperature=plan.settings.audio_temperature,
                    top_k=plan.settings.audio_top_k,
                ),
                cfg_scale=plan.settings.cfg_scale,
                use_cuda_graph=plan.settings.use_cuda_graph,
            )
            engine._ensure_runtime()
            model_load_ms = elapsed_ms(model_load_started)
            state["modelLoadMs"] = round(model_load_ms, 3)
            write_generation_state(state_path, state)
        for job in remaining_jobs:
            prefix_path = resolve_prefix_path(
                job.prefix,
                generated_paths=generated_paths,
                asset_dir=asset_dir,
            )
            output_path = output_dir / job.audio_file_name
            pending_path = pending_output_path(output_dir, job)
            if pending_path.exists():
                raise Dia2PlanError(
                    f"pending Dia2 output requires manual reconciliation: {pending_path.name}"
                )
            request = generation_request(
                plan=plan,
                job=job,
                prefix_path=prefix_path,
            )
            torch.manual_seed(job.seed)
            torch.cuda.manual_seed_all(job.seed)
            started = time.perf_counter()
            engine.generate(
                job.script,
                config=generation_config,
                output_wav=pending_path,
                prefix_speaker_1=str(prefix_path) if prefix_path is not None else None,
                include_prefix=False,
                verbose=False,
            )
            generation_ms = elapsed_ms(started)
            install_immutable_audio(pending_path, output_path)
            audio = inspect_wav(output_path)
            captured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            request_hash = sha256_json(request)
            benchmark_value = benchmark_entry(
                plan=plan,
                job=job,
                audio=audio,
                request_hash=request_hash,
                captured_at=captured_at,
            )
            report_value = {
                "fixtureId": job.fixture_id,
                "audioFileName": job.audio_file_name,
                "generationMs": round(generation_ms, 3),
                "requestHash": request_hash,
                "outputSha256": audio["sha256"],
                "outputBytes": audio["byteLength"],
                "durationMs": audio["durationMs"],
                "sampleRateHz": audio["sampleRateHz"],
                "request": request,
            }
            benchmark_entries.append(benchmark_value)
            report_entries.append(report_value)
            state["completed"].append(
                {
                    "fixtureId": job.fixture_id,
                    "benchmarkEntry": benchmark_value,
                    "reportEntry": report_value,
                }
            )
            generated_paths[job.fixture_id] = output_path
            write_generation_state(state_path, state)
    finally:
        if engine is not None:
            engine.close()
    state["status"] = "complete"
    write_generation_state(state_path, state)
    manifest = {
        "schemaVersion": BENCHMARK_SCHEMA_VERSION,
        "datasetVersion": plan.dataset_version,
        "createdAt": state["createdAt"],
        "entries": benchmark_entries,
    }
    report = {
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "datasetVersion": plan.dataset_version,
        "repositoryRevision": plan.repository_revision,
        "checkpoint": {
            "repoId": plan.checkpoint.repo_id,
            "revision": plan.checkpoint.revision,
            "mimiRepoId": plan.checkpoint.mimi_repo_id,
            "mimiRevision": plan.checkpoint.mimi_revision,
        },
        "settings": settings_to_json(plan.settings),
        "modelLoadMs": model_load_ms,
        "fixtureCount": len(report_entries),
        "failureCount": 0,
        "entries": report_entries,
    }
    return manifest, report


def load_or_create_state(
    state_path: Path,
    *,
    plan: Dia2Plan,
    output_dir: Path,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise Dia2PlanError(f"cannot read Dia2 generation state: {error}") from error
        validate_generation_state(state, plan=plan, state_path=state_path, output_dir=output_dir)
        return state
    state = {
        "schemaVersion": STATE_SCHEMA_VERSION,
        "datasetVersion": plan.dataset_version,
        "planSha256": sha256_file(plan.path),
        "outputDir": str(output_dir),
        "createdAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "status": "running",
        "modelLoadMs": None,
        "completed": [],
    }
    validate_generation_state(state, plan=plan, state_path=state_path, output_dir=output_dir)
    write_generation_state(state_path, state)
    return state


def validate_generation_state(
    state: object,
    *,
    plan: Dia2Plan,
    state_path: Path,
    output_dir: Path,
) -> None:
    if not isinstance(state, dict):
        raise Dia2PlanError("Dia2 generation state must be an object")
    require_exact_keys(
        state,
        "generation state",
        {
            "schemaVersion",
            "datasetVersion",
            "planSha256",
            "outputDir",
            "createdAt",
            "status",
            "modelLoadMs",
            "completed",
        },
    )
    if state.get("schemaVersion") != STATE_SCHEMA_VERSION:
        raise Dia2PlanError(f"generation state schemaVersion must be {STATE_SCHEMA_VERSION}")
    if state.get("datasetVersion") != plan.dataset_version:
        raise Dia2PlanError("generation state dataset does not match plan")
    if state.get("planSha256") != sha256_file(plan.path):
        raise Dia2PlanError("generation state plan does not match plan input")
    if state.get("outputDir") != str(output_dir):
        raise Dia2PlanError("generation state output directory does not match output")
    require_iso_date_time_value(state.get("createdAt"), "generation state createdAt")
    if state.get("status") not in {"running", "complete"}:
        raise Dia2PlanError("generation state status is invalid")
    model_load_ms = state.get("modelLoadMs")
    if model_load_ms is not None and (
        not isinstance(model_load_ms, int | float) or isinstance(model_load_ms, bool) or model_load_ms < 0
    ):
        raise Dia2PlanError("generation state modelLoadMs is invalid")
    completed = state.get("completed")
    if not isinstance(completed, list) or len(completed) > len(plan.jobs):
        raise Dia2PlanError("generation state completed jobs are invalid")
    if completed and model_load_ms is None:
        raise Dia2PlanError("generation state is missing model load timing")
    for index, item in enumerate(completed):
        if not isinstance(item, dict) or set(item) != {"fixtureId", "benchmarkEntry", "reportEntry"}:
            raise Dia2PlanError("generation state completed entry is invalid")
        job = plan.jobs[index]
        if item["fixtureId"] != job.fixture_id:
            raise Dia2PlanError("generation state completed jobs are out of order")
        benchmark = item["benchmarkEntry"]
        report = item["reportEntry"]
        if not isinstance(benchmark, dict) or not isinstance(report, dict):
            raise Dia2PlanError("generation state completed artifacts are invalid")
        if benchmark.get("fixtureId") != job.fixture_id:
            raise Dia2PlanError("generation state benchmark entry does not match plan")
        if report.get("fixtureId") != job.fixture_id:
            raise Dia2PlanError("generation state report entry does not match plan")
        audio_name = benchmark.get("audioFileName")
        if audio_name != job.audio_file_name:
            raise Dia2PlanError("generation state audio file does not match plan")
        audio_path = output_dir / job.audio_file_name
        if not audio_path.is_file():
            raise Dia2PlanError(f"completed Dia2 output is missing: {job.audio_file_name}")
        audio = inspect_wav(audio_path)
        for key in ("sha256", "byteLength", "durationMs", "sampleRateHz"):
            if benchmark.get("audioSha256" if key == "sha256" else key) != audio[key]:
                raise Dia2PlanError(f"completed Dia2 output does not match state: {job.audio_file_name}")
        if report.get("outputSha256") != audio["sha256"]:
            raise Dia2PlanError(f"completed Dia2 report does not match output: {job.audio_file_name}")
    completed_names = {job.audio_file_name for job in plan.jobs[: len(completed)]}
    for job in plan.jobs[len(completed) :]:
        output_path = output_dir / job.audio_file_name
        pending_path = pending_output_path(output_dir, job)
        if output_path.exists() and job.audio_file_name not in completed_names:
            raise Dia2PlanError(f"uncheckpointed Dia2 output collision: {job.audio_file_name}")
        if pending_path.exists():
            raise Dia2PlanError(f"pending Dia2 output requires manual reconciliation: {pending_path.name}")


def pending_output_path(output_dir: Path, job: Dia2Job) -> Path:
    return output_dir / f".{job.audio_file_name}.pending"


def install_immutable_audio(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise Dia2PlanError(f"Dia2 did not create pending output: {source.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise Dia2PlanError(f"Dia2 output collision: {destination.name}")
    with source.open("rb") as file:
        os.fsync(file.fileno())
    try:
        os.link(source, destination, follow_symlinks=False)
    except FileExistsError as error:
        raise Dia2PlanError(f"Dia2 output collision: {destination.name}") from error
    source.unlink()
    fsync_directory(destination.parent)


def load_dia2(source_root: Path) -> tuple[Any, Any, Any, Any]:
    import sys

    source = str(source_root.resolve())
    if source not in sys.path:
        sys.path.insert(0, source)
    import torch
    from dia2 import Dia2, GenerationConfig, SamplingConfig

    if not torch.cuda.is_available():
        raise RuntimeError("Dia2 corpus generation requires CUDA")
    return Dia2, GenerationConfig, SamplingConfig, torch


def verify_source_revision(source_root: Path, expected_revision: str) -> None:
    head_path = source_root / ".git" / "HEAD"
    if not head_path.is_file():
        raise Dia2PlanError("Dia2 source root must be a git checkout")
    import subprocess

    revision = subprocess.run(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if revision != expected_revision:
        raise Dia2PlanError(
            f"Dia2 source revision {revision} does not match {expected_revision}"
        )


def verify_snapshot_revision(snapshot_dir: Path, expected_revision: str) -> None:
    marker = snapshot_dir / ".voiceid-revision"
    if not marker.is_file() or marker.read_text(encoding="utf-8").strip() != expected_revision:
        raise Dia2PlanError(
            f"snapshot {snapshot_dir} is missing revision marker {expected_revision}"
        )


def resolve_prefix_path(
    prefix: GenerationPrefix,
    *,
    generated_paths: dict[str, Path],
    asset_dir: Path,
) -> Path | None:
    if isinstance(prefix, NoPrefix):
        return None
    if isinstance(prefix, GeneratedFixturePrefix):
        return generated_paths[prefix.fixture_id]
    path = (asset_dir / prefix.audio_file_name).resolve()
    if path.parent != asset_dir.resolve() or not path.is_file():
        raise Dia2PlanError(f"consented prefix is missing: {prefix.audio_file_name}")
    return path


def generation_request(
    *,
    plan: Dia2Plan,
    job: Dia2Job,
    prefix_path: Path | None,
) -> dict[str, Any]:
    return {
        "generator": "dia2",
        "repositoryRevision": plan.repository_revision,
        "checkpoint": {
            "repoId": plan.checkpoint.repo_id,
            "revision": plan.checkpoint.revision,
            "mimiRepoId": plan.checkpoint.mimi_repo_id,
            "mimiRevision": plan.checkpoint.mimi_revision,
        },
        "settings": settings_to_json(plan.settings),
        "seed": job.seed,
        "script": job.script,
        "voice": job.voice,
        "prefix": prefix_to_json(job.prefix),
        "prefixSha256": sha256_file(prefix_path) if prefix_path is not None else None,
    }


def benchmark_entry(
    *,
    plan: Dia2Plan,
    job: Dia2Job,
    audio: dict[str, Any],
    request_hash: str,
    captured_at: str,
) -> dict[str, Any]:
    capture = dict(plan.capture)
    capture["sampleRateHz"] = audio["sampleRateHz"]
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
        "capture": capture,
        "capturedAt": captured_at,
        "durationMs": audio["durationMs"],
        "byteLength": audio["byteLength"],
        "mimeType": "audio/wav",
        "provenance": {
            "kind": "synthetic_generation",
            "generator": "dia2",
            "model": f"{plan.checkpoint.repo_id}@{plan.checkpoint.revision}",
            "voice": job.voice,
            "seed": job.seed,
            "license": "Apache-2.0",
            "requestHash": request_hash,
            "conditioning": conditioning_to_json(job.conditioning),
        },
    }


def inspect_wav(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise Dia2PlanError(f"Dia2 did not create {path.name}")
    with wave.open(str(path), "rb") as wav:
        frame_count = wav.getnframes()
        sample_rate_hz = wav.getframerate()
        channel_count = wav.getnchannels()
        sample_width = wav.getsampwidth()
    if frame_count <= 0 or sample_rate_hz <= 0:
        raise Dia2PlanError(f"Dia2 created an empty WAV: {path.name}")
    if channel_count != 1 or sample_width != 2:
        raise Dia2PlanError(f"Dia2 WAV must be mono PCM16: {path.name}")
    return {
        "sha256": sha256_file(path),
        "byteLength": path.stat().st_size,
        "durationMs": round(frame_count * 1000 / sample_rate_hz),
        "sampleRateHz": sample_rate_hz,
    }


def settings_to_json(settings: GenerationSettings) -> dict[str, Any]:
    return {
        "dtype": settings.dtype,
        "textTemperature": settings.text_temperature,
        "textTopK": settings.text_top_k,
        "audioTemperature": settings.audio_temperature,
        "audioTopK": settings.audio_top_k,
        "cfgScale": settings.cfg_scale,
        "useCudaGraph": settings.use_cuda_graph,
    }


def prefix_to_json(prefix: GenerationPrefix) -> dict[str, Any]:
    if isinstance(prefix, NoPrefix):
        return {"kind": "none"}
    if isinstance(prefix, GeneratedFixturePrefix):
        return {"kind": "generated_fixture", "fixtureId": prefix.fixture_id}
    return {"kind": "consented_audio", "audioFileName": prefix.audio_file_name}


def conditioning_to_json(conditioning: Conditioning | None) -> dict[str, str] | None:
    if conditioning is None:
        return None
    return {
        "sourceSubjectId": conditioning.source_subject_id,
        "consentReference": conditioning.consent_reference,
        "retentionClass": conditioning.retention_class,
    }


def sha256_json(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def elapsed_ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise Dia2PlanError(f"cannot read JSON plan {path}: {error}") from error
    return require_object(value, "plan")


def require_object(value: object, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise Dia2PlanError(f"{field_name} must be an object")
    return value


def require_exact_keys(data: dict[str, Any], field_name: str, keys: set[str]) -> None:
    if set(data.keys()) != keys:
        raise Dia2PlanError(f"{field_name} contains unexpected or missing fields")


def require_string(data: dict[str, Any], field_name: str) -> str:
    value = data.get(field_name)
    if not isinstance(value, str) or value.strip() == "":
        raise Dia2PlanError(f"{field_name} must be a non-empty string")
    return value.strip()


def require_identifier(data: dict[str, Any], field_name: str) -> str:
    value = require_string(data, field_name)
    if not all(character.isalnum() or character in "_-" for character in value):
        raise Dia2PlanError(f"{field_name} must be an identifier")
    return value


def require_file_name(data: dict[str, Any], field_name: str) -> str:
    value = require_string(data, field_name)
    if Path(value).name != value:
        raise Dia2PlanError(f"{field_name} must be a file name")
    return value


def require_sha(data: dict[str, Any], field_name: str) -> str:
    value = require_string(data, field_name).lower()
    if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        raise Dia2PlanError(f"{field_name} must be a 40-character git revision")
    return value


def require_one_of(data: dict[str, Any], field_name: str, allowed: frozenset[str]) -> str:
    value = require_string(data, field_name)
    if value not in allowed:
        raise Dia2PlanError(f"{field_name} is invalid")
    return value


def require_positive_int(data: dict[str, Any], field_name: str) -> int:
    value = data.get(field_name)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise Dia2PlanError(f"{field_name} must be a positive integer")
    return value


def require_non_negative_int(data: dict[str, Any], field_name: str) -> int:
    value = data.get(field_name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise Dia2PlanError(f"{field_name} must be a non-negative integer")
    return value


def require_positive_number(data: dict[str, Any], field_name: str) -> float:
    value = data.get(field_name)
    if not isinstance(value, int | float) or isinstance(value, bool) or value <= 0:
        raise Dia2PlanError(f"{field_name} must be a positive number")
    return float(value)


def require_non_negative_number(data: dict[str, Any], field_name: str) -> float:
    value = data.get(field_name)
    if not isinstance(value, int | float) or isinstance(value, bool) or value < 0:
        raise Dia2PlanError(f"{field_name} must be a non-negative number")
    return float(value)


def write_json(path: Path, value: object) -> None:
    encoded = (json.dumps(value, indent=2) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_file() and path.read_bytes() == encoded:
            return
        raise Dia2PlanError(f"immutable output collision: {path.name}")
    with path.open("xb") as output:
        output.write(encoded)


def write_generation_state(path: Path, value: dict[str, Any]) -> None:
    encoded = (json.dumps(value, indent=2) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
        fsync_directory(path.parent)
    finally:
        temporary_path.unlink(missing_ok=True)


def require_iso_date_time_value(value: object, field_name: str) -> None:
    if not isinstance(value, str):
        raise Dia2PlanError(f"{field_name} must be an ISO date-time")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise Dia2PlanError(f"{field_name} must be an ISO date-time") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise Dia2PlanError(f"{field_name} must include a UTC offset")


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a pinned Dia2 VoiceID corpus batch")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--mimi-dir", type=Path, required=True)
    parser.add_argument("--asset-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--manifest-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    args = parser.parse_args()
    manifest, report = generate_plan(
        load_plan(args.plan),
        source_root=args.source_root,
        model_dir=args.model_dir,
        mimi_dir=args.mimi_dir,
        asset_dir=args.asset_dir,
        output_dir=args.output_dir,
        state_path=args.state,
    )
    write_json(args.manifest_out, manifest)
    write_json(args.report_out, report)


if __name__ == "__main__":
    main()
