from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "voice_id_model_manifest_v1"


@dataclass(frozen=True)
class ArtifactSpec:
    artifact_id: str
    relative_path: str
    source: str
    revision: str
    license_name: str
    expected_published_bytes: int


ARTIFACTS = (
    ArtifactSpec(
        artifact_id="moonshine-streaming-tiny-f32",
        relative_path="moonshine/tiny-f32",
        source="https://huggingface.co/UsefulSensors/moonshine-streaming-tiny",
        revision="f8e9dfd8c562c257c151a907b7b7f2fe8ff8511a",
        license_name="MIT",
        expected_published_bytes=178_000_000,
    ),
    ArtifactSpec(
        artifact_id="moonshine-streaming-small-f32",
        relative_path="moonshine/small-f32",
        source="https://huggingface.co/UsefulSensors/moonshine-streaming-small",
        revision="2c036506f23a09c18df5a50057599ba6d9280999",
        license_name="MIT",
        expected_published_bytes=562_000_000,
    ),
    ArtifactSpec(
        artifact_id="moonshine-streaming-tiny-native-quantized",
        relative_path="moonshine/tiny",
        source="https://download.moonshine.ai/model/tiny-streaming-en/quantized",
        revision="moonshine-voice==0.0.71",
        license_name="MIT",
        expected_published_bytes=0,
    ),
    ArtifactSpec(
        artifact_id="moonshine-streaming-small-native-quantized",
        relative_path="moonshine/small",
        source="https://download.moonshine.ai/model/small-streaming-en/quantized",
        revision="moonshine-voice==0.0.71",
        license_name="MIT",
        expected_published_bytes=0,
    ),
    ArtifactSpec(
        artifact_id="moonshine-intent-embeddinggemma-300m-q4",
        relative_path="moonshine/intent",
        source="https://download.moonshine.ai/model/embeddinggemma-300m",
        revision="moonshine-voice==0.0.71",
        license_name="Apache-2.0",
        expected_published_bytes=0,
    ),
    ArtifactSpec(
        artifact_id="speechbrain-ecapa-voxceleb",
        relative_path="ecapa",
        source="https://huggingface.co/speechbrain/spkrec-ecapa-voxceleb",
        revision="0f99f2d0ebe89ac095bcc5903c4dd8f72b367286",
        license_name="Apache-2.0",
        expected_published_bytes=89_100_000,
    ),
)


def build_manifest(root: Path) -> dict[str, Any]:
    artifacts = [build_artifact(root, spec) for spec in ARTIFACTS]
    return {
        "schemaVersion": SCHEMA_VERSION,
        "manifestPurpose": "immutable-local-model-checksums",
        "artifacts": artifacts,
    }


def build_artifact(root: Path, spec: ArtifactSpec) -> dict[str, Any]:
    artifact_root = root / spec.relative_path
    if not artifact_root.is_dir():
        raise FileNotFoundError(f"model artifact directory does not exist: {artifact_root}")
    files = []
    for path in sorted(
        path
        for path in artifact_root.rglob("*")
        if path.is_file()
        and ".cache" not in path.parts
        and not path.name.endswith((".lock", ".metadata"))
    ):
        relative_path = path.relative_to(artifact_root).as_posix()
        content = path.read_bytes()
        files.append(
            {
                "path": relative_path,
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    canonical_files = "".join(
        f"{file['path']}\t{file['bytes']}\t{file['sha256']}\n" for file in files
    ).encode("utf-8")
    return {
        "id": spec.artifact_id,
        "relativePath": spec.relative_path,
        "source": spec.source,
        "revision": spec.revision,
        "license": spec.license_name,
        "expectedPublishedBytes": spec.expected_published_bytes,
        "downloadedBytes": sum(file["bytes"] for file in files),
        "fileCount": len(files),
        "treeSha256": hashlib.sha256(canonical_files).hexdigest(),
        "files": files,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build an immutable VoiceID model checksum manifest")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path, help="verify an existing manifest instead of writing one")
    args = parser.parse_args()
    root = args.root.expanduser().resolve()
    manifest = build_manifest(root)
    if args.verify is not None:
        expected = json.loads(args.verify.read_text(encoding="utf-8"))
        if manifest != expected:
            raise SystemExit("model manifest verification failed")
        print("model manifest verified")
        return
    if args.output is None:
        raise SystemExit("--output is required when --verify is not provided")
    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
