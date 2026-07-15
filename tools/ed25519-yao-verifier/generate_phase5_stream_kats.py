#!/usr/bin/env python3
"""Generate independent public Phase 5 stream/control wire KATs."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


SCHEMA = "seams:ed25519-yao:phase5-stream-wire-kats:v1"
BINARY_MAGIC = b"EY5KAT01"
BINARY_VERSION = 1

MANIFEST_MAGIC = b"EYAOSTM1"
FRAME_MAGIC = b"EYAOTF01"
ROLE_MESSAGE_MAGIC = b"EYAOP401"
WIRE_VERSION = 1
TABLE_FRAME_TYPE = 1
MANIFEST_BYTES = 248
FRAME_HEADER_BYTES = 92
ROLE_MESSAGE_HEADER_BYTES = 156
TABLE_BYTES_PER_AND_GATE = 32

PROTOCOL_IDENTIFIER = b"seams:ed25519-yao:stream:v1\0\0\0\0\0"
CLAIM_IDENTIFIER = b"seams:ed25519-yao:passive-benchmark-one-pass:v1"
GATE_DOMAIN = b"seams:ed25519-yao:phase4:gate-domain:v1"
TRANSCRIPT_START_DOMAIN = b"seams:ed25519-yao:phase4:transcript-start:v1"
TRANSCRIPT_STEP_DOMAIN = b"seams:ed25519-yao:phase4:transcript-step:v1"
MANIFEST_DIGEST_DOMAIN = b"seams:ed25519-yao:stream-manifest-digest:v1"
CHAIN_START_DOMAIN = b"seams:ed25519-yao:stream-chain-start:v1"
PAYLOAD_DIGEST_DOMAIN = b"seams:ed25519-yao:stream-payload-digest:v1"
FRAME_DIGEST_DOMAIN = b"seams:ed25519-yao:stream-frame-digest:v1"
FINAL_TRANSCRIPT_DOMAIN = b"seams:ed25519-yao:stream-final-transcript:v1"

ACTIVATION_CIRCUIT = bytes.fromhex(
    "65b001c2f94de27ee8cb9f0c0773fbe54258ceab43d183174bee710ee8aa546d"
)
ACTIVATION_SCHEDULE = bytes.fromhex(
    "fb04a139dec15e9d52e496dc4fc011cf885c8f3f6f2d18bf3860e46071f0e69a"
)
EXPORT_CIRCUIT = bytes.fromhex(
    "31b03d13e41a728342aedce7af40f5405dc598d28e784de44d8044db9c601a0c"
)
EXPORT_SCHEDULE = bytes.fromhex(
    "66ddc20f8407e369b74f2a210287d2131e78c7525f47fc829c57f6418b0d97d0"
)


def sha256(*parts: bytes) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


def be16(value: int) -> bytes:
    return struct.pack(">H", value)


def be32(value: int) -> bytes:
    return struct.pack(">I", value)


def be64(value: int) -> bytes:
    return struct.pack(">Q", value)


def transcript_step(predecessor: bytes, message: bytes) -> bytes:
    return sha256(TRANSCRIPT_STEP_DOMAIN, predecessor, be64(len(message)), message)


@dataclass(frozen=True)
class Family:
    name: str
    tag: int
    chunk_tag: int
    chunk_bytes: int
    and_gates: int
    output_bits_per_role: int
    session: bytes
    circuit: bytes
    schedule: bytes

    @property
    def table_bytes(self) -> int:
        return self.and_gates * TABLE_BYTES_PER_AND_GATE

    @property
    def frame_count(self) -> int:
        return (self.table_bytes + self.chunk_bytes - 1) // self.chunk_bytes

    @property
    def body_bytes(self) -> int:
        return self.table_bytes + self.frame_count * FRAME_HEADER_BYTES


FAMILIES = (
    Family(
        name="activation-64kib",
        tag=0x93,
        chunk_tag=1,
        chunk_bytes=64 * 1024,
        and_gates=65_780,
        output_bits_per_role=512,
        session=bytes(range(0x01, 0x21)),
        circuit=ACTIVATION_CIRCUIT,
        schedule=ACTIVATION_SCHEDULE,
    ),
    Family(
        name="export-256kib",
        tag=0x94,
        chunk_tag=3,
        chunk_bytes=256 * 1024,
        and_gates=1_275,
        output_bits_per_role=256,
        session=bytes(range(0x21, 0x41)),
        circuit=EXPORT_CIRCUIT,
        schedule=EXPORT_SCHEDULE,
    ),
)


def derive_gate_domain(family: Family) -> int:
    candidate = int.from_bytes(
        sha256(GATE_DOMAIN, bytes([family.tag]), family.session, family.circuit)[:8],
        "big",
    )
    return candidate or 1


def transcript_start(family: Family) -> bytes:
    return sha256(
        TRANSCRIPT_START_DOMAIN,
        bytes([family.tag]),
        family.session,
        family.circuit,
        family.schedule,
    )


def table_payload(family: Family, offset: int, length: int) -> bytes:
    return bytes(((index * 17 + family.tag) & 0xFF) for index in range(offset, offset + length))


def role_payload(family: Family, length: int, multiplier: int) -> bytes:
    return bytes(((index * multiplier + family.tag) & 0xFF) for index in range(length))


def encode_role_message(
    family: Family,
    gate_domain: int,
    predecessor: bytes,
    kind: int,
    item_count: int,
    payload: bytes,
) -> bytes:
    encoded = bytearray(ROLE_MESSAGE_HEADER_BYTES + len(payload))
    encoded[:8] = ROLE_MESSAGE_MAGIC
    encoded[8] = WIRE_VERSION
    encoded[9] = family.tag
    encoded[10] = kind
    encoded[12:44] = family.session
    encoded[44:52] = be64(gate_domain)
    encoded[52:84] = family.circuit
    encoded[84:116] = family.schedule
    encoded[116:148] = predecessor
    encoded[148:152] = be32(item_count)
    encoded[152:156] = be32(len(payload))
    encoded[156:] = payload
    return bytes(encoded)


def encode_manifest(
    family: Family, gate_domain: int, pre_stream_transcript: bytes
) -> bytes:
    encoded = bytearray(MANIFEST_BYTES)
    encoded[:8] = MANIFEST_MAGIC
    encoded[8] = WIRE_VERSION
    encoded[9] = family.tag
    encoded[10] = family.chunk_tag
    encoded[16:48] = PROTOCOL_IDENTIFIER
    encoded[48:80] = sha256(CLAIM_IDENTIFIER)
    encoded[80:112] = family.session
    encoded[112:120] = be64(gate_domain)
    encoded[120:152] = family.circuit
    encoded[152:184] = family.schedule
    encoded[184:216] = pre_stream_transcript
    encoded[216:224] = be64(family.table_bytes)
    encoded[224:232] = be64(family.body_bytes)
    encoded[232:236] = be32(family.frame_count)
    encoded[236:240] = be32(family.chunk_bytes)
    encoded[240:244] = be32(family.and_gates)
    encoded[244:246] = be16(FRAME_HEADER_BYTES)
    return bytes(encoded)


def encode_frames(family: Family, manifest_digest: bytes) -> list[dict[str, bytes | int]]:
    previous = sha256(CHAIN_START_DOMAIN, manifest_digest)
    frames: list[dict[str, bytes | int]] = []
    payload_offset = 0
    and_ordinal = 0
    for sequence in range(family.frame_count):
        payload_length = min(family.chunk_bytes, family.table_bytes - payload_offset)
        payload = table_payload(family, payload_offset, payload_length)
        record_count = payload_length // TABLE_BYTES_PER_AND_GATE
        header = bytearray(FRAME_HEADER_BYTES)
        header[:8] = FRAME_MAGIC
        header[8] = WIRE_VERSION
        header[9] = TABLE_FRAME_TYPE
        header[12:16] = be32(sequence)
        header[16:20] = be32(and_ordinal)
        header[20:24] = be32(record_count)
        header[24:28] = be32(payload_length)
        header[28:60] = previous
        payload_digest = sha256(
            PAYLOAD_DIGEST_DOMAIN, manifest_digest, bytes(header[:60]), payload
        )
        header[60:92] = payload_digest
        frame_digest = sha256(
            FRAME_DIGEST_DOMAIN, manifest_digest, bytes(header), payload
        )
        frames.append(
            {
                "sequence": sequence,
                "payload_offset": payload_offset,
                "payload_bytes": payload_length,
                "and_ordinal": and_ordinal,
                "record_count": record_count,
                "header": bytes(header),
                "payload_digest": payload_digest,
                "frame_digest": frame_digest,
            }
        )
        previous = frame_digest
        payload_offset += payload_length
        and_ordinal += record_count
    if payload_offset != family.table_bytes or and_ordinal != family.and_gates:
        raise AssertionError("frame construction did not consume the fixed table")
    return frames


def build_case(family: Family) -> dict[str, object]:
    gate_domain = derive_gate_domain(family)
    start = transcript_start(family)
    prelude = f"phase5-wire-kat:{family.name}:pre-stream-control:v1".encode("ascii")
    pre_stream = transcript_step(start, prelude)
    manifest = encode_manifest(family, gate_domain, pre_stream)
    manifest_digest = sha256(MANIFEST_DIGEST_DOMAIN, manifest)
    chain_start = sha256(CHAIN_START_DOMAIN, manifest_digest)
    frames = encode_frames(family, manifest_digest)
    first = frames[0]
    final = frames[-1]
    final_frame_digest = final["frame_digest"]
    assert isinstance(final_frame_digest, bytes)
    stream_final = sha256(
        FINAL_TRANSCRIPT_DOMAIN,
        pre_stream,
        manifest_digest,
        final_frame_digest,
        be64(family.body_bytes),
    )

    translation_payload = role_payload(
        family, family.output_bits_per_role // 8, multiplier=29
    )
    translation = encode_role_message(
        family,
        gate_domain,
        stream_final,
        kind=2,
        item_count=family.output_bits_per_role,
        payload=translation_payload,
    )
    post_translation = transcript_step(stream_final, translation)
    returned_payload = role_payload(
        family, family.output_bits_per_role * 16, multiplier=31
    )
    returned = encode_role_message(
        family,
        gate_domain,
        post_translation,
        kind=3,
        item_count=family.output_bits_per_role,
        payload=returned_payload,
    )
    terminal = transcript_step(post_translation, returned)

    return {
        "name": family.name,
        "family_tag": family.tag,
        "chunk_profile_tag": family.chunk_tag,
        "chunk_bytes": family.chunk_bytes,
        "and_gates": family.and_gates,
        "table_bytes": family.table_bytes,
        "frame_count": family.frame_count,
        "body_bytes": family.body_bytes,
        "output_bits_per_role": family.output_bits_per_role,
        "session": family.session,
        "gate_domain": gate_domain,
        "circuit_digest": family.circuit,
        "schedule_digest": family.schedule,
        "transcript_start": start,
        "pre_stream_control_message": prelude,
        "pre_stream_transcript": pre_stream,
        "manifest": manifest,
        "manifest_digest": manifest_digest,
        "chain_start": chain_start,
        "payload_pattern_multiplier": 17,
        "payload_pattern_addend": family.tag,
        "first_frame": first,
        "final_frame": final,
        "stream_final_transcript": stream_final,
        "translation_message": translation,
        "post_translation_transcript": post_translation,
        "returned_label_message": returned,
        "terminal_transcript": terminal,
    }


def hex_case(case: dict[str, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in case.items():
        if isinstance(value, bytes):
            result[f"{key}_hex"] = value.hex()
        elif isinstance(value, dict):
            result[key] = {
                f"{inner_key}_hex" if isinstance(inner_value, bytes) else inner_key: (
                    inner_value.hex() if isinstance(inner_value, bytes) else inner_value
                )
                for inner_key, inner_value in value.items()
            }
        else:
            result[key] = value
    return result


def record_bytes(case: dict[str, object]) -> bytes:
    def raw(name: str) -> bytes:
        value = case[name]
        if not isinstance(value, bytes):
            raise TypeError(name)
        return value

    def number(name: str) -> int:
        value = case[name]
        if not isinstance(value, int):
            raise TypeError(name)
        return value

    def frame(name: str) -> dict[str, bytes | int]:
        value = case[name]
        if not isinstance(value, dict):
            raise TypeError(name)
        return value  # type: ignore[return-value]

    first = frame("first_frame")
    final = frame("final_frame")
    translation = raw("translation_message")
    returned = raw("returned_label_message")
    encoded = bytearray()
    encoded += bytes(
        [
            number("family_tag"),
            number("chunk_profile_tag"),
            number("payload_pattern_multiplier"),
            number("payload_pattern_addend"),
        ]
    )
    encoded += raw("session")
    encoded += be64(number("gate_domain"))
    encoded += raw("circuit_digest")
    encoded += raw("schedule_digest")
    encoded += raw("transcript_start")
    prelude = raw("pre_stream_control_message")
    encoded += be32(len(prelude)) + prelude
    encoded += raw("pre_stream_transcript")
    encoded += raw("manifest")
    encoded += raw("manifest_digest")
    encoded += raw("chain_start")
    encoded += first["header"]
    encoded += first["payload_digest"]
    encoded += first["frame_digest"]
    encoded += final["header"]
    encoded += final["payload_digest"]
    encoded += final["frame_digest"]
    encoded += raw("stream_final_transcript")
    encoded += be32(len(translation)) + translation
    encoded += raw("post_translation_transcript")
    encoded += be32(len(returned)) + returned
    encoded += raw("terminal_transcript")
    return bytes(encoded)


def build_outputs() -> tuple[bytes, bytes]:
    cases = [build_case(family) for family in FAMILIES]
    source_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    document = {
        "schema": SCHEMA,
        "evidence_scope": "public_deterministic_cross_language_wire_kats_only",
        "generator_sha256": source_digest,
        "binary_magic_ascii": BINARY_MAGIC.decode("ascii"),
        "binary_version": BINARY_VERSION,
        "table_payload_pattern": "byte[i] = (17 * global_table_byte_index + family_tag) mod 256",
        "cases": [hex_case(case) for case in cases],
    }
    json_bytes = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    binary = bytearray(BINARY_MAGIC)
    binary += be16(BINARY_VERSION)
    binary += be16(len(cases))
    binary += sha256(json_bytes)
    for case in cases:
        record = record_bytes(case)
        binary += be32(len(record))
        binary += record
    return json_bytes, bytes(binary)


def output_paths() -> tuple[Path, Path]:
    root = Path(__file__).resolve().parents[2]
    artifact_dir = root / "crates/ed25519-yao/artifacts/passive-benchmark-v1"
    return (
        artifact_dir / "phase5-stream-wire-kats-v1.json",
        artifact_dir / "phase5-stream-wire-kats-v1.bin",
    )


def check_exact(path: Path, expected: bytes) -> bool:
    try:
        actual = path.read_bytes()
    except FileNotFoundError:
        print(f"missing generated vector: {path}", file=sys.stderr)
        return False
    if actual != expected:
        print(f"generated vector drift: {path}", file=sys.stderr)
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail unless committed JSON and binary vectors exactly match",
    )
    args = parser.parse_args()
    json_bytes, binary_bytes = build_outputs()
    json_path, binary_path = output_paths()
    if args.check:
        return 0 if all(
            (
                check_exact(json_path, json_bytes),
                check_exact(binary_path, binary_bytes),
            )
        ) else 1
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_bytes(json_bytes)
    binary_path.write_bytes(binary_bytes)
    print(f"wrote {json_path}")
    print(f"wrote {binary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
