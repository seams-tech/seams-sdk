#!/usr/bin/env python3
"""Independent stdlib-only verifier for provisional Ed25519 Yao artifacts."""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import os
import stat
import sys
from array import array
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import verify_vectors


class ArtifactVerificationError(ValueError):
    """A bundle, circuit, schedule, or vector violates the frozen V1 format."""


INDEX_FILE = "ed25519-yao-phase2a-bundle-v1.bin"
INDEX_MAGIC = b"EYAOBA01"
INDEX_BYTES = 387
BUNDLE_INDEX_DIGEST = bytes.fromhex(
    "aa62b83b38163bf898c90084f2eb25df1c95ba41274d0f7826250f9168b80db1"
)
BENCHMARK_MANIFEST_MAGIC = b"EYAOBM01"
BENCHMARK_MANIFEST_BYTES = 1973
BENCHMARK_MANIFEST_DIGEST_DOMAIN = (
    b"seams/router-ab/ed25519-yao/provisional-benchmark/manifest-digest/v1"
)
BENCHMARK_MANIFEST_DIGEST = bytes.fromhex(
    "c9c969fd23998509ae07f04fdc9982e2f3b5b21aa92aac9cf62db5ed2f0cce81"
)
BENCHMARK_COMPILER_CONTRACT = (
    b"seams/router-ab/ed25519-yao/provisional-benchmark/compiler/rust-boolean-ir/v1"
)
BENCHMARK_BIT_ORDER = (
    b"field-order, then byte-index ascending, then bit-index 0..7 (LSB0)"
)
BENCHMARK_WIRE_ORDER = (
    b"inputs-consecutive;gate-output=input-count+gate-index;outputs-ordered;commutative-operands-ascending"
)
IR_MAGIC = b"EYAOIR01"
SCHEDULE_MAGIC = b"EYAOSC01"
IR_HEADER_BYTES = 86
IR_GATE_BYTES = 9
SCHEDULE_HEADER_BYTES = 58
VECTOR_SCHEMA = "seams:router-ab:ed25519-yao:vectors:v1"
PROTOCOL_ID = "router_ab_ed25519_yao_v1"
SCALAR_ORDER = 2**252 + 27742317777372353535851937790883648493

PHASE2B_RECONCILIATION_SCHEMA = (
    "seams:router-ab:ed25519-yao:phase2b-core-reconciliation:v1"
)
PHASE2B_RECONCILIATION_EVIDENCE_SCOPE = (
    "benchmark_only_phase2b_core_cross_corpus_reconciliation_v1"
)
PHASE2B_RECONCILIATION_TOP_LEVEL_KEYS = (
    "schema",
    "protocol_id",
    "evidence_scope",
    "benchmark_manifest_binding",
    "phase1_corpus_commitments",
    "mapping_contracts",
    "cases",
    "explicit_nonclaims",
)
PHASE2B_EXPLICIT_NONCLAIMS = (
    "production_artifact_authority_absent",
    "selected_security_profile_absent",
    "garbling_and_ot_unimplemented",
    "randomized_output_protection_unimplemented",
    "simulator_and_security_experiment_unimplemented",
    "runtime_frame_and_transport_encoding_absent",
    "durable_lifecycle_and_replay_semantics_absent",
    "production_constant_time_and_erasure_unclaimed",
    "independent_operator_reproducibility_unclaimed",
    "reviewer_approval_absent",
)

PHASE2B_CANONICAL_INPUT_DOMAIN = (
    b"seams/router-ab/ed25519-yao/phase2b-reconciliation/canonical-input/v1"
)
PHASE2B_IR_OUTPUT_DOMAIN = (
    b"seams/router-ab/ed25519-yao/phase2b-reconciliation/ir-output/v1"
)
PHASE2B_SCHEDULE_OUTPUT_DOMAIN = (
    b"seams/router-ab/ed25519-yao/phase2b-reconciliation/schedule-output/v1"
)
PHASE2B_PARTY_OUTPUT_DOMAIN = (
    b"seams/router-ab/ed25519-yao/phase2b-reconciliation/party-output/v1"
)
PHASE2B_AUTHORIZED_CLIENT_OUTPUT_DOMAIN = (
    b"seams/router-ab/ed25519-yao/phase2b-reconciliation/authorized-client-output/v1"
)


@dataclass(frozen=True)
class ComponentSpec:
    name: str
    component: int
    input_schema: bytes
    output_schema: bytes
    input_count: int
    gate_count: int
    output_count: int
    xor_count: int
    and_count: int
    inv_count: int
    slot_count: int
    ir_file: str
    schedule_file: str
    ir_bytes: int
    schedule_bytes: int
    ir_digest: bytes
    schedule_digest: bytes
    wire_count: int
    circuit_depth: int
    and_depth: int


@dataclass(frozen=True)
class Phase1CorpusSpec:
    path: str
    schema: str
    case_count: int
    canonical_bytes: int
    sha256_hex: str


PHASE1_CORPORA = (
    Phase1CorpusSpec(
        "vectors/ed25519-yao-v1.json",
        "seams:router-ab:ed25519-yao:vectors:v1",
        5,
        14_826,
        "13934b86ed57e6634c2a3d8ff1361923e9caf28c2aad160251d0b2af779a7e36",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-kdf-v1.json",
        "seams:router-ab:ed25519-yao:kdf-continuity-vectors:v1",
        1,
        4_036,
        "9b2c99469aaf09c1f63318315bd7c5e359039548365e62d11424e5875bceb469",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-ceremony-context-v1.json",
        "seams:router-ab:ed25519-yao:ceremony-context-vectors:v1",
        5,
        31_447,
        "82c6c085f4b5d3b8e9b04e288aa3576763676e90f12fda5644de20dd89f2ee26",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-lifecycle-continuity-v1.json",
        "seams:router-ab:ed25519-yao:lifecycle-continuity-vectors:v1",
        6,
        39_978,
        "c115e81252345985fffd5b6b544d601c5a751b657aca4d1740c27f2f59fc32cd",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-provenance-v1.json",
        "seams:router-ab:ed25519-yao:role-input-provenance-vectors:v1",
        4,
        50_672,
        "8a39d15ddb384fa32111815614a30246e167ec1861d215b89c681e364318d4ba",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-output-sharing-v1.json",
        "seams:router-ab:ed25519-yao:output-sharing-vectors:v1",
        6,
        11_643,
        "c3b340c7f8e181ae38aabb654db7cf6631a11ef634b29e9c46c68c5af6d21965",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-semantic-lifecycle-v1.json",
        "seams:router-ab:ed25519-yao:semantic-artifact-lifecycle-vectors:v1",
        5,
        96_134,
        "758ae82455c6847e04d1b2ad56bc231f6a6a4f44522a9a6d20401a789ef1ca6f",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-output-party-views-v1.json",
        "seams:router-ab:ed25519-yao:output-party-views-vectors:v1",
        5,
        36_950,
        "5aa0c4cbde69125a995c89598dffac41d0924a9cfc05c64af41ccad289c0f9ae",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-evaluation-input-party-views-v1.json",
        "seams:router-ab:ed25519-yao:evaluation-input-party-views-vectors:v1",
        5,
        20_929,
        "da76dfe6e93be9e2dfe4ebfd1c6f7e269a05cd69732c302b8573126f85409f80",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-uniform-abort-envelope-v1.json",
        "seams:router-ab:ed25519-yao:uniform-abort-envelope-vectors:v1",
        5,
        1_965,
        "bf71321d0896c3a6591b0a0f2f57db9a01994209bfcf12dd1ec905e9d6599df0",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-evaluator-abort-state-party-views-v1.json",
        "seams:router-ab:ed25519-yao:evaluator-abort-state-party-views:v1",
        4,
        11_508,
        "9aa77f2cf1b7f74145789bde79d71b53da3c967081d26e609a95f8829a35ed37",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-export-delivery-v1.json",
        "seams:router-ab:ed25519-yao:export-delivery-vectors:v1",
        1,
        5_856,
        "4fae90165fde33a2642eca0704bbe4ebcf126141a8a7d02d410676a0b3cdbe71",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-activation-delivery-v1.json",
        "seams:router-ab:ed25519-yao:activation-delivery-vectors:v1",
        3,
        23_164,
        "8a27dfff5b56be062241667026c0c7cc69ae3d1a395a08a87728afc031df1ccb",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-activation-recipient-party-views-v1.json",
        "seams:router-ab:ed25519-yao:activation-recipient-party-views:v1",
        3,
        17_058,
        "27500219743d5f103f7d39a2af80ac8ab897a93e0a9c373291666e2f2429d420",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-recovery-credential-transition-v1.json",
        "seams:router-ab:ed25519-yao:recovery-credential-transition-vectors:v1",
        1,
        7_228,
        "5293dde1a79a1ceea5fc48e2fe6ff71126c2cd56faec43374e8f087b23ce78b2",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-export-evaluator-authorization-v1.json",
        "seams:router-ab:ed25519-yao:export-evaluator-authorization-vectors:v1",
        1,
        9_805,
        "b9059e1d931227863375afd20af009b056e7b9daa976206236cb307dfe920702",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-registration-evaluator-admission-v1.json",
        "seams:router-ab:ed25519-yao:registration-evaluator-admission-vectors:v1",
        1,
        13_763,
        "ceab8a1b60963313716fc6493bf18736f385362e4a04b479bd78005672b6e7d5",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-recovery-evaluator-admission-v1.json",
        "seams:router-ab:ed25519-yao:recovery-evaluator-admission-vectors:v1",
        1,
        13_727,
        "2555067e3a8bbe0b5242aa370a6db650586ab2da533767dcdc53db8b3afdf19f",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-refresh-evaluator-admission-v1.json",
        "seams:router-ab:ed25519-yao:refresh-evaluator-admission-vectors:v1",
        1,
        15_627,
        "9d5327e9a9623fc101be48f414025d9f6fc108542a72b7126b1ed740b2e0c77a",
    ),
    Phase1CorpusSpec(
        "vectors/ed25519-yao-semantic-frame-party-views-v1.json",
        "seams:router-ab:ed25519-yao:semantic-frame-party-views:v1",
        8,
        249_622,
        "3dc6d30e9c48b3ff55513bc254193e7ad1c1756b42b4a999773adfa6b89a45e9",
    ),
)


COMPONENTS = (
    ComponentSpec(
        "sha512",
        0x81,
        b"seams/router-ab/ed25519-yao/benchmark-component/sha512-fixed32/input/v1:seed[32]:byte-major-lsb0",
        b"seams/router-ab/ed25519-yao/benchmark-component/sha512-fixed32/output/v1:digest[64]:byte-major-lsb0",
        256,
        330_857,
        512,
        269_622,
        54_868,
        6_367,
        4_737,
        "sha512-fixed32.ir.bin",
        "sha512-fixed32.schedule.bin",
        2_979_847,
        2_317_081,
        bytes.fromhex("11488ae3b47722d42d4fc7e2d03fa2684312887ab93c3c9a0b080021b468f53b"),
        bytes.fromhex("0d7c79a0ab31b2ae04b91319355bb79aef32c5f3d5f8532a3db632b121f627da"),
        331_113,
        10_675,
        3_301,
    ),
    ComponentSpec(
        "activation",
        0x91,
        b"seams/router-ab/ed25519-yao/provisional-benchmark/activation/input/v1:a.y_client[32],a.y_server[32],a.tau_client[32]:canonical-l,a.tau_server[32]:canonical-l,b.y_client[32],b.y_server[32],b.tau_client[32]:canonical-l,b.tau_server[32]:canonical-l:field-byte-bit-lsb0",
        b"seams/router-ab/ed25519-yao/provisional-benchmark/activation/output/v1:x_client_base[32]:canonical-l,x_server_base[32]:canonical-l:field-byte-bit-lsb0:no-seed",
        2_048,
        367_240,
        512,
        294_021,
        62_716,
        10_503,
        5_761,
        "activation.ir.bin",
        "activation.schedule.bin",
        3_307_294,
        2_571_762,
        bytes.fromhex("747fa6f1815e3a0c70f0077ffc10508882f321ad6e7bb422f4eef695a853b5a5"),
        bytes.fromhex("e0f9dfb3f3b85eab28fbab81788e0efea25dac7c8de207af8ce9e57567c6ad25"),
        369_288,
        17_903,
        5_723,
    ),
    ComponentSpec(
        "export",
        0x92,
        b"seams/router-ab/ed25519-yao/provisional-benchmark/export/input/v1:a.y_client[32],a.y_server[32],b.y_client[32],b.y_server[32]:field-byte-bit-lsb0:no-tau",
        b"seams/router-ab/ed25519-yao/provisional-benchmark/export/output/v1:seed[32]:field-byte-bit-lsb0:no-scalar",
        1_024,
        4_584,
        256,
        3_819,
        765,
        0,
        1_025,
        "export.ir.bin",
        "export.schedule.bin",
        42_366,
        32_658,
        bytes.fromhex("3cc95694e01966642db7eaed9d68a4116c66bc4d72f14908d0d3b5e25ee79838"),
        bytes.fromhex("bb4b0b1de87baa1bf7b190c8c57538a67367091483a4cb08abc1a2392f55b071"),
        5_608,
        766,
        255,
    ),
)
COMPONENT_BY_NAME = {component.name: component for component in COMPONENTS}
EXPECTED_ENTRIES = (
    (1, COMPONENTS[0].ir_file, COMPONENTS[0].ir_bytes),
    (2, COMPONENTS[0].schedule_file, COMPONENTS[0].schedule_bytes),
    (3, COMPONENTS[1].ir_file, COMPONENTS[1].ir_bytes),
    (4, COMPONENTS[1].schedule_file, COMPONENTS[1].schedule_bytes),
    (5, COMPONENTS[2].ir_file, COMPONENTS[2].ir_bytes),
    (6, COMPONENTS[2].schedule_file, COMPONENTS[2].schedule_bytes),
)
EXPECTED_FILES = {INDEX_FILE, *(filename for _, filename, _ in EXPECTED_ENTRIES)}


@dataclass(frozen=True)
class Circuit:
    spec: ComponentSpec
    opcodes: bytes
    left: array
    right: array
    outputs: array
    digest: bytes


@dataclass(frozen=True)
class Schedule:
    spec: ComponentSpec
    width: int
    opcodes: bytes
    left: array
    right: array
    destination: array
    outputs: array
    digest: bytes


@dataclass(frozen=True)
class VerifiedBundle:
    circuits: dict[str, Circuit]
    schedules: dict[str, Schedule]


class Reader:
    def __init__(self, data: bytes, label: str) -> None:
        self.data = data
        self.label = label
        self.offset = 0

    def take(self, count: int) -> bytes:
        end = self.offset + count
        if end > len(self.data):
            raise ArtifactVerificationError(f"{self.label}: truncated at byte {self.offset}")
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def integer(self, count: int) -> int:
        return int.from_bytes(self.take(count), "big")

    def lp32(self) -> bytes:
        return self.take(self.integer(4))

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise ArtifactVerificationError(f"{self.label}: trailing bytes")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ArtifactVerificationError(message)


def verify_index(index: bytes, artifacts: dict[str, bytes]) -> None:
    reader = Reader(index, "bundle index")
    _require(reader.take(8) == INDEX_MAGIC, "bundle index: wrong magic")
    _require(reader.integer(1) == len(EXPECTED_ENTRIES), "bundle index: wrong entry count")
    for expected_tag, expected_name, expected_length in EXPECTED_ENTRIES:
        tag = reader.integer(1)
        name_length = reader.integer(2)
        try:
            name = reader.take(name_length).decode("ascii")
        except UnicodeDecodeError as error:
            raise ArtifactVerificationError("bundle index: filename is not ASCII") from error
        length = reader.integer(8)
        digest = reader.take(32)
        _require(tag == expected_tag, f"bundle index: wrong tag for {expected_name}")
        _require(name == expected_name, f"bundle index: wrong filename for tag {expected_tag}")
        _require(length == expected_length, f"bundle index: wrong length for {expected_name}")
        _require(expected_name in artifacts, f"bundle index: missing {expected_name}")
        artifact = artifacts[expected_name]
        _require(len(artifact) == length, f"bundle index: file length mismatch for {expected_name}")
        _require(hashlib.sha256(artifact).digest() == digest, f"bundle index: digest mismatch for {expected_name}")
    reader.finish()
    _require(hashlib.sha256(index).digest() == BUNDLE_INDEX_DIGEST, "bundle index: frozen digest mismatch")


def _lp32(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def verify_benchmark_manifest(manifest: bytes, index: bytes) -> None:
    _require(
        len(manifest) == BENCHMARK_MANIFEST_BYTES,
        "benchmark manifest: wrong exact byte length",
    )
    reader = Reader(manifest, "benchmark manifest")
    _require(reader.take(8) == BENCHMARK_MANIFEST_MAGIC, "benchmark manifest: wrong magic")
    _require(reader.integer(2) == 1, "benchmark manifest: wrong version")
    _require(reader.integer(1) == 1, "benchmark manifest: status is not benchmark-only")
    _require(reader.integer(1) == 1, "benchmark manifest: wrong bit-order tag")
    _require(
        reader.lp32() == BENCHMARK_COMPILER_CONTRACT,
        "benchmark manifest: wrong compiler contract",
    )
    _require(reader.lp32() == BENCHMARK_BIT_ORDER, "benchmark manifest: wrong bit order")
    _require(reader.lp32() == BENCHMARK_WIRE_ORDER, "benchmark manifest: wrong wire order")
    _require(reader.lp32() == INDEX_FILE.encode("ascii"), "benchmark manifest: wrong index filename")
    _require(reader.integer(8) == len(index), "benchmark manifest: wrong index length")
    _require(
        reader.take(32) == hashlib.sha256(index).digest() == BUNDLE_INDEX_DIGEST,
        "benchmark manifest: wrong bundle-index digest",
    )
    _require(reader.integer(1) == len(COMPONENTS), "benchmark manifest: wrong component count")
    for spec in COMPONENTS:
        _require(reader.integer(1) == spec.component, f"{spec.name} manifest: wrong component tag")
        _require(reader.lp32() == spec.ir_file.encode("ascii"), f"{spec.name} manifest: wrong IR filename")
        _require(
            reader.lp32() == spec.schedule_file.encode("ascii"),
            f"{spec.name} manifest: wrong schedule filename",
        )
        _require(reader.lp32() == spec.input_schema, f"{spec.name} manifest: wrong input schema")
        _require(reader.lp32() == spec.output_schema, f"{spec.name} manifest: wrong output schema")
        _require(reader.take(32) == spec.ir_digest, f"{spec.name} manifest: wrong IR digest")
        _require(
            reader.take(32) == spec.schedule_digest,
            f"{spec.name} manifest: wrong schedule digest",
        )
        expected_circuit_metrics = (
            spec.input_count,
            spec.output_count,
            spec.wire_count,
            spec.and_count,
            spec.xor_count,
            spec.inv_count,
            spec.gate_count,
            spec.circuit_depth,
            spec.and_depth,
            spec.ir_bytes,
        )
        actual_circuit_metrics = tuple(reader.integer(8) for _ in range(10))
        _require(
            actual_circuit_metrics == expected_circuit_metrics,
            f"{spec.name} manifest: wrong circuit metrics",
        )
        expected_schedule_metrics = (
            spec.input_count,
            spec.output_count,
            spec.gate_count,
            spec.slot_count,
        )
        actual_schedule_metrics = tuple(reader.integer(8) for _ in range(4))
        _require(
            actual_schedule_metrics == expected_schedule_metrics,
            f"{spec.name} manifest: wrong schedule metrics",
        )
        _require(reader.integer(1) == 2, f"{spec.name} manifest: wrong slot width")
        _require(reader.integer(1) == 7, f"{spec.name} manifest: wrong gate-record width")
        _require(reader.integer(8) == spec.schedule_bytes, f"{spec.name} manifest: wrong schedule bytes")
        _require(
            reader.integer(8) == 32 * spec.and_count,
            f"{spec.name} manifest: wrong passive table bytes",
        )
    reader.finish()
    digest = hashlib.sha256(
        _lp32(BENCHMARK_MANIFEST_DIGEST_DOMAIN) + _lp32(manifest)
    ).digest()
    _require(digest == BENCHMARK_MANIFEST_DIGEST, "benchmark manifest: frozen digest mismatch")


def _schema_digest(schema: bytes) -> bytes:
    return hashlib.sha256(schema).digest()


def parse_ir(data: bytes, spec: ComponentSpec) -> Circuit:
    expected_length = IR_HEADER_BYTES + IR_GATE_BYTES * spec.gate_count + 4 * spec.output_count
    _require(len(data) == expected_length, f"{spec.name} IR: wrong exact length")
    reader = Reader(data, f"{spec.name} IR")
    _require(reader.take(8) == IR_MAGIC, f"{spec.name} IR: wrong magic")
    _require(reader.integer(1) == spec.component, f"{spec.name} IR: wrong component")
    _require(reader.integer(1) == 1, f"{spec.name} IR: wrong bit order")
    _require(reader.take(32) == _schema_digest(spec.input_schema), f"{spec.name} IR: wrong input schema")
    _require(reader.take(32) == _schema_digest(spec.output_schema), f"{spec.name} IR: wrong output schema")
    input_count = reader.integer(4)
    gate_count = reader.integer(4)
    output_count = reader.integer(4)
    _require(input_count == spec.input_count, f"{spec.name} IR: wrong input count")
    _require(gate_count == spec.gate_count, f"{spec.name} IR: wrong gate count")
    _require(output_count == spec.output_count, f"{spec.name} IR: wrong output count")

    opcodes = bytearray()
    left = array("I")
    right = array("I")
    opcode_counts = [0, 0, 0, 0]
    for gate_index in range(gate_count):
        opcode = reader.integer(1)
        first = reader.integer(4)
        second = reader.integer(4)
        output_wire = input_count + gate_index
        _require(opcode in (1, 2, 3), f"{spec.name} IR: unknown gate opcode")
        _require(first < output_wire and second < output_wire, f"{spec.name} IR: forward gate reference")
        if opcode in (1, 2):
            _require(first <= second, f"{spec.name} IR: noncanonical commutative operands")
        else:
            _require(first == second, f"{spec.name} IR: INV operands differ")
        opcodes.append(opcode)
        left.append(first)
        right.append(second)
        opcode_counts[opcode] += 1
    _require(opcode_counts[1] == spec.xor_count, f"{spec.name} IR: wrong XOR count")
    _require(opcode_counts[2] == spec.and_count, f"{spec.name} IR: wrong AND count")
    _require(opcode_counts[3] == spec.inv_count, f"{spec.name} IR: wrong INV count")

    wire_count = input_count + gate_count
    outputs = array("I", (reader.integer(4) for _ in range(output_count)))
    _require(all(output < wire_count for output in outputs), f"{spec.name} IR: output out of range")
    _require(len(set(outputs)) == output_count, f"{spec.name} IR: duplicate output")
    reader.finish()
    _require(_all_gates_live(input_count, opcodes, left, right, outputs), f"{spec.name} IR: dead gate")
    digest = hashlib.sha256(data).digest()
    _require(digest == spec.ir_digest, f"{spec.name} IR: frozen digest mismatch")
    return Circuit(spec, bytes(opcodes), left, right, outputs, digest)


def _all_gates_live(
    input_count: int, opcodes: bytes, left: array, right: array, outputs: array
) -> bool:
    live = bytearray(len(opcodes))
    pending = list(outputs)
    while pending:
        wire = pending.pop()
        if wire < input_count:
            continue
        gate_index = wire - input_count
        if live[gate_index]:
            continue
        live[gate_index] = 1
        pending.append(left[gate_index])
        if right[gate_index] != left[gate_index]:
            pending.append(right[gate_index])
    return all(live)


def _minimal_width(slot_count: int) -> int:
    _require(slot_count > 0, "schedule: zero slot count")
    maximum = slot_count - 1
    if maximum <= 0xFF:
        return 1
    if maximum <= 0xFFFF:
        return 2
    if maximum <= 0xFF_FFFF:
        return 3
    return 4


def parse_schedule(data: bytes, spec: ComponentSpec, circuit: Circuit) -> Schedule:
    _require(len(data) >= SCHEDULE_HEADER_BYTES, f"{spec.name} schedule: truncated header")
    reader = Reader(data, f"{spec.name} schedule")
    _require(reader.take(8) == SCHEDULE_MAGIC, f"{spec.name} schedule: wrong magic")
    _require(reader.integer(1) == spec.component, f"{spec.name} schedule: wrong component")
    width = reader.integer(1)
    _require(1 <= width <= 4, f"{spec.name} schedule: invalid slot width")
    _require(reader.take(32) == circuit.digest, f"{spec.name} schedule: circuit digest mismatch")
    input_count = reader.integer(4)
    gate_count = reader.integer(4)
    output_count = reader.integer(4)
    slot_count = reader.integer(4)
    _require(input_count == spec.input_count, f"{spec.name} schedule: wrong input count")
    _require(gate_count == spec.gate_count, f"{spec.name} schedule: wrong gate count")
    _require(output_count == spec.output_count, f"{spec.name} schedule: wrong output count")
    _require(slot_count == spec.slot_count, f"{spec.name} schedule: wrong slot count")
    _require(width == _minimal_width(slot_count), f"{spec.name} schedule: nonminimal slot width")
    expected_length = SCHEDULE_HEADER_BYTES + gate_count * (1 + 3 * width) + output_count * width
    _require(len(data) == expected_length, f"{spec.name} schedule: wrong exact length")

    opcodes = bytearray()
    left = array("I")
    right = array("I")
    destination = array("I")
    for gate_index in range(gate_count):
        opcode = reader.integer(1)
        first = reader.integer(width)
        second = reader.integer(width)
        output = reader.integer(width)
        _require(opcode in (1, 2, 3), f"{spec.name} schedule: unknown opcode")
        _require(opcode == circuit.opcodes[gate_index], f"{spec.name} schedule: opcode order mismatch")
        _require(first < slot_count and second < slot_count and output < slot_count, f"{spec.name} schedule: slot out of range")
        if opcode == 3:
            _require(first == second, f"{spec.name} schedule: INV operands differ")
        opcodes.append(opcode)
        left.append(first)
        right.append(second)
        destination.append(output)
    outputs = array("I", (reader.integer(width) for _ in range(output_count)))
    _require(all(output < slot_count for output in outputs), f"{spec.name} schedule: output slot out of range")
    _require(len(set(outputs)) == output_count, f"{spec.name} schedule: duplicate output slot")
    reader.finish()

    expected = derive_schedule_bytes(circuit)
    _require(data == expected, f"{spec.name} schedule: not the canonical last-use schedule")
    digest = hashlib.sha256(data).digest()
    _require(digest == spec.schedule_digest, f"{spec.name} schedule: frozen digest mismatch")
    return Schedule(spec, width, bytes(opcodes), left, right, destination, outputs, digest)


def derive_schedule_bytes(circuit: Circuit) -> bytes:
    spec = circuit.spec
    wire_count = spec.input_count + spec.gate_count
    terminal = spec.gate_count
    last_use: list[int | None] = [None] * wire_count
    for gate_index in range(spec.gate_count):
        last_use[circuit.left[gate_index]] = gate_index
        last_use[circuit.right[gate_index]] = gate_index
    for output in circuit.outputs:
        last_use[output] = terminal

    wire_slots: list[int | None] = [None] * wire_count
    free: list[int] = []
    for wire in range(spec.input_count):
        if last_use[wire] is None:
            free.append(wire)
        else:
            wire_slots[wire] = wire
    heapq.heapify(free)
    free_members = set(free)
    next_slot = spec.input_count
    scheduled_left = array("I")
    scheduled_right = array("I")
    scheduled_destination = array("I")

    def release(wire: int, gate_index: int) -> None:
        if last_use[wire] != gate_index:
            return
        slot = wire_slots[wire]
        _require(slot is not None, "schedule derivation: missing operand slot")
        wire_slots[wire] = None
        _require(slot not in free_members, "schedule derivation: duplicate free slot")
        free_members.add(slot)
        heapq.heappush(free, slot)

    for gate_index in range(spec.gate_count):
        left_wire = circuit.left[gate_index]
        right_wire = circuit.right[gate_index]
        left_slot = wire_slots[left_wire]
        right_slot = wire_slots[right_wire]
        _require(left_slot is not None and right_slot is not None, "schedule derivation: missing operand")
        release(left_wire, gate_index)
        if right_wire != left_wire:
            release(right_wire, gate_index)
        if free:
            destination = heapq.heappop(free)
            free_members.remove(destination)
        else:
            destination = next_slot
            next_slot += 1
        wire_slots[spec.input_count + gate_index] = destination
        scheduled_left.append(left_slot)
        scheduled_right.append(right_slot)
        scheduled_destination.append(destination)

    output_slots = array("I")
    for output in circuit.outputs:
        slot = wire_slots[output]
        _require(slot is not None, "schedule derivation: missing pinned output")
        output_slots.append(slot)
    _require(next_slot == spec.slot_count, f"{spec.name} schedule: derived slot count changed")
    width = _minimal_width(next_slot)

    encoded = bytearray(SCHEDULE_MAGIC)
    encoded.append(spec.component)
    encoded.append(width)
    encoded.extend(circuit.digest)
    encoded.extend(spec.input_count.to_bytes(4, "big"))
    encoded.extend(spec.gate_count.to_bytes(4, "big"))
    encoded.extend(spec.output_count.to_bytes(4, "big"))
    encoded.extend(next_slot.to_bytes(4, "big"))
    for gate_index, opcode in enumerate(circuit.opcodes):
        encoded.append(opcode)
        encoded.extend(scheduled_left[gate_index].to_bytes(width, "big"))
        encoded.extend(scheduled_right[gate_index].to_bytes(width, "big"))
        encoded.extend(scheduled_destination[gate_index].to_bytes(width, "big"))
    for output in output_slots:
        encoded.extend(output.to_bytes(width, "big"))
    return bytes(encoded)


def verify_bundle_directory(directory: Path) -> VerifiedBundle:
    directory_fd = _open_directory_nofollow(directory)
    try:
        _verify_directory_names(directory_fd)
        index = _read_exact_file_at(directory_fd, INDEX_FILE, INDEX_BYTES)
        artifacts = {
            filename: _read_exact_file_at(directory_fd, filename, expected_length)
            for _, filename, expected_length in EXPECTED_ENTRIES
        }
        _verify_directory_names(directory_fd)
    finally:
        os.close(directory_fd)
    verify_index(index, artifacts)
    circuits: dict[str, Circuit] = {}
    schedules: dict[str, Schedule] = {}
    for spec in COMPONENTS:
        circuit = parse_ir(artifacts[spec.ir_file], spec)
        schedule = parse_schedule(artifacts[spec.schedule_file], spec, circuit)
        circuits[spec.name] = circuit
        schedules[spec.name] = schedule
    return VerifiedBundle(circuits, schedules)


def _artifact_directory_flags() -> int:
    _require(
        sys.platform in ("linux", "darwin"),
        "artifact verification supports only Linux and macOS",
    )
    required = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    _require(
        all(hasattr(os, name) for name in required),
        "artifact verification requires Linux/macOS no-follow descriptor flags",
    )
    return os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW


def _open_directory_nofollow(path: Path) -> int:
    parts = path.parts
    _require(".." not in parts, "artifact bundle path must not contain a parent component")
    flags = _artifact_directory_flags()
    anchor = path.anchor if path.is_absolute() else "."
    try:
        directory_fd = os.open(anchor, flags)
    except OSError as error:
        raise ArtifactVerificationError("unable to open artifact path anchor") from error
    try:
        for part in parts:
            if part in ("", ".", path.anchor):
                continue
            try:
                next_fd = os.open(part, flags, dir_fd=directory_fd)
            except OSError as error:
                raise ArtifactVerificationError(
                    "artifact bundle path contains a symlink or non-directory component"
                ) from error
            os.close(directory_fd)
            directory_fd = next_fd
        return directory_fd
    except BaseException:
        os.close(directory_fd)
        raise


def _verify_directory_names(directory_fd: int) -> None:
    try:
        names = set(os.listdir(directory_fd))
    except OSError as error:
        raise ArtifactVerificationError("unable to enumerate artifact directory") from error
    _require(
        names == EXPECTED_FILES,
        "artifact directory must contain exactly seven fixed files",
    )


def _file_snapshot(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_exact_file_at(
    directory_fd: int, filename: str, expected_length: int
) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        file_fd = os.open(filename, flags, dir_fd=directory_fd)
    except OSError as error:
        raise ArtifactVerificationError(
            f"{filename}: unable to open a direct artifact file"
        ) from error
    try:
        before = os.fstat(file_fd)
        _require(stat.S_ISREG(before.st_mode), f"{filename}: not a regular file")
        _require(before.st_nlink == 1, f"{filename}: multiple hardlinks")
        _require(
            before.st_size == expected_length,
            f"{filename}: wrong exact file length",
        )
        chunks: list[bytes] = []
        remaining = expected_length
        while remaining:
            chunk = os.read(file_fd, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        trailing = os.read(file_fd, 1)
        after = os.fstat(file_fd)
    except OSError as error:
        raise ArtifactVerificationError(f"{filename}: descriptor read failed") from error
    finally:
        os.close(file_fd)
    _require(
        _file_snapshot(before) == _file_snapshot(after),
        f"{filename}: changed while being read",
    )
    data = b"".join(chunks)
    _require(
        len(data) == expected_length and trailing == b"",
        f"{filename}: wrong exact file length",
    )
    return data


def evaluate_ir(circuit: Circuit, inputs: bytes) -> bytes:
    spec = circuit.spec
    _require(len(inputs) == spec.input_count, f"{spec.name}: wrong evaluator input width")
    wires = bytearray(inputs)
    for gate_index, opcode in enumerate(circuit.opcodes):
        first = wires[circuit.left[gate_index]]
        second = wires[circuit.right[gate_index]]
        if opcode == 1:
            wires.append(first ^ second)
        elif opcode == 2:
            wires.append(first & second)
        else:
            wires.append(first ^ 1)
    return bytes(wires[output] for output in circuit.outputs)


def evaluate_schedule(schedule: Schedule, inputs: bytes) -> bytes:
    spec = schedule.spec
    _require(len(inputs) == spec.input_count, f"{spec.name}: wrong schedule input width")
    slots = bytearray(spec.slot_count)
    slots[: spec.input_count] = inputs
    for gate_index, opcode in enumerate(schedule.opcodes):
        first = slots[schedule.left[gate_index]]
        second = slots[schedule.right[gate_index]]
        if opcode == 1:
            output = first ^ second
        elif opcode == 2:
            output = first & second
        else:
            output = first ^ 1
        slots[schedule.destination[gate_index]] = output
    return bytes(slots[output] for output in schedule.outputs)


BIT_TABLE = tuple(bytes((byte >> bit) & 1 for bit in range(8)) for byte in range(256))


def _lsb0_bits(fields: Sequence[bytes]) -> bytes:
    return b"".join(BIT_TABLE[byte] for field in fields for byte in field)


def _bits_to_bytes(bits: bytes) -> bytes:
    _require(len(bits) % 8 == 0, "output bit count is not byte aligned")
    output = bytearray(len(bits) // 8)
    for byte_index in range(len(output)):
        value = 0
        for bit_index in range(8):
            value |= bits[byte_index * 8 + bit_index] << bit_index
        output[byte_index] = value
    return bytes(output)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in output, f"vector corpus: duplicate key {key}")
        output[key] = value
    return output


def _hex32(value: Any, field: str) -> bytes:
    _require(type(value) is str and len(value) == 64 and value == value.lower(), f"{field}: expected lowercase hex32")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ArtifactVerificationError(f"{field}: invalid hex") from error
    _require(len(decoded) == 32, f"{field}: wrong byte length")
    return decoded


def _hex64(value: Any, field: str) -> bytes:
    _require(type(value) is str and len(value) == 128 and value == value.lower(), f"{field}: expected lowercase hex64")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ArtifactVerificationError(f"{field}: invalid hex") from error
    _require(len(decoded) == 64, f"{field}: wrong byte length")
    return decoded


def _evaluate_pair(bundle: VerifiedBundle, name: str, inputs: bytes) -> bytes:
    ir_output = evaluate_ir(bundle.circuits[name], inputs)
    schedule_output = evaluate_schedule(bundle.schedules[name], inputs)
    _require(ir_output == schedule_output, f"{name}: IR and schedule outputs differ")
    return _bits_to_bytes(ir_output)


def _require_ordered_keys(value: Any, keys: tuple[str, ...], path: str) -> dict[str, Any]:
    _require(type(value) is dict, f"{path}: expected an object")
    _require(tuple(value) == keys, f"{path}: wrong fields or field order")
    return value


def _require_exact_structure(actual: Any, expected: Any, path: str) -> None:
    _require(type(actual) is type(expected), f"{path}: wrong value type")
    if type(expected) is dict:
        _require(tuple(actual) == tuple(expected), f"{path}: wrong fields or field order")
        for key, expected_value in expected.items():
            _require_exact_structure(actual[key], expected_value, f"{path}.{key}")
        return
    if type(expected) is list:
        _require(len(actual) == len(expected), f"{path}: wrong array length")
        for index, (actual_value, expected_value) in enumerate(
            zip(actual, expected, strict=True)
        ):
            _require_exact_structure(actual_value, expected_value, f"{path}[{index}]")
        return
    _require(actual == expected, f"{path}: expected {expected!r}")


def _strict_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _read_reconciliation_certificate(certificate: Path | bytes | bytearray) -> bytes:
    if type(certificate) in (bytes, bytearray):
        return bytes(certificate)
    _require(isinstance(certificate, Path), "certificate must be Path or canonical bytes")
    try:
        metadata = certificate.lstat()
    except OSError as error:
        raise ArtifactVerificationError("unable to inspect reconciliation certificate") from error
    _require(stat.S_ISREG(metadata.st_mode), "reconciliation certificate must be a direct regular file")
    _require(metadata.st_nlink == 1, "reconciliation certificate must have one hardlink")
    try:
        return certificate.read_bytes()
    except OSError as error:
        raise ArtifactVerificationError("unable to read reconciliation certificate") from error


def _parse_reconciliation_certificate(certificate: Path | bytes | bytearray) -> dict[str, Any]:
    encoded = _read_reconciliation_certificate(certificate)
    _require(not encoded.startswith(b"\xef\xbb\xbf"), "reconciliation certificate contains a BOM")
    _require(b"\r" not in encoded, "reconciliation certificate contains CR bytes")
    try:
        source = encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ArtifactVerificationError("reconciliation certificate is not UTF-8") from error
    try:
        document = json.loads(
            source,
            object_pairs_hook=_strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ArtifactVerificationError(f"non-standard JSON constant {value!r}")
            ),
        )
    except json.JSONDecodeError as error:
        raise ArtifactVerificationError("reconciliation certificate is invalid JSON") from error
    _require(type(document) is dict, "reconciliation certificate must be an object")
    _require(
        encoded == _strict_json_bytes(document),
        "reconciliation certificate is not canonical pretty JSON with one trailing LF",
    )
    return document


def _canonical_bundle_index() -> bytes:
    digests: dict[str, bytes] = {}
    for component in COMPONENTS:
        digests[component.ir_file] = component.ir_digest
        digests[component.schedule_file] = component.schedule_digest
    encoded = bytearray(INDEX_MAGIC)
    encoded.append(len(EXPECTED_ENTRIES))
    for tag, filename, length in EXPECTED_ENTRIES:
        filename_bytes = filename.encode("ascii")
        encoded.append(tag)
        encoded.extend(len(filename_bytes).to_bytes(2, "big"))
        encoded.extend(filename_bytes)
        encoded.extend(length.to_bytes(8, "big"))
        encoded.extend(digests[filename])
    result = bytes(encoded)
    _require(len(result) == INDEX_BYTES, "canonical bundle index length changed")
    _require(
        hashlib.sha256(result).digest() == BUNDLE_INDEX_DIGEST,
        "canonical bundle index digest changed",
    )
    return result


def _expected_benchmark_manifest_binding() -> dict[str, Any]:
    component_kinds = ("fixed_sha512_32", "activation", "export")
    components = []
    for component_kind, component in zip(component_kinds, COMPONENTS, strict=True):
        components.append(
            {
                "component_kind": component_kind,
                "component_tag": component.component,
                "ir_file": component.ir_file,
                "schedule_file": component.schedule_file,
                "input_schema": component.input_schema.decode("ascii"),
                "output_schema": component.output_schema.decode("ascii"),
                "ir_digest_hex": component.ir_digest.hex(),
                "schedule_digest_hex": component.schedule_digest.hex(),
            }
        )
    return {
        "manifest_magic": BENCHMARK_MANIFEST_MAGIC.decode("ascii"),
        "manifest_canonical_bytes": BENCHMARK_MANIFEST_BYTES,
        "manifest_digest_hex": BENCHMARK_MANIFEST_DIGEST.hex(),
        "compiler_contract": BENCHMARK_COMPILER_CONTRACT.decode("ascii"),
        "bit_order": BENCHMARK_BIT_ORDER.decode("ascii"),
        "wire_order": BENCHMARK_WIRE_ORDER.decode("ascii"),
        "bundle_index_file": INDEX_FILE,
        "bundle_index_canonical_bytes": INDEX_BYTES,
        "bundle_index_digest_hex": BUNDLE_INDEX_DIGEST.hex(),
        "components": components,
    }


def _mapping_field(
    semantic_field: str,
    source_role: str,
    source_field: str,
    wire_start: int,
) -> dict[str, Any]:
    return {
        "semantic_field": semantic_field,
        "source_role": source_role,
        "source_field": source_field,
        "wire_start": wire_start,
        "wire_count": 256,
        "byte_order": "little_endian",
        "bit_order": "byte_index_ascending_lsb0",
    }


def _zero_evaluation_plan() -> dict[str, Any]:
    return {
        "kind": "zero_evaluation_continuation",
        "counts": {
            "yao_evaluations": 0,
            "deriver_a_invocations": 0,
            "deriver_b_invocations": 0,
            "contribution_derivations": 0,
            "ideal_output_share_samples": 0,
        },
    }


def _expected_mapping_contracts() -> dict[str, Any]:
    activation_inputs = [
        _mapping_field("a.y_client", "deriver_a", "y_client_hex", 0),
        _mapping_field("a.y_server", "deriver_a", "y_server_hex", 256),
        _mapping_field("a.tau_client", "deriver_a", "tau_client_hex", 512),
        _mapping_field("a.tau_server", "deriver_a", "tau_server_hex", 768),
        _mapping_field("b.y_client", "deriver_b", "y_client_hex", 1024),
        _mapping_field("b.y_server", "deriver_b", "y_server_hex", 1280),
        _mapping_field("b.tau_client", "deriver_b", "tau_client_hex", 1536),
        _mapping_field("b.tau_server", "deriver_b", "tau_server_hex", 1792),
    ]
    activation_outputs = [
        _mapping_field("x_client_base", "circuit_output", "x_client_base", 0),
        _mapping_field("x_server_base", "circuit_output", "x_server_base", 256),
    ]
    export_inputs = [
        _mapping_field("a.y_client", "deriver_a", "y_client_hex", 0),
        _mapping_field("a.y_server", "deriver_a", "y_server_hex", 256),
        _mapping_field("b.y_client", "deriver_b", "y_client_hex", 512),
        _mapping_field("b.y_server", "deriver_b", "y_server_hex", 768),
    ]
    return {
        "activation_family": {
            "mapping_id": "activation_family_inputs_outputs_v1",
            "component_kind": "activation",
            "input_fields": activation_inputs,
            "output_fields": activation_outputs,
        },
        "activation_continuation": {
            "mapping_id": "activation_continuation_zero_evaluation_v1",
            "evaluation_plan": _zero_evaluation_plan(),
            "input_fields": [],
            "output_fields": [],
        },
        "export_family": {
            "mapping_id": "export_family_inputs_outputs_v1",
            "component_kind": "export",
            "input_fields": export_inputs,
            "output_fields": [
                _mapping_field("seed", "circuit_output", "seed", 0)
            ],
        },
    }


def _phase2b_digest(domain: bytes, payload: bytes) -> str:
    return hashlib.sha256(_lp32(domain) + _lp32(payload)).hexdigest()


def _load_phase1_corpora(
    commitments: Any, source_vector_dir: Path
) -> dict[str, dict[str, Any]]:
    _require(type(commitments) is list, "$.phase1_corpus_commitments must be an array")
    _require(
        len(commitments) == len(PHASE1_CORPORA),
        "$.phase1_corpus_commitments must contain exactly twenty entries",
    )
    directory_fd = _open_directory_nofollow(source_vector_dir)
    documents: dict[str, dict[str, Any]] = {}
    try:
        for index, (entry, specification) in enumerate(
            zip(commitments, PHASE1_CORPORA, strict=True)
        ):
            expected_entry = {
                "path": specification.path,
                "schema": specification.schema,
                "case_count": specification.case_count,
                "canonical_bytes": specification.canonical_bytes,
                "sha256_hex": specification.sha256_hex,
            }
            _require_exact_structure(
                entry, expected_entry, f"$.phase1_corpus_commitments[{index}]"
            )
            relative = Path(specification.path)
            _require(
                relative.parts == ("vectors", relative.name),
                f"phase 1 commitment {index}: path is not a direct vectors entry",
            )
            encoded = _read_exact_file_at(
                directory_fd,
                relative.name,
                specification.canonical_bytes,
            )
            _require(
                hashlib.sha256(encoded).hexdigest() == specification.sha256_hex,
                f"phase 1 commitment {index}: file digest mismatch",
            )
            try:
                source = encoded.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ArtifactVerificationError(
                    f"phase 1 commitment {index}: invalid UTF-8"
                ) from error
            try:
                document = verify_vectors.parse_corpus_json(source)
            except verify_vectors.VerificationError as error:
                raise ArtifactVerificationError(
                    f"phase 1 commitment {index}: strict JSON failure: {error}"
                ) from error
            _require(
                encoded == _strict_json_bytes(document),
                f"phase 1 commitment {index}: noncanonical JSON bytes",
            )
            _require(
                document.get("schema") == specification.schema,
                f"phase 1 commitment {index}: schema mismatch",
            )
            cases = document.get("cases")
            _require(
                type(cases) is list and len(cases) == specification.case_count,
                f"phase 1 commitment {index}: case count mismatch",
            )
            documents[relative.name] = document
    finally:
        os.close(directory_fd)
    _verify_phase1_corpus_owners(documents, source_vector_dir)
    return documents


def _verify_phase1_corpus_owners(
    documents: dict[str, dict[str, Any]], source_vector_dir: Path
) -> None:
    def document(filename: str) -> dict[str, Any]:
        return documents[filename]

    arithmetic = document("ed25519-yao-v1.json")
    kdf = document("ed25519-yao-kdf-v1.json")
    ceremony = document("ed25519-yao-ceremony-context-v1.json")
    lifecycle = document("ed25519-yao-lifecycle-continuity-v1.json")
    provenance = document("ed25519-yao-provenance-v1.json")
    output_sharing = document("ed25519-yao-output-sharing-v1.json")
    semantic = document("ed25519-yao-semantic-lifecycle-v1.json")
    output_views = document("ed25519-yao-output-party-views-v1.json")
    evaluation_views = document("ed25519-yao-evaluation-input-party-views-v1.json")
    uniform_abort = document("ed25519-yao-uniform-abort-envelope-v1.json")
    evaluator_abort = document("ed25519-yao-evaluator-abort-state-party-views-v1.json")
    export_delivery = document("ed25519-yao-export-delivery-v1.json")
    activation_delivery = document("ed25519-yao-activation-delivery-v1.json")
    activation_recipient = document("ed25519-yao-activation-recipient-party-views-v1.json")
    recovery_transition = document("ed25519-yao-recovery-credential-transition-v1.json")
    export_authorization = document("ed25519-yao-export-evaluator-authorization-v1.json")
    registration_admission = document("ed25519-yao-registration-evaluator-admission-v1.json")
    recovery_admission = document("ed25519-yao-recovery-evaluator-admission-v1.json")
    refresh_admission = document("ed25519-yao-refresh-evaluator-admission-v1.json")
    semantic_frames = document("ed25519-yao-semantic-frame-party-views-v1.json")

    try:
        counts = (
            verify_vectors.verify_corpus(arithmetic),
            verify_vectors.verify_kdf_corpus(kdf),
            verify_vectors.verify_ceremony_context_corpus(ceremony),
            verify_vectors.verify_lifecycle_continuity_corpus(lifecycle),
            verify_vectors.verify_provenance_corpus(provenance, ceremony),
            verify_vectors.verify_output_sharing_corpus(output_sharing),
            verify_vectors.verify_semantic_lifecycle_corpus(
                semantic, ceremony, provenance
            ),
            verify_vectors.verify_output_party_views_corpus(
                output_views, semantic, ceremony, provenance
            ),
            verify_vectors.verify_evaluation_input_party_views_corpus(
                evaluation_views, ceremony, provenance, semantic, output_views
            ),
            verify_vectors.verify_uniform_abort_corpus(uniform_abort, ceremony),
            verify_vectors.verify_evaluator_abort_view_corpus(
                evaluator_abort, ceremony
            ),
            verify_vectors.verify_export_delivery_corpus(export_delivery),
            verify_vectors.verify_activation_delivery_corpus(
                activation_delivery,
                semantic,
                ceremony,
                provenance,
                output_views,
            ),
            verify_vectors.verify_activation_recipient_party_views_corpus(
                activation_recipient,
                ceremony,
                provenance,
                semantic,
                output_views,
                activation_delivery,
            ),
            verify_vectors.verify_recovery_credential_transition_corpus(
                recovery_transition,
                ceremony,
                provenance,
                semantic,
                output_views,
                activation_delivery,
                activation_recipient,
            ),
            verify_vectors.verify_export_evaluator_authorization_corpus(
                export_authorization
            ),
            verify_vectors.verify_registration_evaluator_admission_corpus(
                registration_admission
            ),
            verify_vectors.verify_recovery_evaluator_admission_corpus(
                recovery_admission
            ),
            verify_vectors.verify_refresh_evaluator_admission_corpus(
                refresh_admission
            ),
            verify_vectors.verify_semantic_frame_party_views_corpus(
                semantic_frames, source_vector_dir
            ),
        )
    except verify_vectors.VerificationError as error:
        raise ArtifactVerificationError(
            f"Phase 1 owning verifier rejected a committed corpus: {error}"
        ) from error
    _require(
        counts == tuple(specification.case_count for specification in PHASE1_CORPORA),
        "Phase 1 owning verifier case counts changed",
    )


def _case_selector(case: dict[str, Any]) -> str | None:
    direct = case.get("case_id")
    if type(direct) is str:
        return direct
    vector = case.get("vector")
    if type(vector) is not dict:
        return None
    vector_case = vector.get("case_id")
    if type(vector_case) is str:
        return vector_case
    reference = vector.get("reference")
    if type(reference) is dict and type(reference.get("case_id")) is str:
        return reference["case_id"]
    return None


def _selected_case(
    document: dict[str, Any], selector: str, request_kind: str, label: str
) -> dict[str, Any]:
    cases = document.get("cases")
    _require(type(cases) is list, f"{label}: cases must be an array")
    matches = [case for case in cases if type(case) is dict and _case_selector(case) == selector]
    _require(len(matches) == 1, f"{label}: selector {selector!r} must resolve exactly once")
    selected = matches[0]
    _require(
        selected.get("request_kind") == request_kind,
        f"{label}: selector request kind mismatch",
    )
    return selected


def _case_vector(case: dict[str, Any], label: str) -> dict[str, Any]:
    vector = case.get("vector")
    _require(type(vector) is dict, f"{label}: selected case has no vector object")
    return vector


def _evaluate_component_outputs(
    bundle: VerifiedBundle, component: str, canonical_input: bytes
) -> tuple[bytes, bytes]:
    bits = _lsb0_bits(tuple(canonical_input[index : index + 32] for index in range(0, len(canonical_input), 32)))
    ir_bits = evaluate_ir(bundle.circuits[component], bits)
    schedule_bits = evaluate_schedule(bundle.schedules[component], bits)
    ir_output = _bits_to_bytes(ir_bits)
    schedule_output = _bits_to_bytes(schedule_bits)
    _require(ir_output == schedule_output, f"{component}: IR and schedule outputs differ")
    return ir_output, schedule_output


def _decode_input_view_fields(
    selected: dict[str, Any], request_kind: str
) -> bytes:
    vector = _case_vector(selected, f"{request_kind} evaluation input")
    roles = vector.get("role_extensions")
    _require(type(roles) is dict, f"{request_kind}: input role extensions missing")
    deriver_a = roles.get("deriver_a")
    deriver_b = roles.get("deriver_b")
    _require(type(deriver_a) is dict and type(deriver_b) is dict, f"{request_kind}: Deriver inputs missing")
    if request_kind == "export":
        expected_a = "deriver_a_export_evaluation_inputs"
        expected_b = "deriver_b_export_evaluation_inputs"
        fields = ("y_client_hex", "y_server_hex")
    else:
        expected_a = "deriver_a_activation_evaluation_inputs"
        expected_b = "deriver_b_activation_evaluation_inputs"
        fields = ("y_client_hex", "y_server_hex", "tau_client_hex", "tau_server_hex")
    _require(deriver_a.get("kind") == expected_a, f"{request_kind}: wrong Deriver A input kind")
    _require(deriver_b.get("kind") == expected_b, f"{request_kind}: wrong Deriver B input kind")
    payload = bytearray()
    for role_name, role in (("deriver_a", deriver_a), ("deriver_b", deriver_b)):
        _require(tuple(role) == ("kind", *fields), f"{request_kind}: wrong {role_name} field order")
        for field in fields:
            decoded = _hex32(role[field], f"{request_kind}.{role_name}.{field}")
            if field.startswith("tau_"):
                _require(
                    int.from_bytes(decoded, "little") < SCALAR_ORDER,
                    f"{request_kind}.{role_name}.{field}: noncanonical scalar",
                )
            payload.extend(decoded)
    return bytes(payload)


def _reconstruct_activation_party_output(selected: dict[str, Any], request_kind: str) -> bytes:
    vector = _case_vector(selected, f"{request_kind} output party view")
    roles = vector.get("role_extensions")
    _require(type(roles) is dict, f"{request_kind}: output role extensions missing")
    deriver_a = roles.get("deriver_a")
    deriver_b = roles.get("deriver_b")
    _require(type(deriver_a) is dict and type(deriver_b) is dict, f"{request_kind}: output shares missing")
    _require(
        tuple(deriver_a)
        == ("kind", "client_scalar_share_hex", "signing_worker_scalar_share_hex"),
        f"{request_kind}: wrong Deriver A output shape",
    )
    _require(tuple(deriver_b) == tuple(deriver_a), f"{request_kind}: wrong Deriver B output shape")
    _require(
        deriver_a["kind"] == "deriver_a_activation_scalar_shares"
        and deriver_b["kind"] == "deriver_b_activation_scalar_shares",
        f"{request_kind}: wrong activation output kinds",
    )
    output = bytearray()
    for field in ("client_scalar_share_hex", "signing_worker_scalar_share_hex"):
        left = _hex32(deriver_a[field], f"{request_kind}.deriver_a.{field}")
        right = _hex32(deriver_b[field], f"{request_kind}.deriver_b.{field}")
        left_value = int.from_bytes(left, "little")
        right_value = int.from_bytes(right, "little")
        _require(left_value < SCALAR_ORDER and right_value < SCALAR_ORDER, f"{request_kind}: noncanonical output share")
        output.extend(((left_value + right_value) % SCALAR_ORDER).to_bytes(32, "little"))
    return bytes(output)


def _reconstruct_export_party_output(selected: dict[str, Any]) -> tuple[bytes, bytes]:
    vector = _case_vector(selected, "export output party view")
    roles = vector.get("role_extensions")
    _require(type(roles) is dict, "export: output role extensions missing")
    deriver_a = roles.get("deriver_a")
    deriver_b = roles.get("deriver_b")
    client = roles.get("client")
    _require(type(deriver_a) is dict and type(deriver_b) is dict and type(client) is dict, "export: output roles missing")
    _require(
        tuple(deriver_a) == ("kind", "seed_share_hex")
        and tuple(deriver_b) == ("kind", "seed_share_hex"),
        "export: wrong seed-share shape",
    )
    _require(
        deriver_a["kind"] == "deriver_a_seed_share"
        and deriver_b["kind"] == "deriver_b_seed_share",
        "export: wrong seed-share kinds",
    )
    _require(tuple(client) == ("kind", "seed_hex") and client["kind"] == "client_authorized_seed", "export: wrong Client output shape")
    left = int.from_bytes(_hex32(deriver_a["seed_share_hex"], "export.deriver_a.seed_share_hex"), "little")
    right = int.from_bytes(_hex32(deriver_b["seed_share_hex"], "export.deriver_b.seed_share_hex"), "little")
    reconstructed = ((left + right) % (1 << 256)).to_bytes(32, "little")
    authorized = _hex32(client["seed_hex"], "export.client.seed_hex")
    return reconstructed, authorized


def _verify_case_digest(value: Any, domain: bytes, payload: bytes, path: str) -> None:
    _require(type(value) is str, f"{path}: expected lowercase SHA-256 hex")
    _require(len(value) == 64 and value == value.lower(), f"{path}: expected lowercase SHA-256 hex")
    try:
        bytes.fromhex(value)
    except ValueError as error:
        raise ArtifactVerificationError(f"{path}: invalid SHA-256 hex") from error
    _require(value == _phase2b_digest(domain, payload), f"{path}: digest mismatch")


def _verify_activation_continuation_case(
    vector: Any, documents: dict[str, dict[str, Any]]
) -> None:
    expected_keys = (
        "case_kind",
        "case_id",
        "evaluation_input_party_view_case_id",
        "output_party_view_case_id",
        "semantic_frame_success_case_id",
        "activation_origin",
        "mapping_id",
        "evaluation_plan",
        "reconciliation_result",
    )
    value = _require_ordered_keys(vector, expected_keys, "$.cases[1].vector")
    fixed = {
        "case_kind": "activation_continuation_reconciliation",
        "case_id": "activation_phase2b_zero_evaluation_reconciliation_v1",
        "evaluation_input_party_view_case_id": "activation_no_evaluation_input_party_views_v1",
        "output_party_view_case_id": "activation_output_party_views_metadata_consumed_v1",
        "semantic_frame_success_case_id": "registration_success_worker_activated_v1",
        "activation_origin": "registration",
        "mapping_id": "activation_continuation_zero_evaluation_v1",
        "evaluation_plan": _zero_evaluation_plan(),
        "reconciliation_result": "exact_zero_evaluation_and_no_new_private_output",
    }
    _require_exact_structure(value, fixed, "$.cases[1].vector")

    input_case = _selected_case(
        documents["ed25519-yao-evaluation-input-party-views-v1.json"],
        value["evaluation_input_party_view_case_id"],
        "activation",
        "activation input view",
    )
    input_vector = _case_vector(input_case, "activation input view")
    _require_exact_structure(
        input_vector["common_public"]["evaluation_plan"],
        _zero_evaluation_plan(),
        "activation input evaluation plan",
    )
    expected_input_kinds = {
        "deriver_a": "deriver_a_empty",
        "deriver_b": "deriver_b_empty",
        "client": "client_empty",
        "signing_worker": "signing_worker_empty",
        "router": "router_empty",
        "observer": "observer_empty",
        "diagnostics_logs": "diagnostics_empty",
    }
    for role, kind in expected_input_kinds.items():
        _require_exact_structure(
            input_vector["role_extensions"][role],
            {"kind": kind},
            f"activation input role {role}",
        )

    output_case = _selected_case(
        documents["ed25519-yao-output-party-views-v1.json"],
        value["output_party_view_case_id"],
        "activation",
        "activation output view",
    )
    output_vector = _case_vector(output_case, "activation output view")
    expected_output_kinds = {
        "deriver_a": "deriver_a_no_new_private_output",
        "deriver_b": "deriver_b_no_new_private_output",
        "client": "client_no_new_private_output",
        "signing_worker": "signing_worker_no_new_private_output",
        "router": "router_no_new_private_output",
        "observer": "observer_no_new_private_output",
        "diagnostics_logs": "diagnostics_logs_no_new_private_output",
    }
    for role, kind in expected_output_kinds.items():
        _require_exact_structure(
            output_vector["role_extensions"][role],
            {"kind": kind},
            f"activation output role {role}",
        )
    origins = output_vector["common_public"]["origin_metadata_projections"]
    _require(type(origins) is list and len(origins) == 3, "activation origin projections changed")
    _require_exact_structure(
        origins[0]["zero_reevaluation"],
        {
            "yao_evaluations": 0,
            "deriver_a_invocations": 0,
            "deriver_b_invocations": 0,
            "contribution_derivations": 0,
            "output_share_samples": 0,
        },
        "activation registration-origin zero reevaluation",
    )

    trace_case = _selected_case(
        documents["ed25519-yao-semantic-frame-party-views-v1.json"],
        value["semantic_frame_success_case_id"],
        "registration",
        "activation semantic success trace",
    )
    steps = trace_case.get("trace_steps")
    _require(type(steps) is list, "activation semantic trace steps missing")
    control_indices = [
        index
        for index, step in enumerate(steps)
        if type(step) is dict and step.get("delivery_state") == "activation_metadata_consumed"
    ]
    _require(control_indices == [4], "activation control step changed")
    _require(
        steps[4].get("emitted_frame_classes") == ["router_local_activation_control"],
        "activation control emitted an evaluator frame",
    )
    forbidden = {
        "router_to_deriver_a_input_delivery",
        "router_to_deriver_b_input_delivery",
        "deriver_a_to_deriver_b_peer_protocol",
        "deriver_b_to_deriver_a_peer_protocol",
        "deriver_a_to_router_output_packages",
        "deriver_b_to_router_output_packages",
    }
    for step in steps[4:]:
        frames = step.get("emitted_frame_classes")
        _require(type(frames) is list and forbidden.isdisjoint(frames), "activation continuation emitted an evaluator frame")


def _verify_activation_evaluation_case(
    vector: Any,
    request_kind: str,
    bundle: VerifiedBundle,
    documents: dict[str, dict[str, Any]],
) -> None:
    expected_keys = (
        "case_kind",
        "case_id",
        "evaluation_input_party_view_case_id",
        "output_party_view_case_id",
        "semantic_frame_success_case_id",
        "evaluator_admission_case_id",
        "mapping_id",
        "component_kind",
        "canonical_input_digest_hex",
        "ir_evaluated_output_digest_hex",
        "schedule_evaluated_output_digest_hex",
        "party_output_reconstruction_digest_hex",
        "reconciliation_result",
    )
    value = _require_ordered_keys(vector, expected_keys, f"{request_kind} reconciliation")
    selectors = {
        "registration": (
            "registration_phase2b_core_reconciliation_v1",
            "registration_evaluation_input_party_views_v1",
            "registration_output_party_views_package_prepared_v1",
            "registration_success_worker_activated_v1",
            "registration_admitted_evaluation_output_committed_v1",
        ),
        "recovery": (
            "recovery_phase2b_core_reconciliation_v1",
            "recovery_evaluation_input_party_views_v1",
            "recovery_output_party_views_package_prepared_v1",
            "recovery_success_worker_activated_v1",
            "recovery_admitted_evaluation_output_committed_v1",
        ),
        "refresh": (
            "refresh_phase2b_core_reconciliation_v1",
            "refresh_evaluation_input_party_views_v1",
            "refresh_output_party_views_package_prepared_v1",
            "refresh_success_worker_activated_v1",
            "refresh_admitted_evaluation_output_committed_v1",
        ),
    }
    case_id, input_selector, output_selector, frame_selector, admission_selector = selectors[
        request_kind
    ]
    for field, expected in (
        ("case_kind", "activation_evaluation_reconciliation"),
        ("case_id", case_id),
        ("evaluation_input_party_view_case_id", input_selector),
        ("output_party_view_case_id", output_selector),
        ("semantic_frame_success_case_id", frame_selector),
        ("evaluator_admission_case_id", admission_selector),
        ("mapping_id", "activation_family_inputs_outputs_v1"),
        ("component_kind", "activation"),
        ("reconciliation_result", "exact_input_ir_schedule_and_party_output_match"),
    ):
        _require(value[field] == expected, f"{request_kind}: {field} mismatch")

    input_case = _selected_case(
        documents["ed25519-yao-evaluation-input-party-views-v1.json"],
        input_selector,
        request_kind,
        f"{request_kind} input view",
    )
    output_case = _selected_case(
        documents["ed25519-yao-output-party-views-v1.json"],
        output_selector,
        request_kind,
        f"{request_kind} output view",
    )
    _selected_case(
        documents["ed25519-yao-semantic-frame-party-views-v1.json"],
        frame_selector,
        request_kind,
        f"{request_kind} semantic trace",
    )
    _selected_case(
        documents[f"ed25519-yao-{request_kind}-evaluator-admission-v1.json"],
        admission_selector,
        request_kind,
        f"{request_kind} evaluator admission",
    )

    canonical_input = _decode_input_view_fields(input_case, request_kind)
    _require(len(canonical_input) == 256, f"{request_kind}: activation input width changed")
    ir_output, schedule_output = _evaluate_component_outputs(
        bundle, "activation", canonical_input
    )
    party_output = _reconstruct_activation_party_output(output_case, request_kind)
    _require(ir_output == schedule_output == party_output, f"{request_kind}: output relation mismatch")
    _verify_case_digest(
        value["canonical_input_digest_hex"],
        PHASE2B_CANONICAL_INPUT_DOMAIN,
        canonical_input,
        f"{request_kind}.canonical_input_digest_hex",
    )
    _verify_case_digest(
        value["ir_evaluated_output_digest_hex"],
        PHASE2B_IR_OUTPUT_DOMAIN,
        ir_output,
        f"{request_kind}.ir_evaluated_output_digest_hex",
    )
    _verify_case_digest(
        value["schedule_evaluated_output_digest_hex"],
        PHASE2B_SCHEDULE_OUTPUT_DOMAIN,
        schedule_output,
        f"{request_kind}.schedule_evaluated_output_digest_hex",
    )
    _verify_case_digest(
        value["party_output_reconstruction_digest_hex"],
        PHASE2B_PARTY_OUTPUT_DOMAIN,
        party_output,
        f"{request_kind}.party_output_reconstruction_digest_hex",
    )


def _verify_export_evaluation_case(
    vector: Any,
    bundle: VerifiedBundle,
    documents: dict[str, dict[str, Any]],
) -> None:
    expected_keys = (
        "case_kind",
        "case_id",
        "evaluation_input_party_view_case_id",
        "output_party_view_case_id",
        "semantic_frame_success_case_id",
        "evaluator_authorization_case_id",
        "mapping_id",
        "component_kind",
        "canonical_input_digest_hex",
        "ir_evaluated_output_digest_hex",
        "schedule_evaluated_output_digest_hex",
        "party_output_reconstruction_digest_hex",
        "authorized_client_output_digest_hex",
        "reconciliation_result",
    )
    value = _require_ordered_keys(vector, expected_keys, "export reconciliation")
    expected_values = {
        "case_kind": "export_evaluation_reconciliation",
        "case_id": "export_phase2b_core_reconciliation_v1",
        "evaluation_input_party_view_case_id": "export_evaluation_input_party_views_v1",
        "output_party_view_case_id": "export_output_party_views_released_v1",
        "semantic_frame_success_case_id": "export_release_exact_redelivery_v1",
        "evaluator_authorization_case_id": "export_authorized_evaluation_released_v1",
        "mapping_id": "export_family_inputs_outputs_v1",
        "component_kind": "export",
        "reconciliation_result": "exact_input_ir_schedule_party_output_and_authorized_client_match",
    }
    for field, expected in expected_values.items():
        _require(value[field] == expected, f"export: {field} mismatch")

    input_case = _selected_case(
        documents["ed25519-yao-evaluation-input-party-views-v1.json"],
        value["evaluation_input_party_view_case_id"],
        "export",
        "export input view",
    )
    output_case = _selected_case(
        documents["ed25519-yao-output-party-views-v1.json"],
        value["output_party_view_case_id"],
        "export",
        "export output view",
    )
    _selected_case(
        documents["ed25519-yao-semantic-frame-party-views-v1.json"],
        value["semantic_frame_success_case_id"],
        "export",
        "export semantic trace",
    )
    _selected_case(
        documents["ed25519-yao-export-evaluator-authorization-v1.json"],
        value["evaluator_authorization_case_id"],
        "export",
        "export evaluator authorization",
    )

    canonical_input = _decode_input_view_fields(input_case, "export")
    _require(len(canonical_input) == 128, "export: input width changed")
    ir_output, schedule_output = _evaluate_component_outputs(
        bundle, "export", canonical_input
    )
    party_output, authorized_client = _reconstruct_export_party_output(output_case)
    _require(
        ir_output == schedule_output == party_output == authorized_client,
        "export: evaluated, reconstructed, and authorized outputs differ",
    )
    _verify_case_digest(
        value["canonical_input_digest_hex"],
        PHASE2B_CANONICAL_INPUT_DOMAIN,
        canonical_input,
        "export.canonical_input_digest_hex",
    )
    _verify_case_digest(
        value["ir_evaluated_output_digest_hex"],
        PHASE2B_IR_OUTPUT_DOMAIN,
        ir_output,
        "export.ir_evaluated_output_digest_hex",
    )
    _verify_case_digest(
        value["schedule_evaluated_output_digest_hex"],
        PHASE2B_SCHEDULE_OUTPUT_DOMAIN,
        schedule_output,
        "export.schedule_evaluated_output_digest_hex",
    )
    _verify_case_digest(
        value["party_output_reconstruction_digest_hex"],
        PHASE2B_PARTY_OUTPUT_DOMAIN,
        party_output,
        "export.party_output_reconstruction_digest_hex",
    )
    _verify_case_digest(
        value["authorized_client_output_digest_hex"],
        PHASE2B_AUTHORIZED_CLIENT_OUTPUT_DOMAIN,
        authorized_client,
        "export.authorized_client_output_digest_hex",
    )


def verify_phase2b_core_reconciliation(
    certificate: Path | bytes | bytearray,
    bundle: VerifiedBundle,
    benchmark_manifest: bytes,
    source_vector_dir: Path,
) -> int:
    """Independently verifies the strict Phase 2B cross-corpus certificate."""
    _require(type(bundle) is VerifiedBundle, "bundle must be a verified fixed artifact bundle")
    _require(
        set(bundle.circuits) == set(COMPONENT_BY_NAME)
        and set(bundle.schedules) == set(COMPONENT_BY_NAME),
        "bundle component set changed",
    )
    document = _parse_reconciliation_certificate(certificate)
    _require_ordered_keys(document, PHASE2B_RECONCILIATION_TOP_LEVEL_KEYS, "$")
    _require(document["schema"] == PHASE2B_RECONCILIATION_SCHEMA, "$.schema mismatch")
    _require(document["protocol_id"] == PROTOCOL_ID, "$.protocol_id mismatch")
    _require(
        document["evidence_scope"] == PHASE2B_RECONCILIATION_EVIDENCE_SCOPE,
        "$.evidence_scope mismatch",
    )

    canonical_index = _canonical_bundle_index()
    verify_benchmark_manifest(benchmark_manifest, canonical_index)
    _require_exact_structure(
        document["benchmark_manifest_binding"],
        _expected_benchmark_manifest_binding(),
        "$.benchmark_manifest_binding",
    )
    _require_exact_structure(
        document["mapping_contracts"],
        _expected_mapping_contracts(),
        "$.mapping_contracts",
    )
    _require_exact_structure(
        document["explicit_nonclaims"],
        list(PHASE2B_EXPLICIT_NONCLAIMS),
        "$.explicit_nonclaims",
    )
    documents = _load_phase1_corpora(
        document["phase1_corpus_commitments"], source_vector_dir
    )

    cases = document["cases"]
    _require(type(cases) is list and len(cases) == 5, "$.cases must contain exactly five cases")
    expected_request_kinds = (
        "registration",
        "activation",
        "recovery",
        "refresh",
        "export",
    )
    for index, (case, request_kind) in enumerate(
        zip(cases, expected_request_kinds, strict=True)
    ):
        value = _require_ordered_keys(
            case, ("request_kind", "vector"), f"$.cases[{index}]"
        )
        _require(value["request_kind"] == request_kind, f"$.cases[{index}]: request order changed")
        if request_kind in ("registration", "recovery", "refresh"):
            _verify_activation_evaluation_case(
                value["vector"], request_kind, bundle, documents
            )
        elif request_kind == "activation":
            _verify_activation_continuation_case(value["vector"], documents)
        else:
            _verify_export_evaluation_case(value["vector"], bundle, documents)
    return len(cases)


def verify_five_case_corpus(bundle: VerifiedBundle, corpus_path: Path) -> int:
    with corpus_path.open("r", encoding="utf-8") as source:
        document = json.load(source, object_pairs_hook=_strict_object)
    _require(type(document) is dict and set(document) == {"schema", "protocol_id", "cases"}, "vector corpus: wrong top-level shape")
    _require(document["schema"] == VECTOR_SCHEMA, "vector corpus: wrong schema")
    _require(document["protocol_id"] == PROTOCOL_ID, "vector corpus: wrong protocol")
    cases = document["cases"]
    expected_kinds = ["registration", "activation", "recovery", "refresh", "export"]
    _require(type(cases) is list and len(cases) == len(expected_kinds), "vector corpus: expected five cases")
    input_fields = {
        "y_client_a_hex",
        "y_server_a_hex",
        "y_client_b_hex",
        "y_server_b_hex",
        "tau_client_a_hex",
        "tau_server_a_hex",
        "tau_client_b_hex",
        "tau_server_b_hex",
    }
    reference_fields = {"case_id", "context", "inputs", "clear_reference_trace"}
    trace_fields = {
        "y_a_hex",
        "y_b_hex",
        "joined_seed_hex",
        "sha512_digest_hex",
        "clamped_scalar_bytes_hex",
        "signing_scalar_hex",
        "tau_a_hex",
        "tau_b_hex",
        "tau_hex",
        "x_client_base_hex",
        "x_server_base_hex",
        "x_client_point_hex",
        "x_server_point_hex",
        "public_key_hex",
    }
    for case_index, (case, expected_kind) in enumerate(zip(cases, expected_kinds, strict=True)):
        _require(type(case) is dict and set(case) == {"request_kind", "vector"}, "vector corpus: wrong case shape")
        _require(case["request_kind"] == expected_kind, "vector corpus: wrong case order")
        vector = case["vector"]
        _require(type(vector) is dict, "vector corpus: vector is not an object")
        if expected_kind == "export":
            _require(set(vector) == {"reference", "authorized_seed_hex"}, "vector corpus: wrong export shape")
        else:
            _require(set(vector) == reference_fields, "vector corpus: wrong reference shape")
        reference = vector["reference"] if expected_kind == "export" else vector
        _require(type(reference) is dict and set(reference) == reference_fields, "vector corpus: wrong nested reference shape")
        inputs = reference["inputs"]
        trace = reference["clear_reference_trace"]
        _require(type(inputs) is dict and set(inputs) == input_fields, "vector corpus: wrong input fields")
        _require(type(trace) is dict and set(trace) == trace_fields, "vector corpus: wrong trace fields")
        decoded = {field: _hex32(inputs[field], f"case {case_index} {field}") for field in input_fields}
        for tau_field in ("tau_client_a_hex", "tau_server_a_hex", "tau_client_b_hex", "tau_server_b_hex"):
            _require(int.from_bytes(decoded[tau_field], "little") < SCALAR_ORDER, f"case {case_index}: noncanonical tau")

        joined_seed = _hex32(trace["joined_seed_hex"], f"case {case_index} joined seed")
        if expected_kind in ("registration", "recovery", "refresh"):
            activation_inputs = _lsb0_bits(
                (
                    decoded["y_client_a_hex"],
                    decoded["y_server_a_hex"],
                    decoded["tau_client_a_hex"],
                    decoded["tau_server_a_hex"],
                    decoded["y_client_b_hex"],
                    decoded["y_server_b_hex"],
                    decoded["tau_client_b_hex"],
                    decoded["tau_server_b_hex"],
                )
            )
            activation_output = _evaluate_pair(bundle, "activation", activation_inputs)
            expected_activation = _hex32(
                trace["x_client_base_hex"], "x_client_base"
            ) + _hex32(trace["x_server_base_hex"], "x_server_base")
            _require(
                activation_output == expected_activation,
                f"case {case_index}: activation output mismatch",
            )
        elif expected_kind == "export":
            export_inputs = _lsb0_bits(
                (
                    decoded["y_client_a_hex"],
                    decoded["y_server_a_hex"],
                    decoded["y_client_b_hex"],
                    decoded["y_server_b_hex"],
                )
            )
            _require(
                _evaluate_pair(bundle, "export", export_inputs) == joined_seed,
                f"case {case_index}: export output mismatch",
            )
            _require(
                _hex32(vector["authorized_seed_hex"], "authorized seed")
                == joined_seed,
                "vector corpus: authorized export seed mismatch",
            )
        else:
            _require(
                expected_kind == "activation",
                f"case {case_index}: unsupported lifecycle dispatch",
            )
    return len(cases)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("vector_corpus", type=Path)
    arguments = parser.parse_args()
    try:
        bundle = verify_bundle_directory(arguments.artifact_dir)
        count = verify_five_case_corpus(bundle, arguments.vector_corpus)
    except (ArtifactVerificationError, OSError, json.JSONDecodeError) as error:
        print(f"artifact verification failed: {error}")
        return 1
    print(f"verified {count} independent Phase 2A artifact vector cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
