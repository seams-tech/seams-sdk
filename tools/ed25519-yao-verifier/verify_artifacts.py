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
        sha_inputs = _lsb0_bits((joined_seed,))
        sha_output = _evaluate_pair(bundle, "sha512", sha_inputs)
        _require(sha_output == _hex64(trace["sha512_digest_hex"], f"case {case_index} SHA digest"), f"case {case_index}: SHA output mismatch")

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
        expected_activation = _hex32(trace["x_client_base_hex"], "x_client_base") + _hex32(trace["x_server_base_hex"], "x_server_base")
        _require(activation_output == expected_activation, f"case {case_index}: activation output mismatch")

        export_inputs = _lsb0_bits(
            (
                decoded["y_client_a_hex"],
                decoded["y_server_a_hex"],
                decoded["y_client_b_hex"],
                decoded["y_server_b_hex"],
            )
        )
        _require(_evaluate_pair(bundle, "export", export_inputs) == joined_seed, f"case {case_index}: export output mismatch")
        if expected_kind == "export":
            _require(_hex32(vector["authorized_seed_hex"], "authorized seed") == joined_seed, "vector corpus: authorized export seed mismatch")
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
