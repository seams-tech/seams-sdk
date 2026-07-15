# Passive One-Pass Stream Wire v1

Status: benchmark-only normative specification for `passive/stream.rs`.

This document freezes the Phase 5 passive table-stream encoding. Any change to
field order, width, interpretation, digest preimage, frame partitioning, or
request order requires a new wire version.

All integers are unsigned big-endian. All reserved bytes are zero. The wire is
binary only; JSON, base64, runtime profile negotiation, and arbitrary chunk
sizes are invalid.

## Security boundary

Version 1 is digest-chained for accidental corruption and non-adversarial fault
detection in the benchmark harness. SHA-256 digests do not authenticate A, B,
the manifest, or a frame; an on-path adversary can rewrite bytes and recompute
the chain. TLS peer authentication, a signed opening manifest, and a session
MAC belong to Phase 6B. This wire version cannot support a production-
authentication claim by itself.

## Fixed families and profiles

Each instantiation fixes one circuit family and one sealed chunk marker before
the ceremony. The received manifest must match that expected Rust type; peers
do not negotiate it on the wire.

| Family | Family tag | AND-table records | Table payload bytes |
| --- | ---: | ---: | ---: |
| Activation private output | `0x93` | 65,780 | 2,104,960 |
| Export private output | `0x94` | 1,275 | 40,800 |

One AND-table record is exactly 32 bytes. XOR and inversion gates have no table
record.

| Chunk marker | Tag | Maximum payload | Activation frames | Activation body | Export frames | Export body |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `Chunk64KiB` | 1 | 65,536 | 33 | 2,107,996 | 1 | 40,892 |
| `Chunk128KiB` | 2 | 131,072 | 17 | 2,106,524 | 1 | 40,892 |
| `Chunk256KiB` | 3 | 262,144 | 9 | 2,105,788 | 1 | 40,892 |

`body_bytes = table_payload_bytes + frame_count * 92`. Activation has 65,536
records in full frames followed by a final 244-record, 7,808-byte frame under
all three markers. Export has one 1,275-record, 40,800-byte frame.

## Opening manifest

The manifest is exactly 248 bytes. It precedes and binds the expected shape of
the table body at the benchmark protocol layer; it is not included in
`body_bytes`.

| Offset | Width | Field | Required value |
| ---: | ---: | --- | --- |
| 0 | 8 | magic | ASCII `EYAOSTM1` |
| 8 | 1 | version | `1` |
| 9 | 1 | family | `0x93` or `0x94`, fixed by the expected family |
| 10 | 1 | chunk marker | `1`, `2`, or `3`, fixed by the expected marker type |
| 11 | 5 | reserved | zero |
| 16 | 32 | protocol identifier | ASCII `seams:ed25519-yao:stream:v1` followed by five NUL bytes |
| 48 | 32 | claim identifier | `SHA-256("seams:ed25519-yao:passive-benchmark-one-pass:v1")` |
| 80 | 32 | session ID | exact nonzero Phase 4 session ID |
| 112 | 8 | gate domain | exact family/session-derived Phase 4 gate domain |
| 120 | 32 | circuit digest | exact pinned family circuit digest |
| 152 | 32 | schedule digest | exact pinned family schedule digest |
| 184 | 32 | pre-stream transcript | transcript after OT, direct labels, and masked labels; output translation has not yet been derived |
| 216 | 8 | table payload bytes | fixed family value above |
| 224 | 8 | body bytes | fixed family/chunk value above |
| 232 | 4 | frame count | fixed family/chunk value above |
| 236 | 4 | maximum frame payload | fixed chunk value above |
| 240 | 4 | AND-table record count | fixed family value above |
| 244 | 2 | frame-header bytes | `92` |
| 246 | 2 | reserved | zero |

The decoder is constructed with the expected family binding, pre-stream
transcript, and chunk marker. Every manifest byte must equal the value derived
from that context.

## Table frame

Each frame is a 92-byte header immediately followed by its payload.

| Offset | Width | Field | Rule |
| ---: | ---: | --- | --- |
| 0 | 8 | magic | ASCII `EYAOTF01` |
| 8 | 1 | version | `1` |
| 9 | 1 | frame type | `1` for an AND-table frame |
| 10 | 2 | reserved | zero |
| 12 | 4 | sequence | starts at zero and increments by one |
| 16 | 4 | AND-table ordinal start | starts at zero and equals the prior end |
| 20 | 4 | AND-table record count | exactly `payload_length / 32` |
| 24 | 4 | payload length | exact expected chunk length |
| 28 | 32 | previous-frame digest | chain start for frame zero, prior frame digest thereafter |
| 60 | 32 | payload digest | digest defined below |
| 92 | variable | payload | consecutive 32-byte Half-Gates AND-table records |

The ordinal fields enumerate only table-bearing AND gates in their order of
appearance in the pinned full schedule. They are not full-schedule gate
ordinals. An incremental evaluator walks the full schedule, executes XOR and
inversion gates locally, and consumes exactly one record whenever it encounters
the next AND gate.

Every non-final frame has the selected maximum payload length. The final frame
has exactly the remaining table bytes. Payloads are nonempty, at most the fixed
maximum, and divisible by 32. The range must not overflow and its final end must
equal the manifest's AND-table record count.

## Digest chain and terminal transcript

Concatenation below is byte concatenation. Literal domain strings have no NUL
terminator. Integer encodings use the widths declared above.

```text
manifest_digest = SHA-256(
  "seams:ed25519-yao:stream-manifest-digest:v1" || manifest[0..248]
)

first_previous = SHA-256(
  "seams:ed25519-yao:stream-chain-start:v1" || manifest_digest
)

payload_digest = SHA-256(
  "seams:ed25519-yao:stream-payload-digest:v1" ||
  manifest_digest || frame_header[0..60] || payload
)

frame_digest = SHA-256(
  "seams:ed25519-yao:stream-frame-digest:v1" ||
  manifest_digest || frame_header[0..92] || payload
)

final_transcript = SHA-256(
  "seams:ed25519-yao:stream-final-transcript:v1" ||
  pre_stream_transcript || manifest_digest || final_frame_digest ||
  u64be(body_bytes)
)

post_translation_transcript = SHA-256(
  "seams:ed25519-yao:phase4:transcript-step:v1" ||
  final_transcript || u64be(translation_message_bytes) ||
  translation_message
)

terminal_control_transcript = SHA-256(
  "seams:ed25519-yao:phase4:transcript-step:v1" ||
  post_translation_transcript || u64be(returned_label_message_bytes) ||
  returned_label_message
)
```

The payload digest is verified before a frame is exposed to the incremental
evaluator. The terminal transcript is usable only after exact EOF succeeds.
`translation_message` and `returned_label_message` are the complete canonical
role-message bytes, including their role-message headers. The native harness's
four-byte transport length prefixes are excluded from both transcript steps.

## Frozen request order

The table stream refines the Phase 4 whole-message baseline into this one-pass
order:

1. B sends the fresh base-OT offer.
2. A sends base-OT choices and A's direct input labels.
3. B sends the OT extension matrix.
4. A sends masked B-input labels. The OT exchange is now complete.
5. A sends the opening stream manifest, then garbles and emits the framed table
   body incrementally while B evaluates it incrementally.
6. A ends the dedicated table request body at the manifest's exact
   `body_bytes`. After its local close, A may send B's private-output
   translation bits on the independent control channel without waiting for an
   extra acknowledgment round trip.
7. B validates exact table EOF and finalizes the stream transcript before it
   reads, decodes, or uses the queued translation message. The message is bound
   to that terminal stream transcript.
8. B decodes only its output share, then returns A's opaque selected output
   labels bound to the post-translation transcript.

This order is required for one-pass bounded garbling. B-output translation is
derived from final output-wire labels and therefore does not exist until A has
garbled the complete circuit. Sending it before the table would require either
whole-table retention or a second deterministic garbling pass. No table frame
passes through the Router or client.

The P0 benchmark claim requires B's validated read/use order, not evidence that
B finished reading before A placed translation bytes on the separate control
channel. A profile that requires peer-confirmed table acceptance must add an
authenticated EOF receipt and its round trip in Phase 6B.

## Parser, EOF, and abort rules

The decoder validates a complete header before permitting a payload read. That
header fixes the one allowed payload length, capped by the selected marker.
The payload must be read exactly and its digest verified before evaluation.

Reject the ceremony on any wrong length, unknown magic/version/type, nonzero
reserved byte, context mismatch, overflow, misalignment, short non-final frame,
sequence gap, duplicate, reordering, AND-table range mismatch, previous-digest
mismatch, payload-digest mismatch, premature EOF, disconnect, timeout, or byte
after the exact final frame. Parser errors are terminal; version 1 has no retry,
resumption, or recovery branch. Output cannot be released before terminal EOF
and transcript finalization.

## Bounded-memory disposal

A retains the live garbling arena and at most one selected-profile payload
buffer. After the header and payload are committed to the transport, A
zeroizes that buffer and continues in canonical schedule order.

B retains the live evaluation arena, one 92-byte header, and exactly one
bounded payload buffer. After digest verification, B consumes consecutive
32-byte records into the evaluator and zeroizes the buffer before accepting the
next header.

On success or abort, both roles destroy live wire labels, global delta, OT
secrets, output-decode secrets, and table buffers. Neither role materializes a
whole table stream in Rust or JavaScript. A Worker integration must use bounded
binary chunks and must not use `arrayBuffer()`, JSON, base64, Router relay, or
whole-body persistence.
