# Passive Split-Role Relay V1

Status: benchmark-only Phase 9A viability grammar. It is not an authenticated,
encrypted, actively secure, or production protocol.

## Fixed roles and fixture

Deriver A is the garbler and Deriver B is the evaluator. They are independently
instantiable and exchange only encoded messages. The six public profiles fix the
circuit family and table payload bound at the Rust type level:

- activation with 64, 128, or 256 KiB table frames;
- export with 64, 128, or 256 KiB table frames.

The benchmark fixture is shared with the Phase 5 process runner. It uses the RFC
8032 seed `9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`,
zero complementary input fields, and fresh OS-random output coins from both
roles for every ceremony.

## Outer envelope

Every directional-body message is encoded as one `EYAORL01` envelope followed
by exactly one existing binary OT, role, manifest, or table-frame payload.

| Offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 8 | ASCII `EYAORL01` |
| 8 | 1 | version `1` |
| 9 | 1 | message tag |
| 10 | 2 | zero reserved bytes |
| 12 | 4 | big-endian payload length |
| 16 | `n` | exact inner payload |

Tags are fixed: Offer `1`, BaseChoices `2`, Direct `3`, Extension `4`, Masked `5`,
Manifest `6`, TableFrame `7`, Translation `8`, and ReturnedLabels `9`.
Unknown tags, versions, nonzero reserved bytes, zero payloads, payloads above
`262236` bytes, truncated envelopes, and trailing bytes in an envelope fail.
The directional codecs reject every tag assigned to the opposite direction,
including nonterminal OT and role messages.
`DirectionalWireDecoder` owns incremental framing across arbitrary host chunks;
the host does not duplicate tag or length parsing.

## Exact inner lengths

All values below exclude the 16-byte outer envelope.

| Message | Activation | Export |
| --- | ---: | ---: |
| Offer | 4144 | 4144 |
| BaseChoices | 4144 | 4144 |
| Direct | 24732 | 12444 |
| Extension | 24624 | 12336 |
| Masked | 49200 | 24624 |
| Manifest | 248 | 248 |
| Translation | 220 | 188 |
| ReturnedLabels | 8348 | 4252 |

Each TableFrame is the canonical 92-byte Phase 5 table header followed by its
profile-bounded payload. Activation carries exactly 2,104,960 table bytes;
export carries exactly 40,800. Activation has 33, 17, or 9 frames for the 64,
128, or 256 KiB profiles. Export has one frame in all three profiles.

## Directional order

One full-duplex streaming request uses these directional sequences:

- B to A: Offer, Extension, ReturnedLabels, physical response EOF.
- A to B: BaseChoices, Direct, Masked, Manifest, all TableFrames,
  Translation, physical request EOF.

The cross-direction dependency order is:

1. B emits Offer.
2. A emits BaseChoices, then Direct.
3. B emits Extension.
4. A emits Masked, then Manifest and the exact table-frame sequence.
5. Completion of the manifest-declared frame schedule closes the logical table
   section. No caller-provided table-close boolean or mid-protocol physical EOF
   exists.
6. A emits Translation and the A-to-B direction reaches physical EOF.
7. B consumes Translation only after its incremental decoder observes that EOF.
8. B emits ReturnedLabels and the B-to-A direction reaches physical EOF.
9. A and B release typed recipient packages only after their respective local
   close and peer EOF evidence matches the ceremony session, direction,
   terminal tag, and encoder/decoder provenance.

The public role `instruction()` reports the next action, expected tag, and exact
inner length. A platform adapter moves one envelope or EOF witness at a time;
it does not reimplement the protocol order graph.

## Binding and transcript

The session, family, circuit digest, schedule digest, gate domain, OT domain,
manifest, role-message context, and recipient packages retain the Phase 4/5
bindings. In particular, A rejects an Offer unless its encoded OT session equals
the OT session derived from A's local ceremony binding.

The control transcript advances over the exact inner message bytes in this
order: Offer, BaseChoices, Direct, Extension, Masked. The stream manifest binds
that predecessor. The Phase 5 chained stream transcript covers the manifest and
all table frames. Translation advances the stream transcript; ReturnedLabels
advances it once more. Both completed roles and every recipient package carry
the same final transcript.

## Allocation and copy accounting

The Phase 9A garbler presently copies each reusable runtime table chunk into an
owned wire-frame allocation. Metrics report cumulative runtime-chunk-to-wire
payload copies, cumulative wire-frame allocation bytes, peak wire-frame
allocation, and the combined runtime-plus-wire table-buffer estimate. This is a
bounded viability implementation, not a zero-copy claim. The directional outer
envelope also shifts one message payload in-place; Phase 9B must measure actual
Rust/WASM/JavaScript and platform-stream copies separately.

## Host trust and failure

Directional EOF witnesses are opaque, session/direction/provenance-bound values
created only after the matching envelope codec has processed its terminal
message. The benchmark host remains trusted to invoke codec finalization only
after the platform reports physical close/EOF. Phase 9B owns that adapter and
its truncation, timeout, disconnect, and backpressure tests.

Any wrong state, role, family, session, tag, length, frame sequence, digest,
table range, transcript context, terminal direction, or EOF witness aborts and
drops the consuming ephemeral state. There is no retry or compatibility path.
