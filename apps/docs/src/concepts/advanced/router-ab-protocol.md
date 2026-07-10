---
title: Router A/B Protocol
---

# Router A/B Protocol

Router A/B protocol details include transcript binding, role-specific
envelopes, replay digests, Deriver identity, SigningWorker identity, output
package binding, and activation receipts.

The public concepts docs should keep these details out of the first
architecture page. This page is the place for readers who need protocol-level
evidence.

Keep the architecture page focused on roles, material boundaries, and operation
paths. Put transcript fields, envelope formats, activation receipts, and
deployment assertions here.

## Protocol Invariants

1. Router request context is bound before role envelopes are decrypted.
2. Deriver A and Deriver B receive role-specific encrypted envelopes.
3. SigningWorker activation is bound to selected worker identity and key epoch.
4. Replay digests and idempotency state prevent request reuse.
5. Response binding checks happen before SDK acceptance.

Ed25519 adds active two-party-computation invariants:

1. Deriver A is always the garbler and Deriver B is always the evaluator.
2. The circuit, role assignment, active-security suite, and request graph are
   fixed by the deployment manifest.
3. Malicious-secure OT, input consistency, selective-failure resistance, and
   authenticated private outputs are required for production.
4. A and B use one-use preprocessing tickets. Failure, timeout, ambiguity, or
   replay burns the ticket.
5. The Router relays compact recipient ciphertexts and public receipts. It
   never handles garbled tables, wire labels, OT state, or plaintext outputs.
6. Recipients verify their private shares and the public output relation before
   accepting activation or export.

The target protects privacy and correctness-with-abort against the Router plus
at most one malicious Deriver. It excludes A+B collusion, platform-wide
compromise, fairness, and guaranteed output delivery.

See [Streaming Yao A/B](/concepts/threshold-signing/streaming-yao-ab) for the
operation flow, round trips, compute model, and deployment comparison.
