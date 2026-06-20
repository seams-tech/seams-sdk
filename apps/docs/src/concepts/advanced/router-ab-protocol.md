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
