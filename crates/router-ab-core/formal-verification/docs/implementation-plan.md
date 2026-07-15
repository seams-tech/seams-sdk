# Fixed ECDSA Threshold-PRF Formal Plan

The production model follows
[`../../specs/ecdsa-threshold-prf.md`](../../specs/ecdsa-threshold-prf.md).

## Implemented slice

- [x] Model Router, Deriver A, Deriver B, Client, and SigningWorker roles.
- [x] Model Client-only `x_client_base` and SigningWorker-only
      `x_server_base` opening authorization.
- [x] Model fixed Deriver-local threshold-PRF partial visibility.
- [x] Model forbidden joined-state events and single-role exclusion.
- [x] Bind Rust service roles, request construction, payload separation, and
      SigningWorker activation context through anti-drift tests.

## Remaining proof work

- [ ] Model the fixed 2-of-2 share-id relation A=`1`, B=`2`.
- [ ] Mirror fixed context and transcript field order.
- [ ] Model request kind, recipient identity, ceremony id, and root epoch.
- [ ] Prove recipient and epoch separation.
- [ ] Prove that every accepted proof batch binds one fixed-role share id,
      transcript, output purpose, and recipient.
- [ ] Connect the Lean view model to the Rust payload and output types.
- [ ] Treat PRF, DLEQ, hash, signature, and recipient-encryption security as
      explicit computational assumptions.
