# Security Model — Succinct HSS for Ed25519 Threshold Key Derivation

## Threat model

Two parties — **client** (browser/mobile) and **server** (relayer) — jointly derive Ed25519 FROST signing shares from a shared root seed, without either party learning the full seed, the derived scalar, or the other party's root share.

The adversary may compromise one party. The protocol must ensure that a single compromise does not yield enough material to reconstruct the signing key or forge signatures.

## Security properties

### 1. Neither party learns the full signing scalar

The signing scalar `a = clamp(SHA-512(d)[0..31]) mod l` is never reconstructed in the clear by either party. Both parties receive only their FROST base share:

- Client receives `x_client_base = a + rho mod l`
- Server receives `x_relayer_base = a + 2*rho mod l`

Recovering `a` from one share requires knowing `rho`, which is derived from both `tau_client` (client-held) and `tau_relayer` (server-held). Neither party has both.

### 2. Root-share boundary status

- `y_client` (derived from WebAuthn PRF output) never leaves the client. It enters the protocol via Oblivious Transfer — the server provides encrypted label pairs, the client selects one per bit, and the server cannot determine which was chosen.
- `y_relayer` (derived from server's `K_org` via HKDF) is intended to remain server-confidential in all non-export production flows. The old sealed `ServerInputsPacket` seam failed that stronger property against a malicious client endpoint and now survives only as regression-test support.

Current reality:

- the legacy sealed packet seam is no longer part of the production client boundary
- the production staged flow now advances through real server-owned stage-local
  continuation state from add-stage onward:
  - add-stage materializes only the add-stage transition plus the first stored
    `message_schedule` continuation
  - each `message_schedule(n)` response advances only the immediately prior
    schedule continuation
  - each `round_core(n)` response advances only the immediately prior
    round-core continuation
  - `output_projection` materializes final output only when that stage
    executes
- `ServerAssistInit` is now only the authenticated init/handle handoff; the
  server-owned hidden-eval execution state begins at the first online
  add-stage request
- the staged server state now carries only stage-local continuations plus the
  minimum projector prerequisites needed for a later `output_projection`
  transition:
  - add-stage bits
  - client tau bits
  - relayer tau transport halves
- those projector prerequisites are retained because delaying them further
  would require recomputing from dropped relayer roots; they are not final
  output bundles and are not client-visible
- that retained `projector_inputs` set is the accepted minimal post-add-stage
  server state for the current design, not a temporary loophole in the
  boundary model
- so the old joined-input packet boundary is removed from production, while
  broader malicious-security work still remains outside this specific fix

Required invariant for the next protocol revision:

- in non-export production flows, the client must never receive enough material
  to reconstruct per-account `y_relayer`
- in non-export production flows, the client must never receive enough material
  to reconstruct per-account `tau_relayer`
- satisfying this invariant requires a protocol redesign, not just stronger
  packet encryption or tighter API visibility

Intentional exception:

- `ExplicitKeyExport` is allowed to deliver the canonical seed to the
  authorized client
- that is intentional because export is the one flow where the user is asking
  to receive private-key-equivalent material in the client runtime
- a compromised browser/app runtime can therefore abuse or exfiltrate export
  output by design
- the stronger secrecy guarantee for `y_relayer` and `tau_relayer` applies
  only to non-export operations
- that flow therefore intentionally falls outside the non-export secrecy
  invariant above

Possible future directions for safer export:

- encrypted backup export:
  - instead of handing the raw canonical seed to ordinary page/application
    logic, export a ciphertext or sealed backup artifact
  - this only improves the boundary if the decryption key is outside the
    browser/page runtime being protected
  - a page-collected passphrase is not enough, because malicious in-page code
    could still steal the plaintext before encryption
- device-to-device migration export:
  - move key-equivalent material into another trusted device or stronger
    runtime boundary instead of disclosing it to normal browser-page code
  - examples include native-app transfer, hardware-backed import, or another
    privileged runtime treated as part of the trusted computing base
  - this preserves a stronger browser boundary because the page receives only
    migration protocol messages, not the raw canonical seed

These are intentionally different product/security models from the current
`ExplicitKeyExport` behavior. The current flow is a direct client-visible
export; the alternatives above are ways to avoid disclosing relayer-recoverable
material to ordinary browser-page execution.

### 3. Factors required for compromise

To reconstruct the signing key, an attacker needs ALL of:

| Factor | Held by | How it's protected |
|--------|---------|-------------------|
| `y_client` | Client only | Derived from WebAuthn PRF; requires biometric/PIN + passkey ceremony |
| `y_relayer` | Intended server-only factor | Derived from `K_org` via HKDF; scoped to `(orgId, accountId, keyPurpose, keyVersion, credentialId)` |
| Beaver triple correlation | Split across both parties | Generated during session preparation; each party holds only their share-side |

Compromising any single factor yields no usable information about the signing key.

### 4. Blast radius containment

Each protocol execution is scoped to a single credential on a single account:

```
y_relayer = HKDF(K_org, label, (orgId, accountId, keyPurpose, keyVersion, credentialId))
```

- **Cross-account isolation**: different `accountId` in the HKDF context produces a completely independent `y_relayer`. Compromising the transport bundle for account A reveals nothing about account B, even within the same organisation.
- **Cross-credential isolation**: different `credentialId` (e.g., a second passkey enrolled on a different device) produces a different `y_relayer`. Compromising one credential does not affect another.
- **Cross-organisation isolation**: different `K_org` per tenant. One organisation's key material is independent of another's.

### 5. Transport bundle exposure

If an attacker intercepts the server's transport bundle (the wire message sent during the online phase), they obtain:

- Encrypted/authenticated relayer transport material for one specific credential
- OT encrypted branches (two ciphertexts per client input bit, only one decryptable per bit)

This is insufficient for a passive wire attacker to recover `y_relayer`, `tau_relayer`, `y_client`, or `a`.

However, this passive-wire statement is weaker than the malicious-client boundary we ultimately want. The old sealed server-input packet flow did allow an evaluator endpoint to observe both relayer transport halves, which is why that seam was removed from production. The kept production path now uses the staged server-assisted flow instead.

### 5.1 Evaluator-side server-input handling

The normal packet-based evaluator flow has been hardened so it no longer materializes a generic owned `DdhHiddenEvalServerInputs` object after opening the server-input packet.

Instead:

- the evaluator opens the encrypted server-input packet into left/right transport bundles
- validation still checks the same context binding, bundle pairing, and combined server-input commitment
- hidden evaluation now consumes borrowed left/right transport-bundle references directly in the add stage and output projector

This is an important boundary improvement because it narrows the normal evaluator path: the runtime no longer promotes opened server input transport into a general-purpose owned hidden-value structure that is easier to pass around or reuse accidentally.

Security-wise, this does **not** change the on-wire cryptography or the commitment semantics:

- the same transport bundle pair validation still runs
- the same combined server-input commitment is recomputed
- the same hidden evaluation result is produced

So the change removes an unnecessary in-memory materialization step without weakening any of the existing checks.

It also does **not** solve the stronger malicious-client boundary problem. The evaluator still receives both relayer transport halves inside the sealed packet flow.

Measured impact was acceptable:

- native hidden eval stayed in the same band, roughly `~0.261s -> ~0.268s`
- browser hidden eval stayed effectively flat to slightly better, roughly `~0.379s -> ~0.359s`

The prepared-session benchmark path remains separate and highly optimized; this hardening specifically improves the normal transport-message evaluator flow.

### 5.2 Arithmetic execution boundary status

The remaining security boundary work is no longer in packet opening or the
production hidden-eval hot path. It is now mostly in trusted simulation/test
helpers and in the internal storage shape of the split/local arithmetic model.

Progress so far:

- the normal evaluator path no longer materializes a generic joined relayer-input object after opening server-input transport
- add-stage and output-projector server-input handling now consume split left/right transport words directly
- production output delivery now carries split relayer output transport longer, instead of eagerly rebuilding a joined server-owned output bundle
- production constant-pool material now enters the executor as split/local words instead of joined hidden words
- client ingress now converts shared input bundles to split/local stage state once at stage entry
- production message schedule, round core, and output-projector arithmetic now stay split/local through the full hot path
- final output bundle construction now rebuilds client and relayer output bundles directly from split/local words at the explicit boundary
- joined-derived conversion helpers are now test-only and are not callable from production code

Why this matters:

- production execution no longer advances through a joined hidden-value type across the add stage, message schedule, round core, or output projector
- that removes the main evaluator-visible runtime surface where both share halves were previously carried together during the hot arithmetic path
- the remaining joined helpers are confined to trusted simulation/tests and explicit boundary rebuild points

What is still not solved:

- joined hidden value types still exist for trusted simulation/tests and a few explicit boundary helpers
- the split/local production representation is still implemented with helper-composed `DdhHssLocalBitSlice` values rather than a denser executor-local storage model
- the staged boundary hardening is now benchmarked and kept, but there is still room for future executor-local storage and kernel-fusion work if we want more latency wins

Current direction:

- backend-local width-1 add/open/mul helpers are now landed and tested
- backend-local width-1 batched local-mul helpers are now landed and tested
- the stage-local `Ch`, `Maj`, carry/add, schedule, round-core, and output-projector rewrites are landed
- the executor now stays split/local end-to-end through the production arithmetic path
- the staged production seam is now the kept design
- the next meaningful security/performance step is therefore not more joined-value cleanup; it is optional follow-on work on denser storage, fused local kernels, and amortized local Beaver material inside the hardened split/local model

### 6. Oblivious Transfer security

The OT implementation uses 1-out-of-2 Elliptic Curve OT on Curve25519 with ChaCha20Poly1305 AEAD:

- **Receiver privacy**: the server (OT sender) cannot determine which branch the client selected. The client's OT request is computationally hiding under the DDH assumption on Curve25519.
- **Sender privacy**: the client (OT receiver) can decrypt only the branch matching its selection bit. The other branch is encrypted under a key the client cannot derive.

### 7. Beaver triple multiplication protocol

Each AND gate in the SHA-512 circuit is evaluated using a precomputed Beaver triple `(a, b, c)` where `c = a*b`:

- The protocol opens masked differences `d = x - a` and `e = y - b`, which are uniformly random (masked by the random triple values)
- Neither party learns `x` or `y` from the opened values
- Each triple is consumed exactly once — no reuse across gates
- Correctness relies on the algebraic relationship `c = a*b`; security relies on the randomness of `a` and `b`

## Current security level

**Semi-honest (passive) security.** The protocol is secure against adversaries who follow the protocol honestly but attempt to learn additional information from the messages they observe.

**Not yet secure against malicious adversaries.** A malicious garbler could construct incorrect Beaver triples or OT responses to extract information. Active security (Phase 4 in the development plan) will address this via:

- Dual execution with progressive output revelation (Liu et al. 2025)
- MAC-based triple verification
- Commitment consistency checks on wire messages

**Historical boundary gap:** the old sealed server-input packet flow did not satisfy the stronger product invariant that the client must never be able to reconstruct per-account `y_relayer` or `tau_relayer`. This refactor removes that production seam; the remaining work is broader malicious-security hardening beyond this specific boundary fix.

## Assumptions

- **DDH on Curve25519**: the Decisional Diffie-Hellman problem is hard in the Ed25519 group
- **AEAD (ChaCha20Poly1305)**: ciphertexts are IND-CCA2 secure
- **HKDF (SHA-256)**: outputs are computationally indistinguishable from random
- **WebAuthn PRF**: the PRF extension produces unpredictable output bound to the credential
