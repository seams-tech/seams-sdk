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

### 2. Neither party learns the other's root share

- `y_client` (derived from WebAuthn PRF output) never leaves the client. It enters the protocol via Oblivious Transfer — the server provides encrypted label pairs, the client selects one per bit, and the server cannot determine which was chosen.
- `y_relayer` (derived from server's `K_org` via HKDF) enters the protocol as an additive share transported to the evaluator. The evaluator receives one share-side, not the full value. The other share-side is embedded in the Beaver triple correlation.

### 3. Three independent factors required for compromise

To reconstruct the signing key, an attacker needs ALL of:

| Factor | Held by | How it's protected |
|--------|---------|-------------------|
| `y_client` | Client only | Derived from WebAuthn PRF; requires biometric/PIN + passkey ceremony |
| `y_relayer` | Server only | Derived from `K_org` via HKDF; scoped to `(orgId, accountId, keyPurpose, keyVersion, credentialId)` |
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

- One share-side of `y_relayer` for one specific credential
- OT encrypted branches (two ciphertexts per client input bit, only one decryptable per bit)

This is insufficient to recover `y_relayer` (need the other share-side from the Beaver correlation), `y_client` (protected by OT — attacker cannot decrypt without the client's selection), or `a` (requires both root shares plus the full evaluation).

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

Measured impact was acceptable:

- native hidden eval stayed in the same band, roughly `~0.261s -> ~0.268s`
- browser hidden eval stayed effectively flat to slightly better, roughly `~0.379s -> ~0.359s`

The prepared-session benchmark path remains separate and highly optimized; this hardening specifically improves the normal transport-message evaluator flow.

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

## Assumptions

- **DDH on Curve25519**: the Decisional Diffie-Hellman problem is hard in the Ed25519 group
- **AEAD (ChaCha20Poly1305)**: ciphertexts are IND-CCA2 secure
- **HKDF (SHA-256)**: outputs are computationally indistinguishable from random
- **WebAuthn PRF**: the PRF extension produces unpredictable output bound to the credential
