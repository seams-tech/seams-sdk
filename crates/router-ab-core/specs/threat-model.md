# Threat Model And Claims

This spec defines the security claims for Router/A/B split derivation. The
claims are scoped to this primitive and its typed boundary. Deployment integrity,
TLS, Worker account security, storage durability, and envelope encryption
security are separate assumptions.

## Assets

Protected assets:

- joined `d`
- joined `a`
- joined `x_client_base`
- joined `y_relayer`
- joined `tau_relayer`
- A-side derivation state
- B-side derivation state
- plaintext client delivery material before client receipt
- plaintext relayer delivery material before relayer receipt

Public or metadata assets:

- candidate id
- request kind
- correctness level
- account scope
- root-share epoch labels
- ceremony id
- role identities
- ciphertext lengths
- ciphertext digests
- public transcript evidence

## Role Assumptions

### Router

Router authenticates users, rate limits traffic, assigns ceremony ids, and
transports encrypted role envelopes. Router may inspect routing metadata and
public transcript evidence.

Router must never receive plaintext A/B derivation shares, plaintext client
delivery material, plaintext relayer delivery material, or joined secret state.

### Signer A And Signer B

Signer A and Signer B each hold one role-local derivation state. A single signer
may derive or deliver only its own candidate-specific output contribution.

A and B must validate transcript fields before deriving output material. A and B
must reject swapped identities, duplicated signer identities, and mismatched
root epochs.

### Client

The client receives encrypted client-output delivery material and opens
`x_client_base`. The client must not receive joined relayer material.

A malicious client may submit malformed requests, replay old public inputs, or
withhold returned delivery material. Minimum Level C tolerates malicious client
behavior as an output-correctness and availability risk.

### Relayer

The designated relayer receives encrypted relayer-output delivery material and
opens `x_relayer_base`. The relayer may be Signer A in the initial deployment.

Relayer compromise exposes relayer-opened material. It must not expose
client-opened material or joined `d`/`a`.

### Storage

Storage may hold public metadata, replay keys, encrypted delivery packages, and
public transcript evidence. Storage compromise must not reveal plaintext
delivery material or both plaintext A/B derivation states.

## Corruption Matrix

| Compromised set | Privacy claim | Correctness claim | Availability claim |
| --- | --- | --- | --- |
| Router only | Cannot reconstruct joined `d`, `a`, `x_client_base`, `y_relayer`, or `tau_relayer` from allowed state | Can drop, reorder, or replay unless replay cache rejects | Can deny service |
| Signer A only | Cannot reconstruct joined forbidden state without B | Can return malformed A-side output | Can deny A-side progress |
| Signer B only | Cannot reconstruct joined forbidden state without A | Can return malformed B-side output | Can deny B-side progress |
| Client only | Can reveal its own opened `x_client_base` | Can cause bad client-side use of outputs | Can abandon ceremonies |
| Relayer only | Can reveal opened `x_relayer_base` | Can misuse relayer-side output | Can deny relayer service |
| Storage only | Sees metadata and encrypted packages only | Cannot forge transcript evidence without role keys | Can lose replay or package state |
| Router + Signer A | Cannot reconstruct B-side state or joined forbidden state if B remains honest and envelopes hold | Can bias/drop A-side behavior and Router routing | Can deny service |
| Router + Signer B | Cannot reconstruct A-side state or joined forbidden state if A remains honest and envelopes hold | Can bias/drop B-side behavior and Router routing | Can deny service |
| Signer A + Signer B | Server-blind privacy claim fails for server-side derivation state | Can produce arbitrary candidate outputs | Can deny service |
| Router + A + B | Server-side privacy claim fails | Full server-side forgery within this primitive | Can deny service |

## Server-Blind Claim

Server blindness means no single server-side role, and no Router plus one signer
collusion set, has enough allowed state to reconstruct joined `d`, joined `a`,
or joined `x_client_base`.

The claim relies on:

- A and B keeping separate role-local derivation state
- Router transporting encrypted role envelopes without plaintext share access
- delivery material encrypted to the intended recipient
- transcript binding enforced by A and B
- replay cache enforcement at the Router or storage boundary

The claim does not survive A+B collusion.

## Minimum Level C Claims

Minimum Level C provides:

- transcript binding
- signer identity binding
- root epoch binding
- recipient binding
- replay rejection for changed bound fields
- server blindness under the corruption matrix above

Minimum Level C does not provide:

- public group-relation correctness
- detection of every malicious signer output
- proof that derived output matches the account public key
- protection from A+B collusion
- deployment attestation

## Stronger Public-Share-Binding Claims

The stronger correctness path adds public verifying-share binding and group
relation checks. That path is required if the product needs detection of
malicious signer output before address verification or recipient-side opening.

## Formal Verification Claims

Formal verification should model:

- allowed role views
- forbidden joined-state exclusion
- corruption sets up to Router plus one signer
- role/output authorization
- transcript field inclusion
- epoch and recipient separation

Formal verification should treat cryptographic security of hash functions,
envelope encryption, signatures, and elliptic-curve assumptions as explicit
external assumptions.
