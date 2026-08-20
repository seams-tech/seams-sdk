# Solana signer support (deferred)

**Status:** Deferred. This document describes a possible implementation. Solana is not a supported `ChainNamespace`, signer, custody key, or public SDK surface today.

## Decision

Add Solana as an independent Ed25519 wallet family when it becomes a product priority. Reuse the existing threshold Ed25519 protocol where its message-signing semantics fit, then build a Solana-specific transaction boundary, authorization model, RPC lifecycle, custody identity, and recovery path around it.

Solana signatures cover the canonical serialized transaction message bytes. The implementation must sign those bytes directly. Hashing the message into the current 32-byte digest request would produce a different signature domain and an invalid Solana transaction.

## Initial scope

The first release should support:

- one Solana Ed25519 public key per wallet custody seed;
- legacy and version-0 transaction messages;
- Address Lookup Table resolution for version-0 messages;
- native SOL transfers;
- SPL Token transfers and Associated Token Account creation;
- fee-payer signing and transactions with additional signers;
- `mainnet-beta` and `devnet` through an application-configured RPC endpoint;
- simulation, broadcast, and blockheight-based confirmation.

Initial support should exclude:

- proposed transaction versions that are not active on the target cluster;
- durable nonce transactions;
- stake, vote, program deployment, and validator operations;
- blind approval of arbitrary program instructions;
- advanced Token-2022 extensions until each extension has an explicit decoder and policy;
- private transaction semantics, which Solana does not provide at the base transaction layer.

## Custody and key identity

Introduce a `SolanaEd25519` entry in the wallet key manifest and a dedicated seed-derivation label. Its group public key becomes the wallet's 32-byte Solana account address, encoded with base58 for display and RPC use.

The Solana root must be derived in parallel with the existing owner signing roots. It must never reuse the NEAR Ed25519 root, shares, participant transcript, key identifier, lane material, or public key. Separate derivation domains preserve chain separation and allow Solana policy, rotation, and retirement to evolve independently.

Registration and recovery become custody ceremonies for the enlarged manifest. Both flows must prove that the wallet custody seed reproduces the same Solana public key together with every other owner key. Factor addition continues to authenticate and reseal the existing seed without deriving a replacement identity.

The initial threshold shape should follow the existing owner Ed25519 deployment unless a protocol review chooses a different participant set. Device linking provisions the material needed by the linked owner while preserving the same aggregate public key. Lane shares remain per-lane material and stay outside recovery sets.

## Transaction boundary

Raw RPC JSON, wallet-adapter objects, and serialized transaction bytes are untrusted inputs. Parse them once into a precise union before policy or signing:

```ts
type SolanaSigningTransaction =
  | {
      version: 'legacy';
      messageBytes: Uint8Array;
      message: ParsedLegacyMessage;
      signatures: readonly SolanaSignatureSlot[];
    }
  | {
      version: 0;
      messageBytes: Uint8Array;
      message: ParsedV0Message;
      addressTableLookups: readonly ResolvedAddressTableLookup[];
      signatures: readonly SolanaSignatureSlot[];
    };
```

The concrete types should follow repository conventions: required identity and lifecycle fields, branch-specific builders, exhaustive switches, and boundary parsers for base58 values, compact arrays, account indexes, short-vector lengths, and lookup-table data.

Parsing must reject malformed encodings, unsupported versions, duplicate or unresolved lookup entries, invalid signature counts, out-of-range account indexes, and messages over the cluster's accepted transaction-size limit. The parser must retain the exact serialized `messageBytes`; reconstruction is allowed only when the SDK itself built the message and verifies a byte-for-byte round trip.

## Authorization model

Approval must describe the exact message that the threshold protocol will sign. The authorization record should bind at least:

- cluster/genesis identity and RPC policy;
- transaction version and exact message bytes or a collision-resistant commitment to them;
- fee payer and the wallet's signer index;
- recent blockhash and `lastValidBlockHeight`;
- static and lookup-loaded account keys, including signer and writable privileges;
- every program id, instruction, and instruction data payload;
- compute-unit limits and priority-fee instructions;
- decoded transfers, token mints, recipients, amounts, and created accounts;
- the expected set of occupied and empty signature slots.

Use allowlisted decoders for the System Program, SPL Token Program, Associated Token Account Program, and the explicitly supported Token-2022 instructions. An unknown program or instruction must surface as raw program id, accounts, and data, then require a separately designed expert policy. It should be denied by the initial product policy.

Simulation is diagnostic evidence. It must never replace decoding or influence the authorized message after approval. Any mutation to account order, signer bits, program data, lookup tables, blockhash, or fee instructions creates a different operation and requires fresh authorization.

## Signing and submission flow

1. Fetch `getLatestBlockhash` and retain both `blockhash` and `lastValidBlockHeight`.
2. Build or parse a legacy or version-0 message and resolve every Address Lookup Table against the selected cluster.
3. Derive the display and policy facts from the exact parsed message.
4. Simulate the assembled transaction when useful. Treat simulation output as advisory.
5. Authorize the exact message and its validity window.
6. Run threshold Ed25519 over the canonical serialized message bytes.
7. Verify the resulting 64-byte signature locally against the Solana group public key and exact message bytes.
8. Insert the signature at the slot corresponding to that public key, preserving valid co-signer signatures byte for byte.
9. Serialize and send the complete transaction, then confirm it before `lastValidBlockHeight`.

A stale blockhash is a terminal result for that authorization. Refreshing the blockhash changes the signed message, so the SDK must rebuild and request authorization again. Automatic rebroadcast may reuse the identical signed bytes while their validity window remains open.

## SDK integration

Implementation should extend the existing seams directly:

- add `solana` to `ChainNamespace` and introduce explicit Solana cluster configuration;
- add a Solana branch to the wallet key manifest, seed derivation, custody ceremony, recovery re-establishment, device linking, and public identity records;
- expose a raw-message Ed25519 signing request whose input is required `message: Uint8Array`; keep the current digest request for chains that sign a digest;
- add `chains/solana` transaction parsing, serialization, instruction decoding, and intent construction;
- add a `signSolana` flow with Solana-specific prepared, authorized, signing, submitted, confirmed, expired, and failed states;
- add an RPC client for blockhash acquisition, lookup-table reads, simulation, submission, and confirmation;
- expose the final API through a Solana-specific client surface rather than widening EVM or NEAR request objects.

The current NEAR integration and names remain NEAR-specific. The reusable unit is the lower-level threshold Ed25519 protocol. Extract a chain-neutral raw-message entry point only after a Solana vector proves that the existing primitive signs arbitrary message bytes with the required transcript and verification semantics.

## Delivery phases

### 1. Protocol and custody proof

- Add deterministic Solana derivation, manifest, registration, and recovery vectors.
- Prove threshold Ed25519 signs arbitrary-length canonical Solana message bytes.
- Verify the aggregate signature with an independent Solana implementation.
- Review domain separation, transcript binding, nonce handling, and maximum-message behavior.

### 2. Transaction codec and intent

- Implement strict legacy and version-0 parsers and serializers.
- Resolve Address Lookup Tables and freeze their contents into authorization.
- Decode the initial allowlist of system and token instructions.
- Produce a stable human-readable approval model from exact message fields.

### 3. RPC lifecycle

- Implement blockhash acquisition, simulation, broadcast, rebroadcast, expiry, and confirmation.
- Preserve partial signatures and support a threshold signer in any required signature slot.
- Demonstrate native SOL and SPL Token transfers on `devnet`.

### 4. Product integration and audit

- Add intended-behaviour contracts for registration, unlock, signing, expiry, recovery, and device linking.
- Complete an independent review of the new Ed25519 message-signing surface and Solana transaction boundary.
- Enable `mainnet-beta` only after interoperability, recovery, and policy evidence is complete.

## Security and privacy constraints

- The displayed intent and threshold transcript must commit to the same exact message bytes.
- The signer must verify its expected public key occupies the claimed required-signature slot.
- Resolved lookup-table accounts must be included in policy evaluation; table addresses alone are insufficient.
- Co-signer signatures must be verified where present and preserved exactly.
- RPC responses are untrusted. Cluster identity, blockhash fields, lookup-table owners, account data, and confirmation status require boundary validation.
- Logs and telemetry must exclude raw transaction bytes when they could expose sensitive application activity. Solana transaction contents and account addresses remain public on-chain.
- Export, recovery, and rotation must preserve the documented public identity or report an explicit new-wallet operation.

## Acceptance evidence

Solana support is ready only when all of the following pass:

- deterministic legacy and version-0 vectors cross-check against an independent Solana SDK;
- threshold signatures verify over the exact serialized message and are accepted on `devnet`;
- mutations to blockhash, account order, privileges, instructions, lookup contents, and compute-budget fields invalidate authorization or signature verification;
- multi-signer fixtures preserve existing signatures and place the threshold signature in the correct slot;
- expiry produces a typed terminal result and never silently re-signs a refreshed message;
- recovery recreates the identical Solana public key and key-manifest entry;
- intended-behaviour contracts cover the complete supported lifecycle;
- an external cryptographic and transaction-boundary review has no unresolved high-severity findings.

## References

- [Solana transactions](https://solana.com/docs/core/transactions)
- [Versioned transactions and Address Lookup Tables](https://solana.com/developers/guides/advanced/versions)
- [RPC JSON transaction structures](https://solana.com/docs/rpc/json-structures)
- [`getLatestBlockhash`](https://solana.com/docs/rpc/http/getlatestblockhash)
- [`simulateTransaction`](https://solana.com/docs/rpc/http/simulatetransaction)
- [`sendTransaction`](https://solana.com/docs/rpc/http/sendtransaction)
- [Transaction confirmation and expiration](https://solana.com/developers/guides/advanced/confirmation)
