# Refactor 115 — Minimal EIP-8130 Foundation and Vibenet MVP

Status: future/inactive. Current product uses normal threshold ECDSA owner
addresses for Tempo and EVM-family signing. Smart-account code has been removed
from the active SDK, server, config, persistence, and test surface. This plan
does not describe current behavior and must not add active code paths, public
API fields, config fields, database tables, or tests until the feature is
explicitly reintroduced.

Date created: August 25, 2026

## Goal

Prove that the existing Seams threshold-signing architecture can authorize a
native EIP-8130 smart account on Base Vibenet. Add the smallest isolated seam
needed for the experimental protocol.

Refactor 115 does not redesign wallet identity or generalize the current EVM
architecture. The existing architecture remains authoritative:

```text
WalletId
  -> EvmFamilyWalletKeyRecord
  -> threshold secp256k1 key
  -> existing signing flow
```

The MVP adds one leaf beside the current EIP-1559 adapter:

```text
active EvmFamilyWalletKeyRecord
  -> internal EIP-8130 account descriptor
  -> Eip8130NativeAdapter
  -> existing generic EVM-family threshold-signing flow
  -> direct Vibenet RPC submission
```

The proof is complete when one development wallet:

1. derives a counterfactual smart-account address;
2. deploys it and executes one call in a native type-`0x79` transaction;
3. verifies the account code and initial threshold-owner actor onchain;
4. executes a second native transaction without creation data.

## Minimal Change Surface

### Unchanged

- `EvmFamilyWalletKeyRecord` and all wallet-key lifecycle types;
- the meaning of `evmAddress` as the threshold-owner EOA address;
- `EvmSigningRequest`, `EvmAdapter`, and `signEvmWithUiConfirm`;
- Router A/B derivation, SigningWorker material, Wallet Sessions, budgets,
  step-up authorization, and presignatures;
- registration, recovery, sync, D1, IndexedDB, and browser wallet profiles;
- supported-chain configuration and public SDK types;
- existing EIP-1559 transaction, nonce, confirmation, and broadcast behavior.

### Added for the internal MVP

- one pinned Vibenet native-EIP-8130 profile;
- one internal EIP-8130 account descriptor and deployment-state union;
- one `Eip8130NativeAdapter` implementing the existing `ChainAdapter` contract;
- one internal signing entry point that reuses
  `signEvmFamilyWithUiConfirm`;
- deterministic reference vectors;
- one explicit Vibenet smoke command.

There is no repo-wide `EvmAccountIdentity` abstraction in Refactor 115. Product
account identity becomes relevant only when smart accounts enter registration,
persistence, and the public wallet surface. That decision belongs to the later
product-integration plan.

## MVP Operating Model

The MVP derives one smart account for the single development wallet used by the
smoke command. It does not create an account for every registered wallet.

When product integration is eventually designed, wallets explicitly configured
for smart-account use will each need a distinct deterministic account address.
The address can remain counterfactual until its first native transaction, so
there is no separate predeployment step for every wallet.

The MVP uses the pinned canonical Vibenet account implementation. It does not
deploy a Seams account implementation, factory, authenticator, or recovery
contract.

The MVP uses no relayer or ERC-4337 bundler. The account is self-funded through
the Vibenet faucet, signed through the existing threshold path, and submitted
directly with `eth_sendRawTransaction`.

## Internal Architecture

### Native chain profile

Keep the experimental network descriptor local to the EIP-8130 module:

```ts
type Eip8130NativeProfile = {
  readonly chainId: 84538453;
  readonly rpcUrl: 'https://rpc.vibes.base.org';
  readonly accountProfile: Eip8130AccountProfile;
};
```

`Eip8130AccountProfile` contains the pinned canonical deployment addresses,
runtime code and hashes, deployment version, and k1 authenticator identifier.
Callers cannot override those values.

Refactor 115 does not add Vibenet to general supported-chain configuration. A
later product plan may introduce a chain execution-profile union when there are
two real product execution modes to select between.

### Account descriptor and state

Use a protocol-local descriptor instead of changing global wallet identity:

```ts
type Eip8130AccountDescriptor = {
  readonly accountAddress: Eip8130AccountAddress;
  readonly ownerWalletKeyId: WalletKeyId;
  readonly ownerAddress: ThresholdOwnerAddress;
  readonly accountProfileId: Eip8130AccountProfileId;
};

type Eip8130AccountState =
  | {
      readonly state: 'counterfactual';
      readonly account: Eip8130AccountDescriptor;
      readonly createPlan: Eip8130CreatePlan;
      readonly codeHash?: never;
      readonly configSequence?: never;
    }
  | {
      readonly state: 'deployed';
      readonly account: Eip8130AccountDescriptor;
      readonly createPlan?: never;
      readonly codeHash: Eip8130RuntimeCodeHash;
      readonly configSequence: Eip8130ConfigSequence;
    };
```

The descriptor is constructed from an already resolved active
`EvmFamilyWalletKeyRecord`. It never establishes threshold signing readiness.
The state is derived from deterministic inputs and direct chain reads and is not
persisted.

### Protocol adapter

The new adapter follows the existing `ChainAdapter` shape:

```ts
class Eip8130NativeAdapter implements ChainAdapter<
  Eip8130SigningRequest,
  Eip8130IntentUiModel,
  Eip8130SignedResult
> {
  readonly chain = 'evm' as const;

  buildIntent(
    request: Eip8130SigningRequest,
  ): Promise<SigningIntent<Eip8130IntentUiModel, Eip8130SignedResult>>;
}
```

It is independent of `EvmAdapter`. The adapter owns every shape imported from
the pinned EIP implementation:

- account and CREATE2 derivation;
- create-plan construction;
- sender-payload hashing;
- k1 `sender_auth` encoding;
- type-`0x79` serialization;
- native RPC extensions and receipt parsing.

The adapter emits one secp256k1 digest sign request. The existing generic
EVM-family signing flow handles threshold authorization and signing. This is the
main integration seam proven by Refactor 115.

### Internal signing request

The MVP request is local to the EIP-8130 module. It is not added to the existing
`EvmSigningRequest` union:

```ts
type Eip8130SigningRequest = {
  readonly chain: 'evm';
  readonly kind: 'eip8130';
  readonly nonce: Eip8130OrderedNonceKeyZero;
  readonly gas: Eip8130GasFields;
  readonly payer: { readonly kind: 'self' };
  readonly validity: Eip8130ValidityWindow;
  readonly metadata: { readonly kind: 'none' };
  readonly senderSignatureAlgorithm: 'secp256k1';
} & (
  | {
      readonly operation: 'deploy_and_call';
      readonly account: CounterfactualEip8130Account;
      readonly call: Eip8130Call;
    }
  | {
      readonly operation: 'call';
      readonly account: DeployedEip8130Account;
      readonly call: Eip8130Call;
    }
);
```

Only ordered nonce key `0`, self-payment, no metadata, and one call are valid.
The counterfactual branch contains the adapter-derived create plan. Application
input cannot supply deployment addresses, creation bytes, authenticators, actor
changes, payer data, or alternate nonce modes.

### Signing and transport

The internal signing entry point supplies the new adapter and EIP-8130 display
model to the existing `signEvmFamilyWithUiConfirm` flow. It does not fork
threshold authorization or signing logic.

One request performs:

1. validate the pinned profile, account state, active owner binding, nonce, gas,
   validity, and call;
2. build structured confirmation facts;
3. hash the exact EIP-8130 sender payload;
4. obtain one threshold secp256k1 signature through the existing flow;
5. encode `sender_auth` and serialize the type-`0x79` transaction;
6. submit exact raw bytes through the existing RPC boundary;
7. parse every receipt phase and inspect final account state.

Confirmation shows Vibenet, chain ID, smart-account address, threshold-owner
address, creation action when present, call target, calldata summary, nonce,
validity, gas, fees, and self-payment.

## Deterministic Account Derivation

Pin the specification, reference contracts, client implementation, canonical
Vibenet deployment, and all relevant code hashes to immutable revisions.

For the MVP, derive the salt from the dedicated development wallet and pinned
account profile:

```text
SHA-256(
  encodeTuple(
    "seams/eip8130/account-salt/v1",
    WalletId,
    Eip8130AccountProfileId
  )
)
```

The CREATE2 address also commits to the runtime code and sorted initial actor
set. The initial actor set contains exactly one unrestricted k1 actor derived
from the active threshold-owner address.

This derivation is an internal protocol detail for the MVP. Its suitability as
a permanent product derivation is reviewed after the final EIP and account
implementation stabilize.

## Implementation Plan

### Phase 0 — Pin and reproduce

- Pin one EIP-8130 specification commit, reference-contracts commit, and client
  implementation commit.
- Record Vibenet chain ID `84538453`, RPC endpoint, canonical deployments, and
  code hashes.
- Reproduce reference vectors for account address, sender digest, serialized
  transaction, transaction hash, and initial actor configuration.
- Verify the live RPC methods required for account reads, nonce reads, gas
  estimation, raw submission, and receipts.

Stop if immutable inputs cannot reproduce the reference behavior.

### Phase 1 — Add the isolated leaf

- Add the protocol-local profile, account descriptor, state union, request,
  result, and receipt types.
- Add `Eip8130NativeAdapter` beside `EvmAdapter` without modifying the latter.
- Add the internal EIP-8130 signing entry point using
  `signEvmFamilyWithUiConfirm`.
- Keep every fork-specific import inside the EIP-8130 module.
- Add type fixtures and deterministic vector tests for this module.

### Phase 2 — Prove Vibenet

Add one explicit development smoke command that:

1. loads a dedicated wallet with an active threshold ECDSA lane;
2. derives its counterfactual account and confirms no code is deployed;
3. funds the address through the Vibenet faucet;
4. submits one `deploy_and_call` transaction;
5. verifies the runtime code hash, configuration sequence, and k1 owner actor;
6. resolves the account as deployed from direct reads;
7. submits one ordinary `call` without creation data;
8. verifies every receipt phase and final account state.

The command uses the adapter and existing threshold-signing flow. It logs only
public addresses, actor identifiers, transaction hashes, block numbers, and
verification results.

### Phase 3 — Stop

- Confirm `EvmAdapter`, `EvmSigningRequest`, and EIP-1559 behavior are unchanged.
- Remove temporary helpers and duplicate protocol shapes.
- Document the adapter inputs that must change for a future EIP revision.
- Record the two Vibenet transaction hashes and verified postconditions.

Do not add registration, persistence, rotation, recovery, relaying, supported-
chain configuration, or public APIs.

## Verification and Exit Criteria

- Pinned account-address and transaction vectors match exactly.
- Invalid counterfactual/deployed request combinations fail typecheck.
- The EIP-8130 adapter emits one digest into the existing threshold-signing
  flow.
- Existing EIP-1559 types, adapter, flow, and focused tests are unchanged.
- One Vibenet transaction creates the no-EOA account and executes a call.
- Onchain code, configuration sequence, and owner actor match the create plan.
- A second Vibenet transaction succeeds without creation data.
- No product identity abstraction, persistence, registration behavior, public
  SDK method, relayer, bundler, or custom contract is introduced.
- No production-support claim is made.

A Vibenet outage is an `environment_or_infrastructure_failure`; deterministic
vectors remain authoritative. Do not add an intended-behavior contract for this
internal experimental path.

## Deferred Follow-On Plans

1. **Product integration:** decide how smart-account identity appears in
   registration, persistence, sync, supported chains, and public SDK methods.
2. **Owner rotation:** authorize a replacement threshold owner, verify the
   onchain actor change, and retire the old owner without changing the account
   address.
3. **Recovery:** design recovery-code and DKIM or guardian authenticators,
   including delay, cancellation, replay, notification, and gas policy.
4. **Portability and production:** support additional native chains or ERC-4337,
   sponsorship, audits, observability, and incident response.

Each follow-on plan must justify its own state and infrastructure. Smart-account
state never becomes a source of threshold-key identity.

## References

- [EIP-8130 specification](https://eips.ethereum.org/EIPS/eip-8130)
- [EIP-8130 builder guide](https://www.eip8130.com/guide)
- [Vibenet getting started](https://www.eip8130.com/guide/getting-started)
- [Creating EIP-8130 accounts](https://www.eip8130.com/guide/creating-accounts)
- [EIP-8130 reference contracts](https://github.com/base/eip-8130)
- [Refactor 37 smart-account deletion and future-plan boundary](./refactor-37.md)
- [EVM ECDSA address invariant](../apps/docs/src/concepts/threshold-signing/evm-ecdsa.md)
- [Key-rotation taxonomy](../apps/docs/src/concepts/delegation/key-rotation.md)
