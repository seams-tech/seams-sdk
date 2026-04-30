# EVM Smart Account Spec

## Goal

Define one canonical EVM smart-account surface for:

- normal owner management during `linkDevice`
- privileged email recovery driven by `recoveryAuthority`
- deferred deployment from canonical off-chain signer state
- sponsored execution on deployed accounts

This spec is the contract-side counterpart to [evm-device-linking.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/evm-device-linking.md).

## Non-goals

- DKIM verification on EVM
- DNS / raw email parsing on EVM
- live NEAR state reads from EVM
- multiple recovery backends in one contract
- legacy compatibility shims

## Core model

Each user has one smart account per EVM chain.

The contract stores:

- the active owner set
- the canonical account-binding hash for that account
- one global `recoveryAuthority`
- replay protection for recovery authorizations
- optional ERC-4337 execution configuration

The contract does not store:

- recovery email payloads
- DKIM proofs
- NEAR public keys in plaintext
- off-chain pending owners for undeployed accounts

## Trust model

`recoveryAuthority` is the only recovery trust root on EVM.

- normal owner mutations are authorized by an existing active owner
- recovery mutations are authorized by an EIP-712 signature from `recoveryAuthority`
- the transaction caller is not trusted

`verifyAndRecover()` must remain publicly callable. The caller can be:

- the relayer
- another executor
- the user

Authorization still comes from the signed recovery payload, not `msg.sender`.

## Required interfaces

### `ISeamsSmartAccount`

```solidity
interface ISeamsSmartAccount is
  ISeamsSmartAccountView,
  ISeamsSmartAccountOwners,
  ISeamsSmartAccountRecovery,
  ISeamsSmartAccountExecution,
  IERC1271
{}
```

### `ISeamsSmartAccountView`

```solidity
interface ISeamsSmartAccountView {
  function accountVersion() external pure returns (uint256);
  function nearAccountIdHash() external view returns (bytes32);
  function recoveryAuthority() external view returns (address);
  function entryPoint() external view returns (address);
  function isOwner(address owner) external view returns (bool);
  function getOwners() external view returns (address[] memory);
  function ownerCount() external view returns (uint256);
  function isRecoveryNonceUsed(bytes32 nonce) external view returns (bool);
}
```

### `ISeamsSmartAccountOwners`

```solidity
interface ISeamsSmartAccountOwners {
  function addOwner(address owner) external;
  function removeOwner(address owner) external;
}
```

### `ISeamsSmartAccountRecovery`

```solidity
interface ISeamsSmartAccountRecovery {
  function verifyAndRecover(
    bytes32 nearAccountIdHash,
    bytes32 newNearKeyHash,
    address newOwner,
    bytes32 recoverySessionHash,
    uint256 nonce,
    uint256 deadline,
    bytes calldata authoritySignature
  ) external;

  function recoverAddOwner(
    bytes32 nearAccountIdHash,
    bytes32 newNearKeyHash,
    address newOwner,
    bytes32 recoverySessionHash,
    uint256 nonce,
    uint256 deadline,
    bytes calldata authoritySignature
  ) external;
}
```

### `ISeamsSmartAccountExecution`

```solidity
interface ISeamsSmartAccountExecution {
  function execute(address target, uint256 value, bytes calldata data) external payable returns (bytes memory);
  function executeBatch(
    address[] calldata targets,
    uint256[] calldata values,
    bytes[] calldata data
  ) external payable returns (bytes[] memory);
}
```

### `ISeamsSmartAccountFactory`

```solidity
interface ISeamsSmartAccountFactory {
  function createAccount(
    bytes32 salt,
    bytes calldata initData
  ) external returns (address account);

  function getAddress(
    bytes32 salt,
    bytes calldata initData
  ) external view returns (address account);
}
```

## Initialization

The smart account must be initializable exactly once.

Canonical initializer shape:

```solidity
struct SmartAccountInit {
  bytes32 nearAccountIdHash;
  address recoveryAuthority;
  address entryPoint;
  address[] owners;
}

function initialize(SmartAccountInit calldata init) external;
```

Rules:

- `owners.length > 0`
- every owner must be unique and non-zero
- `recoveryAuthority != address(0)`
- `nearAccountIdHash != bytes32(0)`
- initializer may only run once

For undeployed accounts, `owners` must come from the canonical deployment manifest materialized from server-side signer state. The factory must not invent or reorder owners independently of that manifest.

## Owner management

### `addOwner(address owner)`

Purpose:

- normal device linking
- normal signer rotation while an active owner still exists

Requirements:

- caller must be an active owner, or the configured ERC-4337 `entryPoint` acting on a valid owner-authorized user operation
- `owner` must be non-zero
- `owner` must not already be active

Effects:

- add `owner` to the active owner set
- emit `OwnerAdded(owner, actor)`

### `removeOwner(address owner)`

Purpose:

- remove lost, rotated, or revoked signers

Requirements:

- caller must be an active owner, or the configured `entryPoint` acting on a valid owner-authorized user operation
- `owner` must currently be active
- removal must not leave the account with zero owners

Effects:

- remove `owner` from the active owner set
- emit `OwnerRemoved(owner, actor)`

## Recovery authorization

The recovery path must use the same typed payload the relayer already prepares off-chain.

### Domain

```solidity
EIP712Domain(
  string name,
  string version,
  uint256 chainId,
  address verifyingContract
)
```

Canonical values:

- `name = "SeamsSmartAccountRecovery"`
- `version = "1"`
- `chainId = block.chainid`
- `verifyingContract = address(this)`

### Struct

```solidity
RecoverAddOwner(
  bytes32 nearAccountIdHash,
  bytes32 newNearKeyHash,
  address newOwner,
  bytes32 recoverySessionHash,
  uint256 nonce,
  uint256 deadline
)
```

Notes:

- `nearAccountIdHash` binds the account to the canonical account identifier
- `newNearKeyHash` makes the exact NEAR recovery key auditable
- `newOwner` is the EVM owner being installed
- `recoverySessionHash` binds the mutation to one verified recovery session
- `nonce` provides replay protection
- `deadline` provides expiry

## Recovery functions

### `verifyAndRecover(...)`

This is the primary public recovery entrypoint.

Semantics:

- recover signer continuity using a `recoveryAuthority` signature
- callable by anyone
- verifies the typed recovery payload
- consumes the recovery nonce
- adds `newOwner` if it is not already active

This function should be the preferred entrypoint for relayers and any future external executors.

### `recoverAddOwner(...)`

This is a second explicit selector for the same recovery authorization model.

Semantics:

- identical authorization checks to `verifyAndRecover`
- same state transition
- same nonce consumption rules

Implementation rule:

- both selectors must call one shared internal recovery implementation
- do not maintain separate replay logic or separate storage semantics per method

The only intentional difference is the function selector, which lets off-chain policy and observability distinguish recovery routes without introducing a second trust model.

## Recovery validation rules

Both recovery functions must enforce all of the following:

1. `nearAccountIdHash` must equal the account's stored `nearAccountIdHash`
2. `newOwner` must be non-zero
3. `deadline >= block.timestamp`
4. `nonce` must be unused
5. recovered signer from `authoritySignature` must equal `recoveryAuthority`
6. the signature must be over the contract's own EIP-712 domain
7. if `newOwner` is already active, the call should revert rather than silently succeed

Effects on success:

1. mark `nonce` used
2. add `newOwner` to the active owner set
3. emit a recovery event containing the hashed recovery fields

## Replay protection

Replay protection must be on-chain and per-account.

Required storage:

```solidity
mapping(bytes32 => bool) private _usedRecoveryNonces;
```

Rules:

- a nonce is consumed exactly once
- a reverted call must not consume a nonce
- nonce reuse across different callers must still fail
- replay protection is enforced by storage, not by trusting the relayer

Recommended getter:

```solidity
function isRecoveryNonceUsed(bytes32 nonce) external view returns (bool);
```

## Execution model

The account needs a standard execution surface for normal EVM use.

### `execute(...)`

Requirements:

- callable by an active owner or valid `entryPoint`
- forwards `value` and `data` to `target`
- bubbles revert data

### `executeBatch(...)`

Requirements:

- same authorization model as `execute`
- array lengths must match
- executes in order
- reverts atomically on failure

If the final implementation adopts ERC-4337-only execution, keep these functions but allow the account to reject direct non-`entryPoint` execution unless a direct-owner mode is intentionally supported. The recovery and owner-management interfaces should not depend on that choice.

## Signature validation

The contract should implement `IERC1271`.

Recommended behavior:

- return valid if the signature resolves to an active owner
- support the same owner signature scheme used by the account's user-operation validation path

This is needed for standard smart-account interoperability.

## Events

```solidity
event OwnerAdded(address indexed owner, address indexed actor);
event OwnerRemoved(address indexed owner, address indexed actor);
event RecoveryOwnerAdded(
  bytes32 indexed recoverySessionHash,
  bytes32 indexed nonce,
  address indexed owner,
  bytes32 nearAccountIdHash,
  bytes32 newNearKeyHash,
  address authority
);
event RecoveryAuthorityUpdated(address indexed oldAuthority, address indexed newAuthority);
```

Notes:

- do not emit plaintext NEAR account IDs or NEAR public keys; emit hashes
- `actor` is `msg.sender`
- recovery events must make replay/debugging straightforward from logs alone

## Errors

Recommended custom errors:

```solidity
error AlreadyInitialized();
error NotOwner();
error InvalidOwner();
error OwnerAlreadyExists(address owner);
error OwnerDoesNotExist(address owner);
error LastOwnerRemovalForbidden();
error InvalidRecoveryAuthority();
error InvalidNearAccountBinding();
error RecoveryNonceAlreadyUsed(bytes32 nonce);
error RecoveryAuthorizationExpired(uint256 deadline, uint256 nowTs);
error InvalidRecoverySignature();
error InvalidEntryPoint();
error ArrayLengthMismatch();
error ExecutionFailed(bytes data);
```

## Authorization internals

The contract should have one internal recovery primitive:

```solidity
function _recoverAddOwner(
  bytes32 nearAccountIdHash_,
  bytes32 newNearKeyHash,
  address newOwner,
  bytes32 recoverySessionHash,
  uint256 nonce,
  uint256 deadline,
  bytes calldata authoritySignature
) internal;
```

Both `verifyAndRecover` and `recoverAddOwner` must delegate to it.

The contract should also have one internal owner mutation primitive:

```solidity
function _addOwner(address owner) internal;
function _removeOwner(address owner) internal;
```

## Factory / deployment requirements

The factory must support deterministic deployment from the canonical deployment manifest.

Required inputs:

- `salt`
- encoded initializer data

The manifest used to build initializer data must include:

- `nearAccountIdHash`
- `recoveryAuthority`
- `entryPoint`
- the current canonical owner set

If an account stayed undeployed during device linking or recovery, later deployment must use the latest canonical owner set. It must not deploy from stale client-local state.

## Storage requirements

Minimum persistent storage:

```solidity
bytes32 private _nearAccountIdHash;
address private _recoveryAuthority;
address private _entryPoint;
mapping(address => bool) private _isOwner;
address[] private _owners;
mapping(bytes32 => bool) private _usedRecoveryNonces;
bool private _initialized;
```

The implementation may add indexing helpers for gas efficiency, but it must not weaken uniqueness or replay guarantees.

## Security invariants

The contract must maintain all of these invariants:

- there is always at least one active owner after initialization
- owner membership is unique
- recovery signatures are domain-separated by chain and contract address
- recovery nonces are single-use
- recovery expires after `deadline`
- public callers cannot bypass `recoveryAuthority`
- normal owner management and privileged recovery remain distinct code paths
- legacy owners cannot remove the latest recovered owner once recovery succeeds

## Open choices

These do not change the required recovery surface, but the implementation must choose them explicitly:

- V1 choice: direct-owner execution remains enabled and the configured `entryPoint` is also authorized
- V1 choice: ERC-4337 validation is pinned to the v0.7 `PackedUserOperation` / `validateUserOp(...)` surface
- V1 choice: ERC-1271 and user-op validation both use raw active-owner ECDSA signatures
- upgradable proxy vs immutable implementation
- exact factory address derivation scheme

## Canonical recommendation

Build one minimal ERC-4337-compatible account with:

- `initialize`
- `addOwner`
- `removeOwner`
- `verifyAndRecover`
- `recoverAddOwner`
- `execute`
- `executeBatch`
- `isValidSignature`
- view getters for owners, `nearAccountIdHash`, `recoveryAuthority`, and used recovery nonces

Everything else should remain out of scope unless a real product requirement appears.

## Phased todo list

### Phase 0: Canonical surface alignment

- [x] extend the canonical deployment manifest to carry all initializer inputs needed by this spec: `nearAccountIdHash`, `recoveryAuthority`, `entryPoint`, and the canonical owner set
- [x] pin one ERC-4337 target for V1 and remove ambiguity: entry point version, validation surface, and direct-owner-vs-`entryPoint` execution policy
- [x] align off-chain recovery authorization semantics so `verifyAndRecover` and `recoverAddOwner` differ only by selector, not by replay domain or nonce derivation
- [x] add contract-facing integration vectors in this repo for initializer encoding, recovery calldata generation, and expected event payloads

### Phase 1: Smart account contract

- [x] add an in-repo contract package at `/contracts/evm-smart-account` with its own Solidity toolchain, tests, deployment scripts, and generated ABI artifacts
- [x] implement `initialize`, `addOwner`, `removeOwner`, `verifyAndRecover`, `recoverAddOwner`, `execute`, `executeBatch`, and `isValidSignature`
- [x] implement one shared `_recoverAddOwner(...)` path and shared replay storage used by both recovery selectors
- [x] enforce owner uniqueness, last-owner protection, deadline expiry, EIP-712 domain separation, and public-call recovery semantics
- [x] emit the canonical owner and recovery events from this spec

Current package status:

- implemented under `/contracts/evm-smart-account`
- tested with local forge unit tests and deterministic factory coverage
- current V1 choice is direct-owner execution plus configured-`entryPoint` authorization
- current V1 choice is ERC-4337 v0.7 `PackedUserOperation` with local `validateUserOp(...)` support
- server-side canonical registration + deployment-manifest materialization now persist `recoveryAuthority` and derive `nearAccountIdHash` from canonical `nearAccountId`
- canonical recovery-subject manifest sync now persists the derived `evmDeploymentPlan` for EVM accounts and clears stale plan metadata for non-EVM targets
- off-chain recovery authorization now matches the selector-independent digest and shared replay semantics used by the smart-account spec
- deployed recovery and deployed `addOwner` / `removeOwner` owner-mutation paths now derive canonical selectors from in-repo smart-account spec metadata
- sponsored recovery execution rows now persist canonical `recoverySpec` metadata for the exact smart-account call plus signed authorization payload
- targeted verification now covers sponsored recovery submission, retry requeue, and receipt confirmation while preserving canonical `recoverySpec` metadata
- relayer end-to-end coverage now includes undeployed recovery continuation plus deployed recovery submission and receipt confirmation while preserving canonical `recoverySpec` metadata
- relayer end-to-end coverage now includes deterministic factory deployment from the canonical `evmDeploymentPlan`
- a reusable EVM deploy hook now executes deterministic factory deployment directly from the canonical `evmDeploymentPlan`
- package-local helper scripts now cover init-data encoding, counterfactual address prediction, recovery calldata encoding, and `RecoveryOwnerAdded(...)` event encoding
- package-local metadata artifacts now export function selectors, error selectors, event topics, and bytecode hashes under `/contracts/evm-smart-account/abi`
- source-backed verification now covers current deployed owner-mutation runtime and shared replay rejection against the in-repo smart-account spec package
- canonical deployment planning now preserves manifest owner ordering all the way into smart-account init data
- spec-package deployment tests now cover undeployed-to-deployed continuity when canonical owner state already includes link-device or recovery mutations
- the V1 smart-account spec-track checklist is now complete; broader multichain follow-ons remain in [evm-device-linking.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/evm-device-linking.md)

### Phase 2: Factory and deployment path

- [x] implement deterministic factory deployment from canonical manifest data
- [x] guarantee initializer owner ordering matches the canonical manifest exactly
- [x] wire deployment tooling to materialize init data from canonical server-side signer state only, never stale client-local state
- [x] add spec-package tests for undeployed-to-deployed continuity after link-device and recovery mutations

### Phase 3: Relay and sponsorship integration

- [x] wire deployed recovery execution against the final spec ABI and selectors
- [x] wire deployed link-device owner mutations against the same spec ABI
- [x] persist deployment-manifest and recovery metadata needed for spec calls, receipt tracking, and observability
- [x] verify sponsored recovery settlement, retry behavior, and receipt confirmation against the final spec implementation

### Phase 4: Verification and cleanup

- [x] add end-to-end tests covering undeployed recovery continuation through `/recover-email`
- [x] add end-to-end tests covering deployed recovery submission and confirmation while preserving canonical `recoverySpec` metadata
- [x] add end-to-end tests covering deterministic factory deployment from canonical `evmDeploymentPlan`
- [x] add source-backed verification covering owner add/remove mutations against current client modules
- [x] add source-backed verification covering replay rejection against the in-repo smart-account spec package
- [x] add negative tests for expired authorization, bad signer, wrong `nearAccountIdHash`, reused nonce, and duplicate owner recovery
- [x] remove any superseded legacy smart-account assumptions once the canonical spec path is active
- [x] update the device-linking and recovery docs to mark completed items and delete obsolete transitional notes

Recommended repo shape for V1:

- keep the EVM smart-account spec in this repo
- isolate it as `/contracts/evm-smart-account`
- keep ABI generation, relayer integration, and recovery authorization fixtures versioned alongside the server/client code that consumes them
