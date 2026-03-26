# Tatchi EVM Smart Account

This package contains the first in-repo implementation of the EVM smart-account
surface described in:

- `docs/evm-smart-accounts.md`
- `docs/evm-device-linking.md`

Current implementation choices for this bootstrap package:

- direct owner execution is enabled
- the configured `entryPoint` is also authorized to call owner-management and execution functions
- ERC-4337 validation is pinned to the v0.7 `PackedUserOperation` / `validateUserOp(...)` surface
- `IERC1271` validation accepts raw ECDSA signatures from active owners
- `verifyAndRecover` and `recoverAddOwner` share one recovery primitive and one replay store
- `validateUserOp` currently accepts raw owner ECDSA signatures over `userOpHash`
- the factory and account do not yet integrate with external EntryPoint libraries or paymaster helpers

The factory expects:

- `salt`: an arbitrary deployment salt
- `initData`: `abi.encode(SmartAccountInit({ ... }))`

Factory helper methods:

- `computeDeploymentSalt(bytes32 salt, bytes initData)`
- `accountCreationCodeHash()`

These expose the exact CREATE2 derivation inputs used by the factory so off-chain tooling can
reuse them without copying hidden internal logic.

## Commands

```bash
pnpm --dir contracts/evm-smart-account build
pnpm --dir contracts/evm-smart-account test
pnpm --dir contracts/evm-smart-account export:abi
pnpm --dir contracts/evm-smart-account export:metadata
pnpm --dir contracts/evm-smart-account export:all
pnpm --dir contracts/evm-smart-account encode:init
pnpm --dir contracts/evm-smart-account predict:account
pnpm --dir contracts/evm-smart-account encode:recovery
pnpm --dir contracts/evm-smart-account encode:event
```

## ABI artifacts

Generated ABI JSON files are written to:

- `abi/TatchiSmartAccount.json`
- `abi/TatchiSmartAccountFactory.json`
- `abi/TatchiSmartAccount.metadata.json`
- `abi/TatchiSmartAccountFactory.metadata.json`

Regenerate them with:

```bash
bash ./script/export-abi.sh
bash ./script/export-metadata.sh
```

The metadata JSON files include:

- function selectors with `0x` prefixes
- custom error selectors
- event topics
- creation bytecode hash
- deployed bytecode hash

## Helper scripts

`script/encode-init-data.sh`

- requires `NEAR_ACCOUNT_ID_HASH`
- requires `RECOVERY_AUTHORITY`
- requires `OWNERS` as a comma-separated address list
- accepts optional `ENTRY_POINT` and defaults it to `0x0000000000000000000000000000000000000000`
- outputs `abi.encode(SmartAccountInit(...))`

`script/predict-account-address.sh`

- requires `FACTORY_ADDRESS`
- requires `SALT`
- accepts `INIT_DATA` directly, or derives it from the same env vars as `encode-init-data.sh`
- outputs the deterministic CREATE2 address used by `TatchiSmartAccountFactory`

`script/encode-recovery-calldata.sh`

- requires `NEAR_ACCOUNT_ID_HASH`
- requires `NEW_NEAR_KEY_HASH`
- requires `NEW_OWNER`
- requires `RECOVERY_SESSION_HASH`
- requires `NONCE`
- requires `DEADLINE`
- requires `AUTHORITY_SIGNATURE`
- accepts optional `CONTRACT_METHOD` with `verifyAndRecover` as the default
- outputs contract calldata for `verifyAndRecover(...)` or `recoverAddOwner(...)`

`script/encode-recovery-event.sh`

- requires `RECOVERY_SESSION_HASH`
- requires `NONCE`
- requires `OWNER`
- requires `NEAR_ACCOUNT_ID_HASH`
- requires `NEW_NEAR_KEY_HASH`
- requires `AUTHORITY`
- outputs the expected topics/data encoding for `RecoveryOwnerAdded(...)`
