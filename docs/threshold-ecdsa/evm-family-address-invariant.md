# EVM-Family ECDSA Address Invariant

Last updated: 2026-05-16

## Funds-Safety Rule

All EVM-class threshold ECDSA signers for the same wallet, RP, signing root,
and key version MUST share the same Ethereum address.

This includes Tempo, Arc, Ethereum, and every future EVM-family chain target.
Users and integrators may fund one displayed EVM signer address and expect that
same address to be the sender on every EVM-class target.

The displayed funding address is the threshold ECDSA owner address. Chain
account wrapper addresses must not be substituted for this value in signer
funding UI.

Raw EIP-1559 signing must resolve sender, nonce, balance preflight, and funding
UI from the threshold owner address. Consumer code must name which address role
it is using.

Public ECDSA operations identify the signer with `walletSession` and a concrete
`chainTarget`. Callers never provide `ecdsaThresholdKeyId`,
`participantIds`, threshold session IDs, or client root shares on the public
bootstrap/sign/export request surface.

## Required Shape

Persistent key identity is EVM-family scoped:

```text
walletSessionUserId
+ rpId
+ signingRootId
+ signingRootVersion
+ keyPurpose
+ keyVersion
+ keyScope = "evm-family"
=> one ecdsaThresholdKeyId
=> one threshold ECDSA public key
=> one Ethereum owner address
```

Concrete `chainTarget` values are allowed to partition:

- session policy and threshold-session auth claims
- wallet signing-session budgets
- runtime lane records
- sealed recovery records
- nonce lanes and broadcast/finalization state
- transaction serialization and signing requests

Concrete `chainTarget` values must never partition persistent ECDSA key
material, `ecdsaThresholdKeyId`, or the displayed signer address.

## Failure Policy

Any path that observes different owner addresses for EVM-family targets under
the same wallet, RP, signing root, and key version must fail closed
before displaying a funding address or signing a transaction.

Any code that reintroduces concrete chain target into ECDSA HSS stable-key
derivation is a critical funds-safety regression.

## Regression Coverage

Required coverage:

- Tempo + EVM registration provisions one shared `ecdsaThresholdKeyId`.
- Tempo + EVM registration returns one shared owner address.
- Tempo and EVM public bootstrap reuse the same warm EVM-family key identity
  without accepting caller-supplied `ecdsaThresholdKeyId` or `participantIds`.
- ECDSA HSS output remains unchanged when only the concrete EVM-family
  `chainTarget` changes.
- ECDSA HSS output changes when `ecdsaThresholdKeyId`, signing root, key
  purpose, or key version changes.
- Raw EIP-1559 nonce preparation fails closed if restored threshold ECDSA
  material is missing the owner address.
- Sealed ECDSA recovery records carry the owner `ethereumAddress` so restored
  lanes cannot fall back to an account-row sender.
