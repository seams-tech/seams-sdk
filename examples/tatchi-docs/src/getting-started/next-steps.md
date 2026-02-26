---
title: Next Steps
---

# Next Steps: Register and Sign NEAR/Tempo/EVM

After [installation](./installation.md), the fastest path is:

1. Register a passkey account.
2. Log in, then ensure threshold sessions are active.
3. Sign one transaction per chain (NEAR, Tempo, EVM).
4. Reuse warm threshold sessions for follow-up signatures.

## 1. Register and Prepare Threshold Signers

In this setup:

- NEAR threshold signer is created during registration (`signerMode: threshold-signer`).
- Tempo + EVM threshold sessions are explicit (`registerPasskey` provisioning or `bootstrapEcdsaSession`).

```tsx
import { useState } from 'react'
import { useTatchi } from '@tatchi-xyz/sdk/react'

export function RegisterAndProvision() {
  const { registerPasskey, tatchi } = useTatchi()
  const [accountId, setAccountId] = useState<string | null>(null)

  async function onRegister(): Promise<void> {
    const id = Date.now()
    const nextAccountId = `tatchi-test-${id}.${tatchi.configs.relayerAccount}`

    const result = await registerPasskey(nextAccountId, {
      onEvent: (event) => console.log('registration event:', event),
    })
    if (!result.success || !result.nearAccountId) return

    setAccountId(result.nearAccountId)
  }

  return (
    <div>
      <button onClick={onRegister}>Register Account</button>
      {accountId ? <p>account: {accountId}</p> : null}
      <p>tempo+evm signer session: bootstrap if missing</p>
    </div>
  )
}
```

Optional override:

```tsx
await registerPasskey(nextAccountId, {
  signerOptions: {
    tempo: {
      enabled: true,
      participantIds: [1, 2],
      sessionKind: 'jwt',
      ttlMs: 30 * 60 * 1000,
      remainingUses: 12,
    },
    evm: {
      enabled: true,
      participantIds: [1, 2],
      sessionKind: 'jwt',
      ttlMs: 30 * 60 * 1000,
      remainingUses: 12,
    },
  },
})
// disable per signer by setting `enabled: false` on tempo/evm
```

## 2. Login and Create a Warm Signing Session

```tsx
import { useTatchi } from '@tatchi-xyz/sdk/react'

export function LoginButton(props: { nearAccountId: string }) {
  const { loginAndCreateSession } = useTatchi()

  async function onLogin(): Promise<void> {
    await loginAndCreateSession(props.nearAccountId, {
      signingSession: {
        ttlMs: 5 * 60 * 1000,
        remainingUses: 5,
      },
    })
  }

  return <button onClick={onLogin}>Log In</button>
}
```

## 3. Bootstrap Tempo/EVM Threshold Session (if needed)

```tsx
import { useTatchi } from '@tatchi-xyz/sdk/react'

export function BootstrapTempoEvmSession(props: { nearAccountId: string }) {
  const { tatchi } = useTatchi()

  async function onBootstrap(): Promise<void> {
    await tatchi.tempo.bootstrapEcdsaSession({
      nearAccountId: props.nearAccountId,
      options: { chain: 'tempo' },
    })
  }

  return <button onClick={onBootstrap}>Bootstrap Tempo/EVM Session</button>
}
```

## 4. Sign a NEAR Transaction (Threshold Ed25519)

```tsx
import { ActionType, useTatchi } from '@tatchi-xyz/sdk/react'

export function SignNear(props: { nearAccountId: string }) {
  const { tatchi } = useTatchi()

  async function onSignNear(): Promise<void> {
    const signed = await tatchi.near.signTransactionsWithActions({
      nearAccountId: props.nearAccountId,
      transactions: [
        {
          receiverId: 'guest-book.testnet',
          actions: [
            {
              type: ActionType.FunctionCall,
              methodName: 'set_greeting',
              args: { greeting: 'hello from threshold near' },
              gas: '30000000000000',
              deposit: '0',
            },
          ],
        },
      ],
    })
    console.log('near signed tx:', signed)
  }

  return <button onClick={onSignNear}>Sign NEAR Tx</button>
}
```

## 5. Sign a Tempo Transaction (Threshold secp256k1)

```tsx
import { useTatchi } from '@tatchi-xyz/sdk/react'

const TEMPO_GREETING_CONTRACT = '0x96cFE92241481954AdA6410409a86AcB6E76a00e'
const SET_GREETING_SELECTOR = '0xa4136862'

function utf8ToHex(value: string): string {
  return Array.from(new TextEncoder().encode(value), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('')
}

function encodeSetGreetingInput(greeting: string): `0x${string}` {
  const messageHex = utf8ToHex(greeting)
  const bytesLength = messageHex.length / 2
  const offsetHex = (32).toString(16).padStart(64, '0')
  const lengthHex = bytesLength.toString(16).padStart(64, '0')
  const paddedDataHex = messageHex.padEnd(Math.ceil(bytesLength / 32) * 64, '0')
  return `0x${SET_GREETING_SELECTOR.slice(2)}${offsetHex}${lengthHex}${paddedDataHex}`
}

export function SignTempo(props: { nearAccountId: string }) {
  const { tatchi } = useTatchi()

  async function onSignTempo(): Promise<void> {
    const setGreetingInput = encodeSetGreetingInput('hello from tempo')

    const signed = await tatchi.tempo.signTempo({
      nearAccountId: props.nearAccountId,
      request: {
        chain: 'tempo',
        kind: 'tempoTransaction',
        senderSignatureAlgorithm: 'secp256k1',
        tx: {
          chainId: 42431n,
          maxPriorityFeePerGas: 1n,
          maxFeePerGas: 2n,
          gasLimit: 200_000n,
          calls: [{ to: TEMPO_GREETING_CONTRACT, value: 0n, input: setGreetingInput }],
          accessList: [],
          nonceKey: 0n,
          nonce: 1n,
          validBefore: null,
          validAfter: null,
          feePayerSignature: { kind: 'none' },
          aaAuthorizationList: [],
        },
      },
    })
    console.log('tempo signed tx:', signed)
  }

  return <button onClick={onSignTempo}>Sign Tempo Tx</button>
}
```

## 6. Sign an EVM EIP-1559 Transaction (Threshold secp256k1)

```tsx
import { useTatchi } from '@tatchi-xyz/sdk/react'

const ARC_TESTNET_GREETING_CONTRACT = '0xeB7aB5A6F761072C96147A54B8a15F012e836691'
const SET_GREETING_SELECTOR = '0xa4136862'

function utf8ToHex(value: string): string {
  return Array.from(new TextEncoder().encode(value), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('')
}

function encodeSetGreetingInput(greeting: string): `0x${string}` {
  const messageHex = utf8ToHex(greeting)
  const bytesLength = messageHex.length / 2
  const offsetHex = (32).toString(16).padStart(64, '0')
  const lengthHex = bytesLength.toString(16).padStart(64, '0')
  const paddedDataHex = messageHex.padEnd(Math.ceil(bytesLength / 32) * 64, '0')
  return `0x${SET_GREETING_SELECTOR.slice(2)}${offsetHex}${lengthHex}${paddedDataHex}`
}

export function SignEvm(props: { nearAccountId: string }) {
  const { tatchi } = useTatchi()

  async function onSignEvm(): Promise<void> {
    const setGreetingData = encodeSetGreetingInput('hello from arc')

    const signed = await tatchi.tempo.signTempo({
      nearAccountId: props.nearAccountId,
      request: {
        chain: 'evm',
        kind: 'eip1559',
        senderSignatureAlgorithm: 'secp256k1',
        tx: {
          chainId: 5042002n,
          nonce: 7n,
          maxPriorityFeePerGas: 1_500_000_000n,
          maxFeePerGas: 3_000_000_000n,
          gasLimit: 200_000n,
          to: ARC_TESTNET_GREETING_CONTRACT,
          value: 0n,
          data: setGreetingData,
          accessList: [],
        },
      },
    })
    console.log('evm signed tx:', signed)
  }

  return <button onClick={onSignEvm}>Sign EVM Tx</button>
}
```

## Recap

- Registration creates your NEAR threshold signer.
- Login creates a warm signing session.
- Tempo + EVM threshold sessions come from registration/bootstrap and are reused until expiry/exhaustion.
- With an active warm session, you can sign:
  - NEAR transactions (`signTransactionsWithActions`)
  - Tempo transactions (`signTempo`, `kind: 'tempoTransaction'`)
  - EVM EIP-1559 transactions (`signTempo`, `kind: 'eip1559'`)

## Troubleshooting

- `threshold session expired` or `No cached threshold-ecdsa session token`
  - Re-bootstrap the chain signer with `bootstrapEcdsaSession({ chain: 'tempo' | 'evm' })`, then retry signing.
- Missing Tempo/EVM session after reload
  - Re-bootstrap with `bootstrapEcdsaSession()` before signing.
- Signing fails right after login due to session state
  - Run `loginAndCreateSession()` first for warm session state, then `bootstrapEcdsaSession()` if ECDSA session state is missing.
- Repeated failures on one chain only
  - Re-provision only that chain (`chain: 'tempo'` or `chain: 'evm'`) to refresh the threshold session/keyRef pair.

## Next Steps

- [React Recipes](/getting-started/react-recipes): patterns for auth, sessions, and account UX.
- [Other Frameworks](./other-frameworks.md): Next.js, Vue, Svelte, Express.
- [Concepts](../concepts/index.md): security model, threshold signing, architecture.
