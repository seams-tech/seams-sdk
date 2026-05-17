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
import { useState } from 'react';
import { useSeams } from '@seams/sdk/react';

export function RegisterAndProvision() {
  const { registerPasskey, seams } = useSeams();
  const [accountId, setAccountId] = useState<string | null>(null);

  async function onRegister(): Promise<void> {
    const id = Date.now();
    const nextAccountId = `seams-test-${id}.${seams.configs.relayerAccount}`;

    const result = await registerPasskey(nextAccountId, {
      onEvent: (event) => console.log('registration event:', event),
    });
    if (!result.success || !result.nearAccountId) return;

    setAccountId(result.nearAccountId);
  }

  return (
    <div>
      <button onClick={onRegister}>Register Account</button>
      {accountId ? <p>account: {accountId}</p> : null}
      <p>tempo+evm signer session: bootstrap if missing</p>
    </div>
  );
}
```

Optional override:

```tsx
await registerPasskey(nextAccountId, {
  signerOptions: {
    tempo: {
      enabled: true,
      signingSession: { kind: 'jwt', ttlMs: 30 * 60 * 1000, remainingUses: 12 },
    },
    evm: {
      enabled: true,
      signingSession: { kind: 'jwt', ttlMs: 30 * 60 * 1000, remainingUses: 12 },
    },
  },
});
// disable per signer by setting `enabled: false` on tempo/evm
```

## 2. Unlock and Create a Warm Signing Session

```tsx
import { useSeams } from '@seams/sdk/react';

export function LoginButton(props: { nearAccountId: string }) {
  const { seams } = useSeams();

  async function onLogin(): Promise<void> {
    await seams.auth.unlock(props.nearAccountId, {
      signingSession: {
        ttlMs: 5 * 60 * 1000,
        remainingUses: 5,
      },
    });
  }

  return <button onClick={onLogin}>Unlock</button>;
}
```

## 3. ECDSA Command Subject Helpers

Tempo and EVM-family calls use a wallet-session command subject plus a concrete
chain target.

```ts
import {
  walletSessionRefFromSession,
  walletSubjectIdFromWalletProfile,
  type ThresholdEcdsaChainTarget,
} from '@seams/sdk';

export function ecdsaCommandSubject(accountId: string) {
  return {
    walletSession: walletSessionRefFromSession({
      walletId: accountId,
      walletSessionUserId: accountId,
    }),
    subjectId: walletSubjectIdFromWalletProfile({ walletId: accountId }),
  };
}

export const TEMPO_CHAIN_TARGET = {
  kind: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
} satisfies ThresholdEcdsaChainTarget;

export const ETHEREUM_SEPOLIA_CHAIN_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 11155111,
  networkSlug: 'ethereum-sepolia',
} satisfies ThresholdEcdsaChainTarget;
```

## 4. Bootstrap Tempo/EVM Threshold Session (if needed)

```tsx
import { useSeams } from '@seams/sdk/react';

export function BootstrapTempoEvmSession(props: { nearAccountId: string }) {
  const { seams } = useSeams();

  async function onBootstrap(): Promise<void> {
    await seams.tempo.bootstrapEcdsaSession({
      kind: 'reuse_warm_ecdsa_bootstrap',
      ...ecdsaCommandSubject(props.nearAccountId),
      chainTarget: TEMPO_CHAIN_TARGET,
    });

    await seams.evm.bootstrapEcdsaSession({
      kind: 'reuse_warm_ecdsa_bootstrap',
      ...ecdsaCommandSubject(props.nearAccountId),
      chainTarget: ETHEREUM_SEPOLIA_CHAIN_TARGET,
    });
  }

  return <button onClick={onBootstrap}>Bootstrap Tempo/EVM Session</button>;
}
```

## 5. Sign a NEAR Transaction (Threshold Ed25519)

```tsx
import { ActionType, useSeams } from '@seams/sdk/react';

export function SignNear(props: { nearAccountId: string }) {
  const { seams } = useSeams();

  async function onSignNear(): Promise<void> {
    const signed = await seams.near.signTransactionsWithActions({
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
    });
    console.log('near signed tx:', signed);
  }

  return <button onClick={onSignNear}>Sign NEAR Tx</button>;
}
```

## 6. Sign a Tempo Transaction (Threshold secp256k1)

Nonce management is engine-owned for default Tempo/EVM signing flows. Do not fetch nonces in app code.

```tsx
import { useSeams } from '@seams/sdk/react';

const TEMPO_GREETING_CONTRACT = '0xBB442B54c85efBa2D7B81eA52990ad638cDbA483';
const SET_GREETING_SELECTOR = '0xa4136862';

function utf8ToHex(value: string): string {
  return Array.from(new TextEncoder().encode(value), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
}

function encodeSetGreetingInput(greeting: string): `0x${string}` {
  const messageHex = utf8ToHex(greeting);
  const bytesLength = messageHex.length / 2;
  const offsetHex = (32).toString(16).padStart(64, '0');
  const lengthHex = bytesLength.toString(16).padStart(64, '0');
  const paddedDataHex = messageHex.padEnd(Math.ceil(bytesLength / 32) * 64, '0');
  return `0x${SET_GREETING_SELECTOR.slice(2)}${offsetHex}${lengthHex}${paddedDataHex}`;
}

export function SignTempo(props: { nearAccountId: string }) {
  const { seams } = useSeams();

  async function onSignTempo(): Promise<void> {
    const setGreetingInput = encodeSetGreetingInput('hello from tempo');

    const signed = await seams.tempo.signTempo({
      ...ecdsaCommandSubject(props.nearAccountId),
      chainTarget: TEMPO_CHAIN_TARGET,
      request: {
        chain: 'tempo',
        kind: 'tempoTransaction',
        senderSignatureAlgorithm: 'secp256k1',
        tx: {
          chainId: 42431,
          maxPriorityFeePerGas: 1n,
          maxFeePerGas: 2n,
          gasLimit: 200_000n,
          calls: [{ to: TEMPO_GREETING_CONTRACT, value: 0n, input: setGreetingInput }],
          accessList: [],
          nonceKey: 0n,
          validBefore: null,
          validAfter: null,
          feePayerSignature: { kind: 'none' },
          aaAuthorizationList: [],
        },
      },
    });
    console.log('tempo signed tx:', signed);
  }

  return <button onClick={onSignTempo}>Sign Tempo Tx</button>;
}
```

### Configure Tempo Preferred Fee Token

Tempo fee token preference is configured by calling `setUserToken(address token)` on the
Fee Manager predeploy (`0xfeec000000000000000000000000000000000000`).

```tsx
import { useSeams } from '@seams/sdk/react';
import { buildTempoSetUserTokenCall, TEMPO_FEE_MANAGER_CONTRACT } from '@seams/sdk';

const ALPHA_USD_TOKEN = '0x20c0000000000000000000000000000000000001' as const;

export function SetTempoFeeToken(props: { nearAccountId: string }) {
  const { seams } = useSeams();

  async function onSetTempoFeeToken(): Promise<void> {
    const setUserTokenCall = buildTempoSetUserTokenCall({
      token: ALPHA_USD_TOKEN,
      feeManager: TEMPO_FEE_MANAGER_CONTRACT,
    });

    const signed = await seams.tempo.signTempo({
      ...ecdsaCommandSubject(props.nearAccountId),
      chainTarget: TEMPO_CHAIN_TARGET,
      request: {
        chain: 'evm',
        kind: 'eip1559',
        senderSignatureAlgorithm: 'secp256k1',
        tx: {
          chainId: 42431,
          maxPriorityFeePerGas: 1n,
          maxFeePerGas: 2n,
          gasLimit: 1_000_000n,
          to: setUserTokenCall.to,
          value: 0n,
          data: setUserTokenCall.input || '0x',
          abi: setUserTokenCall.abi,
          accessList: [],
        },
      },
    });

    console.log('tempo setUserToken signed tx:', signed);
  }

  return <button onClick={onSetTempoFeeToken}>Set Tempo Fee Token</button>;
}
```

## 7. Sign an EVM EIP-1559 Transaction (Threshold secp256k1)

For standard flows, nonce reservation is handled by the signing engine. Manual nonce injection is advanced-only.
This example uses Ethereum Sepolia to make the EVM family/network split explicit.

```tsx
import { useSeams } from '@seams/sdk/react';

const ETHEREUM_SEPOLIA_RECIPIENT = '0x000000000000000000000000000000000000dEaD';

export function SignEvm(props: { nearAccountId: string }) {
  const { seams } = useSeams();

  async function onSignEvm(): Promise<void> {
    const signed = await seams.tempo.signTempo({
      ...ecdsaCommandSubject(props.nearAccountId),
      chainTarget: ETHEREUM_SEPOLIA_CHAIN_TARGET,
      request: {
        chain: 'evm',
        kind: 'eip1559',
        senderSignatureAlgorithm: 'secp256k1',
        tx: {
          chainId: 11155111,
          maxPriorityFeePerGas: 2_000_000_000n,
          maxFeePerGas: 25_000_000_000n,
          gasLimit: 21_000n,
          to: ETHEREUM_SEPOLIA_RECIPIENT,
          value: 1n,
          data: '0x',
          accessList: [],
        },
      },
    });
    console.log('evm signed tx:', signed);
  }

  return <button onClick={onSignEvm}>Sign EVM Tx</button>;
}
```

## Recap

- Registration creates your NEAR threshold signer.
- Unlock creates a warm signing session.
- Tempo + EVM threshold sessions come from registration/bootstrap and are reused until expiry/exhaustion.
- With an active warm session, you can sign:
  - NEAR transactions (`signTransactionsWithActions`)
  - Tempo transactions (`signTempo`, `kind: 'tempoTransaction'`)
  - EVM EIP-1559 transactions (`signTempo`, `kind: 'eip1559'`)

## Troubleshooting

- `threshold session expired` or `No cached threshold-ecdsa session token`
  - Re-bootstrap the chain signer with `kind: 'reuse_warm_ecdsa_bootstrap'`, `walletSession`, `subjectId`, and the concrete `chainTarget`, then retry signing.
- Missing Tempo/EVM session after reload
  - Re-bootstrap the matching `seams.tempo` or `seams.evm` signer before signing.
- Signing fails right after unlock due to session state
  - Run `seams.auth.unlock()` first for warm session state, then bootstrap the missing ECDSA chain target.
- Repeated failures on one chain only
  - Bootstrap that concrete `chainTarget` again to refresh the threshold session lane.

## Next Steps

- [React Recipes](/getting-started/react-recipes): patterns for auth, sessions, and account UX.
- [Other Frameworks](./other-frameworks.md): Next.js, Vue, Svelte, Express.
- [Concepts](../concepts/index.md): security model, threshold signing, architecture.
