import { expect, test } from '@playwright/test';
import { mintRouterAbEd25519YaoWalletSessionV1 } from '../../packages/wallet-server/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration';
import type {
  RouterAbEd25519YaoWalletSessionCredentialV1,
  RouterAbEd25519YaoWalletSessionMintInputV1,
} from '../../packages/wallet-server/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration';
import { parseWalletSessionOperationCredentialV1 } from '../../packages/shared-ts/src/device-linking';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  parseThresholdEd25519SessionId,
  parseWalletAuthMethodId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/encoders';

const SIGNING_WORKER_ID = 'signing-worker:ed25519-yao-projection';
const WALLET_SESSION_ID = 'wallet-session:projection';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function issuedCredentialFor(
  walletSessionId: string,
): Extract<
  RouterAbEd25519YaoWalletSessionCredentialV1,
  { readonly kind: 'issued_wallet_session_v1' }
> {
  return {
    kind: 'issued_wallet_session_v1',
    operationCredential: parseWalletSessionOperationCredentialV1({
      kind: 'opaque_wallet_session_operation_credential_v1',
      token: `wst_${'A'.repeat(43)}`,
      walletSessionId,
    }),
  };
}

function unlockMintInput(
  walletSessionCredential: RouterAbEd25519YaoWalletSessionCredentialV1,
  overrides: { readonly walletSessionId?: string } = {},
): RouterAbEd25519YaoWalletSessionMintInputV1 {
  return {
    kind: 'verified_wallet_unlock_v1',
    walletSessionCredential,
    walletId: walletIdFromString('projection-wallet.testnet'),
    nearAccountId: 'projection-wallet.testnet',
    nearEd25519SigningKeyId: 'near-ed25519-key-projection',
    authority: {
      walletId: walletIdFromString('projection-wallet.testnet'),
      factor: {
        kind: 'passkey',
        credentialIdB64u: required(parseWebAuthnCredentialIdB64u('projection-credential')),
      },
      verifier: {
        kind: 'webauthn',
        rpId: required(parseWebAuthnRpId('example.com')),
      },
      bindingId: required(parseWalletAuthMethodId('wallet-auth-method:projection')),
    },
    thresholdSessionId: required(parseThresholdEd25519SessionId('threshold-session:projection')),
    authorizationId: required(parseWalletSessionAuthorizationId('wallet-authorization:projection')),
    walletSessionId: required(parseWalletSessionId(overrides.walletSessionId ?? WALLET_SESSION_ID)),
    quotaId: required(parseMpcWalletSigningQuotaId('wallet-quota:projection')),
    participantIds: [1, 2],
    runtimePolicyScope: {
      orgId: 'org-projection',
      projectId: 'project-projection',
      envId: 'env-projection',
      signingRootVersion: 'root-v1',
    },
    keyManifestDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(5))),
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 3,
  };
}

test('an issued Ed25519 Yao Wallet Session carries the credential that admits it', async () => {
  const session = await mintRouterAbEd25519YaoWalletSessionV1({
    signingWorkerId: SIGNING_WORKER_ID,
    sessionInput: unlockMintInput(issuedCredentialFor(WALLET_SESSION_ID)),
  });

  expect(session.sessionKind).toBe('issued_wallet_session_v1');
  if (session.sessionKind !== 'issued_wallet_session_v1') {
    throw new Error('issued mint input must project an issued session');
  }
  expect(session.operationCredential.walletSessionId).toBe(session.walletSessionId);
  expect(session.operationCredential.token).toMatch(/^wst_[A-Za-z0-9_-]{43}$/);
  expect(session).not.toHaveProperty('walletSessionToken');
});

test('a reused Ed25519 Yao Wallet Session projects no credential of its own', async () => {
  const session = await mintRouterAbEd25519YaoWalletSessionV1({
    signingWorkerId: SIGNING_WORKER_ID,
    sessionInput: unlockMintInput({ kind: 'reused_wallet_session_v2' }),
  });

  expect(session.sessionKind).toBe('reused_wallet_session_v2');
  /* The credential for a reused session was delivered once by the response
     that issued it; a committed digest cannot reproduce plaintext, so this
     projection must not invent a replacement. */
  expect(session.operationCredential).toBeUndefined();
  expect(session).not.toHaveProperty('walletSessionToken');
});

test('an Ed25519 Yao Wallet Session refuses a credential for another session', async () => {
  await expect(
    mintRouterAbEd25519YaoWalletSessionV1({
      signingWorkerId: SIGNING_WORKER_ID,
      sessionInput: unlockMintInput(issuedCredentialFor('wallet-session:other'), {
        walletSessionId: WALLET_SESSION_ID,
      }),
    }),
  ).rejects.toThrow('Ed25519 Yao Wallet Session credential does not identify its session');
});
