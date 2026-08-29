import { expect, test } from '@playwright/test';
import { mintRouterAbEd25519YaoWalletSessionV1 } from '../../packages/wallet-server/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration';
import {
  buildIssuedRouterAbEd25519YaoWalletSessionCredentialFixture,
  buildRouterAbEd25519YaoWalletSessionMintInputFixture,
  ROUTER_AB_ED25519_YAO_WALLET_SESSION_FIXTURE_ID,
} from './helpers/routerAbEd25519YaoWalletSession.fixtures';

const SIGNING_WORKER_ID = 'signing-worker:ed25519-yao-projection';

test('an issued Ed25519 Yao Wallet Session carries the credential that admits it', async () => {
  const session = await mintRouterAbEd25519YaoWalletSessionV1({
    signingWorkerId: SIGNING_WORKER_ID,
    sessionInput: buildRouterAbEd25519YaoWalletSessionMintInputFixture({
      walletSessionCredential: buildIssuedRouterAbEd25519YaoWalletSessionCredentialFixture(),
    }),
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
    sessionInput: buildRouterAbEd25519YaoWalletSessionMintInputFixture({
      walletSessionCredential: { kind: 'reused_wallet_session_v2' },
    }),
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
      sessionInput: buildRouterAbEd25519YaoWalletSessionMintInputFixture({
        walletSessionCredential:
          buildIssuedRouterAbEd25519YaoWalletSessionCredentialFixture('wallet-session:other'),
        walletSessionId: ROUTER_AB_ED25519_YAO_WALLET_SESSION_FIXTURE_ID,
      }),
    }),
  ).rejects.toThrow('Ed25519 Yao Wallet Session credential does not identify its session');
});
