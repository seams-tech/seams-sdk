import { expect, test } from '@playwright/test';
import type { CurrentEd25519SealedSessionRecord } from '../../packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore';
import {
  requirePasskeyEd25519RestoreAuthorization,
  resolvePasskeyEd25519YaoExportContextWithRuntimeV1,
} from '../../packages/sdk-web/src/core/signingEngine/session/passkey/ed25519YaoWarmRecovery';
import {
  buildPasskeyEd25519AuthorizationProjectionFixture,
  buildPasskeyEd25519SealedSessionRecordFixture,
} from './helpers/sealedSigningSession.fixtures';

const NOW_MS = 1_900_000_000_000;
const WALLET_ID = 'wallet-expiry-boundary';
const NEAR_ACCOUNT_ID = 'wallet-expiry-boundary.testnet';
const THRESHOLD_SESSION_ID = 'threshold-session-expiry-boundary';
const RELAYER_URL = 'https://relay.example.test';

function buildSealedRecord(input: {
  readonly expiresAtMs: number;
  readonly remainingUses: number;
}): CurrentEd25519SealedSessionRecord {
  return buildPasskeyEd25519SealedSessionRecordFixture({
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    thresholdSessionId: THRESHOLD_SESSION_ID,
    expiresAtMs: input.expiresAtMs,
    remainingUses: input.remainingUses,
  });
}

async function unexpectedAuthorizationRead(): Promise<never> {
  throw new Error('expired or exhausted material must not read Wallet Session authorization');
}

async function resolveRecord(record: CurrentEd25519SealedSessionRecord) {
  let recoveryBootstrapCalls = 0;
  const result = await resolvePasskeyEd25519YaoExportContextWithRuntimeV1(
    {
      subject: {
        walletId: WALLET_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        signerSlot: 1,
        thresholdSessionId: THRESHOLD_SESSION_ID,
      },
      relayerUrl: RELAYER_URL,
      fetch: async () => {
        recoveryBootstrapCalls += 1;
        throw new Error('expired or exhausted material must not invoke Yao recovery');
      },
    },
    {
      listExactSealedSessionsForWallet: async () => [record],
      readActiveWalletSessionAuthorization: unexpectedAuthorizationRead,
      nowMs: () => NOW_MS,
    },
  );
  return { result, recoveryBootstrapCalls };
}

test('expired passkey material does not enter Yao recovery even when its budget is empty', async () => {
  const resolved = await resolveRecord(
    buildSealedRecord({ expiresAtMs: NOW_MS, remainingUses: 0 }),
  );

  expect(resolved.result).toEqual({
    kind: 'capability_recovery_required',
    reason: 'sealed_session_expired',
  });
  expect(resolved.recoveryBootstrapCalls).toBe(0);
});

test('unexpired passkey material with no uses remains distinct from expiry', async () => {
  const resolved = await resolveRecord(
    buildSealedRecord({ expiresAtMs: NOW_MS + 60_000, remainingUses: 0 }),
  );

  expect(resolved.result).toEqual({
    kind: 'capability_recovery_required',
    reason: 'sealed_session_exhausted',
  });
  expect(resolved.recoveryBootstrapCalls).toBe(0);
});

test('passkey sealed restore uses the current active authorization bearer', async () => {
  const record = buildSealedRecord({ expiresAtMs: NOW_MS + 60_000, remainingUses: 1 });
  const authorization = buildPasskeyEd25519AuthorizationProjectionFixture(record);
  const currentJwt = authorization.walletSessionJwt;

  const resolved = await requirePasskeyEd25519RestoreAuthorization({
    record,
    authorizationRead: { kind: 'found', projection: authorization },
    nowMs: NOW_MS,
  });

  expect(record).not.toHaveProperty('walletSessionJwt');
  expect(record.ed25519Restore).not.toHaveProperty('walletSessionJwt');
  expect(resolved?.walletSessionJwt).toBe(currentJwt);
});
