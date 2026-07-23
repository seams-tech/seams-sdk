import { expect, test } from '@playwright/test';
import {
  buildCurrentSealedSessionRecord,
  type CurrentEd25519SealedSessionRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore';
import { resolvePasskeyEd25519YaoExportContextWithRuntimeV1 } from '../../packages/sdk-web/src/core/signingEngine/session/passkey/ed25519YaoWarmRecovery';

const NOW_MS = 1_900_000_000_000;
const WALLET_ID = 'wallet-expiry-boundary';
const NEAR_ACCOUNT_ID = 'wallet-expiry-boundary.testnet';
const THRESHOLD_SESSION_ID = 'threshold-session-expiry-boundary';
const SIGNING_GRANT_ID = 'signing-grant-expiry-boundary';
const SIGNING_WORKER_ID = 'signing-worker-expiry-boundary';
const RELAYER_URL = 'https://relay.example.test';

function buildSealedRecord(input: {
  readonly expiresAtMs: number;
  readonly remainingUses: number;
}): CurrentEd25519SealedSessionRecord {
  const record = buildCurrentSealedSessionRecord({
    curve: 'ed25519',
    authMethod: 'passkey',
    thresholdSessionId: THRESHOLD_SESSION_ID,
    thresholdSessionIds: { ed25519: THRESHOLD_SESSION_ID },
    signingGrantId: SIGNING_GRANT_ID,
    walletId: WALLET_ID,
    signingRootId: 'project-expiry-boundary:test',
    signingRootVersion: 'root-v1',
    relayerUrl: RELAYER_URL,
    sealedSecretB64u: 'sealed-secret-expiry-boundary',
    keyVersion: 'v1',
    shamirPrimeB64u: 'shamir-prime-expiry-boundary',
    issuedAtMs: NOW_MS - 1_000,
    expiresAtMs: input.expiresAtMs,
    remainingUses: input.remainingUses,
    updatedAtMs: NOW_MS,
    ed25519Restore: {
      sessionKind: 'jwt',
      walletSessionJwt: 'header.payload.signature',
      nearAccountId: NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: 'ed25519-key-expiry-boundary',
      rpId: 'wallet.example.test',
      credentialIdB64u: 'credential-expiry-boundary',
      relayerKeyId: SIGNING_WORKER_ID,
      participantIds: [1, 2],
      runtimePolicyScope: {
        orgId: 'org-expiry-boundary',
        projectId: 'project-expiry-boundary',
        envId: 'test',
        signingRootVersion: 'root-v1',
      },
      signerSlot: 1,
      routerAbNormalSigning: {
        kind: 'router_ab_ed25519_normal_signing_v1',
        signingWorkerId: SIGNING_WORKER_ID,
      },
    },
  });
  if (!record || record.curve !== 'ed25519') {
    throw new Error('failed to build passkey Ed25519 expiry fixture');
  }
  return record;
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
