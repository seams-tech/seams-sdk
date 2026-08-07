import { expect, test } from '@playwright/test';
import type { CurrentEd25519SealedSessionRecord } from '../../packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore';
import {
  requirePasskeyEd25519RestoreAuthorization,
  resolvePasskeyEd25519YaoExportContextWithRuntimeV1,
} from '../../packages/sdk-web/src/core/signingEngine/session/passkey/ed25519YaoWarmRecovery';
import {
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  buildPasskeyEd25519AuthorizationProjectionFixture,
  buildPasskeyEd25519SealedSessionRecordFixture,
} from './helpers/sealedSigningSession.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

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
        materialActivation: record.ed25519Restore.materialActivation,
      },
      relayerUrl: RELAYER_URL,
      fetch: async () => {
        recoveryBootstrapCalls += 1;
        throw new Error('expired or exhausted material must not invoke Yao recovery');
      },
    },
    {
      readExactEd25519SealedSession: async () => record,
      readActiveWalletSessionAuthorization: unexpectedAuthorizationRead,
      nowMs: () => NOW_MS,
    },
  );
  return { result, recoveryBootstrapCalls };
}

async function warmBootstrapResponse(args: {
  readonly record: CurrentEd25519SealedSessionRecord;
  readonly authorization: ReturnType<typeof buildPasskeyEd25519AuthorizationProjectionFixture>;
  readonly capabilityThresholdSessionId: string;
  readonly capabilityAccountId?: string;
  readonly materialActivation?: MpcMaterialActivationRef;
  readonly responseThresholdSessionId?: string;
}): Promise<Record<string, unknown>> {
  const restore = args.record.ed25519Restore;
  const authority = buildPasskeyWalletAuthAuthority({
    walletId: args.record.walletId,
    rpId: restore.rpId,
    credentialIdB64u: restore.credentialIdB64u,
  });
  return {
    kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_v1',
    walletId: args.record.walletId,
    nearAccountId: restore.nearAccountId,
    nearEd25519SigningKeyId: restore.nearEd25519SigningKeyId,
    signerSlot: restore.signerSlot,
    thresholdSessionId: args.responseThresholdSessionId ?? args.record.thresholdSessionIds.ed25519,
    walletSessionId: String(args.authorization.walletSessionId),
    quotaId: String(args.authorization.quotaId),
    signingWorkerId: restore.relayerKeyId,
    thresholdExpiresAtMs: args.authorization.expiresAtMs,
    participantIds: [...restore.participantIds],
    authority,
    authorityRef: await walletAuthAuthorityRef({ authority }),
    authorityScope: { kind: 'passkey_rp', rpId: restore.rpId },
    runtimePolicyScope: restore.runtimePolicyScope,
    routerAbNormalSigning: restore.routerAbNormalSigning,
    capability: {
      kind: 'router_ab_ed25519_yao_active_capability_v1',
      materialActivation: routerAbMpcMaterialActivationRefToWire(
        args.materialActivation ?? restore.materialActivation,
      ),
      activeCapabilityBinding: new Array<number>(32).fill(7),
      registeredPublicKey: new Array<number>(32).fill(9),
      nearAccountId: restore.nearAccountId,
      applicationBinding: {
        wallet_id: args.record.walletId,
        near_ed25519_signing_key_id: restore.nearEd25519SigningKeyId,
        signing_root_id: `${restore.runtimePolicyScope.projectId}:${restore.runtimePolicyScope.envId}`,
        key_creation_signer_slot: restore.signerSlot,
      },
      participantIds: [...restore.participantIds],
      runtimePolicyScope: restore.runtimePolicyScope,
      lifecycle: {
        lifecycleId: 'warm-capability-lifecycle',
        rootShareEpoch: restore.runtimePolicyScope.signingRootVersion,
        accountId: args.capabilityAccountId ?? args.record.walletId,
        thresholdSessionId: args.capabilityThresholdSessionId,
        signerSetId: 'near-primary',
        signingWorkerId: restore.relayerKeyId,
      },
      stateEpoch: 1,
    },
  };
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

test('warm recovery accepts a renewed Wallet Session threshold for unchanged material', async () => {
  const record = buildPasskeyEd25519SealedSessionRecordFixture({
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    thresholdSessionId: THRESHOLD_SESSION_ID,
    expiresAtMs: NOW_MS + 60_000,
    remainingUses: 1,
  });
  const renewedRecord = buildPasskeyEd25519SealedSessionRecordFixture({
    walletId: record.walletId,
    nearAccountId: record.ed25519Restore.nearAccountId,
    nearEd25519SigningKeyId: record.ed25519Restore.nearEd25519SigningKeyId,
    thresholdSessionId: 'threshold-session-renewed',
    expiresAtMs: NOW_MS + 120_000,
    remainingUses: 1,
    materialActivation: record.ed25519Restore.materialActivation,
  });
  const authorization = buildPasskeyEd25519AuthorizationProjectionFixture(renewedRecord, {
    authorizationSessionId: 'authorization:renewed',
    walletSessionId: 'wallet-session:renewed',
    quotaId: 'quota:renewed',
    authorizationExpiresAtMs: NOW_MS + 120_000,
  });
  const response = await warmBootstrapResponse({
    record,
    authorization,
    capabilityThresholdSessionId: 'threshold-capability-original',
    responseThresholdSessionId: 'threshold-session-renewed',
  });
  expect(response.thresholdExpiresAtMs).toBeGreaterThan(record.expiresAtMs);

  let requestBody: Record<string, unknown> | null = null;
  const resolved = await resolvePasskeyEd25519YaoExportContextWithRuntimeV1(
    {
      subject: {
        walletId: record.walletId,
        nearAccountId: record.ed25519Restore.nearAccountId,
        signerSlot: record.ed25519Restore.signerSlot,
        thresholdSessionId: record.thresholdSessionIds.ed25519,
        materialActivation: record.ed25519Restore.materialActivation,
      },
      relayerUrl: RELAYER_URL,
      fetch: async (_input, init) => {
        requestBody = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
        return new Response(JSON.stringify(response), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      },
    },
    {
      readExactEd25519SealedSession: async () => record,
      readActiveWalletSessionAuthorization: async () => ({
        kind: 'found',
        projection: authorization,
      }),
      nowMs: () => NOW_MS,
    },
  );

  expect(requestBody?.thresholdSessionId).toBe('threshold-session-renewed');
  expect(resolved.kind).toBe('ready');
  if (resolved.kind === 'ready') {
    expect(resolved.context.material.capability.lifecycle.thresholdSessionId).toBe(
      'threshold-capability-original',
    );
    expect(resolved.context.material.capability.materialActivation).toEqual(
      record.ed25519Restore.materialActivation,
    );
  }
});

test('warm recovery rejects identity and material substitutions', async () => {
  const record = buildSealedRecord({ expiresAtMs: NOW_MS + 60_000, remainingUses: 1 });
  const authorization = buildPasskeyEd25519AuthorizationProjectionFixture(record);
  const substitutions = [
    {
      label: 'identity',
      response: await warmBootstrapResponse({
        record,
        authorization,
        capabilityThresholdSessionId: 'threshold-capability-original',
        capabilityAccountId: 'foreign-wallet',
      }),
    },
    {
      label: 'material',
      response: await warmBootstrapResponse({
        record,
        authorization,
        capabilityThresholdSessionId: 'threshold-capability-original',
        materialActivation: buildMpcMaterialActivationRefFixture(
          'foreign-warm-material',
          record.walletId,
        ),
      }),
    },
  ];

  for (const substitution of substitutions) {
    await expect(
      resolvePasskeyEd25519YaoExportContextWithRuntimeV1(
        {
          subject: {
            walletId: record.walletId,
            nearAccountId: record.ed25519Restore.nearAccountId,
            signerSlot: record.ed25519Restore.signerSlot,
            thresholdSessionId: record.thresholdSessionIds.ed25519,
            materialActivation: record.ed25519Restore.materialActivation,
          },
          relayerUrl: RELAYER_URL,
          fetch: async () =>
            new Response(JSON.stringify(substitution.response), {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            }),
        },
        {
          readExactEd25519SealedSession: async () => record,
          readActiveWalletSessionAuthorization: async () => ({
            kind: 'found',
            projection: authorization,
          }),
          nowMs: () => NOW_MS,
        },
      ),
      substitution.label,
    ).rejects.toThrow();
  }
});
