import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import {
  buildEmailOtpEd25519AuthorizationProjectionFixture,
  buildEmailOtpEd25519SealedSessionRecordFixture,
  buildPasskeyEd25519AuthorizationProjectionFixture,
  buildPasskeyEd25519SealedSessionRecordFixture,
} from './helpers/sealedSigningSession.fixtures';

const AVAILABLE_SIGNING_LANES_PATH =
  '/_test-sdk/esm/core/signingEngine/session/availability/availableSigningLanes.js';

test.describe('available signing lane curve isolation', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('does not discover ECDSA capabilities when no ECDSA targets were requested', async ({
    page,
  }) => {
    const result = await page.evaluate(async (modulePath) => {
      const { readAvailableSigningLanes } = await import(modulePath);
      let ecdsaDiscoveryCalls = 0;
      const lanes = await readAvailableSigningLanes(
        {
          walletId: 'near-only-wallet',
          ecdsaChainTargets: [],
        },
        {
          listSealedRecordsForWallet: async () => [],
          listCanonicalEcdsaLanesForWallet: async () => {
            ecdsaDiscoveryCalls += 1;
            throw new Error('ECDSA discovery must not run for an Ed25519-only read');
          },
        },
      );
      return {
        ecdsaDiscoveryCalls,
        nearLaneState: lanes.lanes.ed25519.near.state,
      };
    }, AVAILABLE_SIGNING_LANES_PATH);

    expect(result).toEqual({
      ecdsaDiscoveryCalls: 0,
      nearLaneState: 'missing',
    });
  });

  test('prefers durable Ed25519 policy over a duplicate public capability reference', async ({
    page,
  }) => {
    const sealedRecord = buildPasskeyEd25519SealedSessionRecordFixture({
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 7,
    });
    const authorization = buildPasskeyEd25519AuthorizationProjectionFixture(sealedRecord);
    const restore = sealedRecord.ed25519Restore;
    const publicCapabilityReference = {
      walletId: sealedRecord.walletId,
      nearAccountId: restore.nearAccountId,
      thresholdSessionId: sealedRecord.thresholdSessionIds.ed25519,
      runtimePolicyScope: restore.runtimePolicyScope,
      materialActivation: restore.materialActivation,
      auth: {
        kind: 'passkey' as const,
        rpId: restore.rpId,
        credentialIdB64u: restore.credentialIdB64u,
      },
      nearEd25519SigningKeyId: restore.nearEd25519SigningKeyId,
      signerSlot: restore.signerSlot,
    };
    const result = await page.evaluate(
      async ({ modulePath, sealedRecord, publicCapabilityReference, authorization }) => {
        const { readAvailableSigningLanes } = await import(modulePath);
        const lanes = await readAvailableSigningLanes(
          {
            walletId: sealedRecord.walletId,
            ecdsaChainTargets: [],
          },
          {
            listSealedRecordsForWallet: async () => [sealedRecord],
            listPublicCapabilityReferences: async () => [publicCapabilityReference],
            isPublicCapabilityActive: () => true,
            readActiveWalletSessionAuthorization: async () => authorization,
          },
        );
        const lane = lanes.lanes.ed25519.near;
        return {
          candidateCount: lanes.candidates.ed25519.near.length,
          lane: {
            authorizationState: lane.authorizationState,
            expiresAtMs: lane.expiresAtMs,
            remainingUses: lane.remainingUses,
            source: lane.source,
            state: lane.state,
          },
        };
      },
      {
        modulePath: AVAILABLE_SIGNING_LANES_PATH,
        sealedRecord,
        publicCapabilityReference,
        authorization,
      },
    );

    expect(result).toEqual({
      candidateCount: 1,
      lane: {
        authorizationState: 'authorized',
        expiresAtMs: sealedRecord.expiresAtMs,
        remainingUses: 7,
        source: 'durable_sealed_record',
        state: 'restorable',
      },
    });
  });

  test('prefers a current public capability over deferred durable policy', async ({
    page,
  }) => {
    const durableRecord = buildPasskeyEd25519SealedSessionRecordFixture({
      thresholdSessionId: 'ed25519-sealed-runtime-session-old',
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 7,
    });
    const currentRecord = buildPasskeyEd25519SealedSessionRecordFixture({
      thresholdSessionId: 'ed25519-sealed-runtime-session-current',
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 9,
    });
    const authorization = buildPasskeyEd25519AuthorizationProjectionFixture(currentRecord);
    const restore = currentRecord.ed25519Restore;
    const publicCapabilityReference = {
      walletId: currentRecord.walletId,
      nearAccountId: restore.nearAccountId,
      thresholdSessionId: currentRecord.thresholdSessionIds.ed25519,
      runtimePolicyScope: restore.runtimePolicyScope,
      materialActivation: restore.materialActivation,
      auth: {
        kind: 'passkey' as const,
        rpId: restore.rpId,
        credentialIdB64u: restore.credentialIdB64u,
      },
      nearEd25519SigningKeyId: restore.nearEd25519SigningKeyId,
      signerSlot: restore.signerSlot,
    };
    const result = await page.evaluate(
      async ({ modulePath, durableRecord, publicCapabilityReference, authorization }) => {
        const { readAvailableSigningLanes } = await import(modulePath);
        const lanes = await readAvailableSigningLanes(
          {
            walletId: durableRecord.walletId,
            ecdsaChainTargets: [],
          },
          {
            listSealedRecordsForWallet: async () => [durableRecord],
            listPublicCapabilityReferences: async () => [publicCapabilityReference],
            isPublicCapabilityActive: () => true,
            readActiveWalletSessionAuthorization: async () => authorization,
          },
        );
        const lane = lanes.lanes.ed25519.near;
        return {
          candidateCount: lanes.candidates.ed25519.near.length,
          lane: {
            authorizationState: lane.authorizationState,
            expiresAtMs: lane.expiresAtMs,
            remainingUses: lane.remainingUses,
            source: lane.source,
            state: lane.state,
            thresholdSessionId: lane.thresholdSessionId,
          },
        };
      },
      {
        modulePath: AVAILABLE_SIGNING_LANES_PATH,
        durableRecord,
        publicCapabilityReference,
        authorization,
      },
    );

    expect(result).toEqual({
      candidateCount: 1,
      lane: {
        authorizationState: 'authorized',
        expiresAtMs: currentRecord.expiresAtMs,
        remainingUses: undefined,
        source: 'public_capability_reference',
        state: 'ready',
        thresholdSessionId: currentRecord.thresholdSessionIds.ed25519,
      },
    });
  });

  test('prefers a fresh Email OTP unlock capability over exhausted durable policy', async ({
    page,
  }) => {
    const record = buildEmailOtpEd25519SealedSessionRecordFixture({
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 0,
    });
    const authorization = buildEmailOtpEd25519AuthorizationProjectionFixture(record);
    const restore = record.ed25519Restore;
    const publicCapabilityReference = {
      walletId: record.walletId,
      nearAccountId: restore.nearAccountId,
      thresholdSessionId: record.thresholdSessionIds.ed25519,
      runtimePolicyScope: restore.runtimePolicyScope,
      materialActivation: restore.materialActivation,
      auth: {
        kind: 'email_otp' as const,
        providerSubjectId: restore.providerSubjectId,
      },
      nearEd25519SigningKeyId: restore.nearEd25519SigningKeyId,
      signerSlot: restore.signerSlot,
      remainingUses: 3,
      expiresAtMs: authorization.expiresAtMs,
    };
    const result = await page.evaluate(
      async ({ modulePath, record, publicCapabilityReference, authorization }) => {
        const { readAvailableSigningLanes } = await import(modulePath);
        const lanes = await readAvailableSigningLanes(
          {
            walletId: publicCapabilityReference.walletId,
            ecdsaChainTargets: [],
          },
          {
            listSealedRecordsForWallet: async () => [record],
            listPublicCapabilityReferences: async () => [publicCapabilityReference],
            isPublicCapabilityActive: () => true,
            readActiveWalletSessionAuthorization: async () => authorization,
          },
        );
        const lane = lanes.lanes.ed25519.near;
        return {
          candidateCount: lanes.candidates.ed25519.near.length,
          lane: {
            authorizationState: lane.authorizationState,
            remainingUses: lane.remainingUses,
            source: lane.source,
            state: lane.state,
          },
        };
      },
      {
        modulePath: AVAILABLE_SIGNING_LANES_PATH,
        record,
        publicCapabilityReference,
        authorization,
      },
    );

    expect(result).toEqual({
      candidateCount: 1,
      lane: {
        authorizationState: 'authorized',
        remainingUses: 3,
        source: 'public_capability_reference',
        state: 'ready',
      },
    });
  });
});
