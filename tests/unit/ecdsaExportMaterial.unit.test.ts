import { expect, test } from '@playwright/test';
import { toAccountId } from '../../client/src/core/types/accountIds';
import type { ThresholdEcdsaChainTarget } from '../../client/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEvmFamilyEcdsaKeyIdentityFromRecord,
  toEvmFamilyEcdsaKeyHandle,
  toThresholdOwnerAddress,
  toVerifiedEcdsaPublicFactsFromRecord,
} from '../../client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { SigningSessionIds } from '../../client/src/core/signingEngine/session/operationState/types';
import {
  deriveThresholdEcdsaRuntimeLaneKey,
  type ThresholdEcdsaSessionRecord,
} from '../../client/src/core/signingEngine/session/persistence/records';
import {
  resolveEcdsaExportMaterialForLane,
  resolveFreshEmailOtpEcdsaExportMaterialForLane,
  type EcdsaExportSessionStoreDeps,
  type ExactEcdsaExportLane,
} from '../../client/src/core/signingEngine/flows/recovery/ecdsaExportMaterial';
import type { ThresholdEcdsaCanonicalExportArtifact } from '../../client/src/core/signingEngine/interfaces/signing';

const WALLET_ID = toAccountId('alice.testnet');
const RP_ID = 'localhost';
const OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
const PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

const EVM_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};

function makeRecord(
  overrides: Partial<ThresholdEcdsaSessionRecord> = {},
): ThresholdEcdsaSessionRecord {
  return {
    walletId: WALLET_ID,
    chainTarget: EVM_TARGET,
    relayerUrl: 'https://relay.localhost',
    ecdsaThresholdKeyId: 'ehss-export-key',
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
    relayerKeyId: 'relayer-key',
    clientVerifyingShareB64u: 'client-verifying-share',
    clientAdditiveShareHandle: {
      kind: 'email_otp_worker_session',
      sessionId: 'email-otp-worker-session-1',
    },
    participantIds: [2, 1],
    thresholdSessionKind: 'jwt',
    thresholdSessionId: 'threshold-session-1',
    walletSigningSessionId: 'wallet-signing-session-1',
    thresholdSessionAuthToken: 'threshold-auth-token',
    expiresAtMs: 1_900_000_000_000,
    remainingUses: 1,
    thresholdEcdsaPublicKeyB64u: PUBLIC_KEY_B64U,
    ethereumAddress: OWNER_ADDRESS,
    emailOtpAuthContext: {
      policy: 'per_operation',
      retention: 'single_use',
      reason: 'sign',
      authMethod: 'email_otp',
      authSubjectId: 'google:alice',
    },
    updatedAtMs: 1_800_000_000_000,
    source: 'email_otp',
    ...overrides,
    keyHandle: overrides.keyHandle ?? toEvmFamilyEcdsaKeyHandle('key-handle-export'),
    authMetadata: overrides.authMetadata ?? { rpId: RP_ID },
  };
}

async function exactExportLane(record: ThresholdEcdsaSessionRecord): Promise<ExactEcdsaExportLane> {
  return {
    curve: 'ecdsa',
    key: buildEvmFamilyEcdsaKeyIdentityFromRecord({ record, rpId: RP_ID }),
    publicFacts: await toVerifiedEcdsaPublicFactsFromRecord({ record }),
    session: {
      chainTarget: record.chainTarget,
      authMethod: 'email_otp',
      walletSigningSessionId: SigningSessionIds.walletSigningSession(record.walletSigningSessionId),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(record.thresholdSessionId),
      state: 'ready',
      source: 'runtime_session_record',
    },
  };
}

function depsForRecord(
  record: ThresholdEcdsaSessionRecord,
  cachedExportArtifact?: ThresholdEcdsaCanonicalExportArtifact,
): EcdsaExportSessionStoreDeps {
  const laneKey = deriveThresholdEcdsaRuntimeLaneKey(record);
  return {
    recordsByLane: new Map([[laneKey, record]]),
    exportArtifactsByLane: cachedExportArtifact
      ? new Map([[laneKey, cachedExportArtifact]])
      : new Map(),
  };
}

test.describe('ECDSA export material', () => {
  test('ready export material composes signer material with verified public facts', async () => {
    const record = makeRecord();
    const material = await resolveEcdsaExportMaterialForLane(
      depsForRecord(record),
      await exactExportLane(record),
      RP_ID,
    );

    expect(material.kind).toBe('ready_threshold_ecdsa_export_material');
    if (material.kind !== 'ready_threshold_ecdsa_export_material') {
      throw new Error(`expected ready threshold export material, got ${material.kind}`);
    }
    expect(material.record).toBe(record);
    expect(material.signerSession.kind).toBe('ready_ecdsa_signer_session');
    expect(material.signerSession.session.thresholdSessionId).toBe(record.thresholdSessionId);
    expect(material.cachedExportArtifact).toBeNull();
    expect(material.publicFacts.kind).toBe('verified_ecdsa_public_facts');
    expect(material.publicFacts.publicKeyB64u).toBe(PUBLIC_KEY_B64U);
    expect(material.publicFacts.participantIds.map(Number)).toEqual([1, 2]);
    expect(material.publicFacts.thresholdOwnerAddress).toBe(OWNER_ADDRESS);
    expect('ecdsaThresholdKeyId' in material.publicFacts).toBe(false);
    expect('participantIds' in material).toBe(false);
    expect('keyRef' in material).toBe(false);
    expect('readyMaterial' in material).toBe(false);
  });

  test('ready export material uses cached artifact from ready material provenance', async () => {
    const record = makeRecord();
    const cachedExportArtifact: ThresholdEcdsaCanonicalExportArtifact = {
      artifactKind: 'ecdsa-hss-secp256k1-key-v1',
      chainTarget: EVM_TARGET,
      signingRootId: String(record.signingRootId || 'project:dev'),
      signingRootVersion: String(record.signingRootVersion || 'default'),
      publicKeyHex: '02'.padEnd(66, '0'),
      privateKeyHex: '11'.repeat(32),
      ethereumAddress: OWNER_ADDRESS,
    };
    const material = await resolveEcdsaExportMaterialForLane(
      depsForRecord(record, cachedExportArtifact),
      await exactExportLane(record),
      RP_ID,
    );

    expect(material.kind).toBe('ready_threshold_ecdsa_export_material');
    if (material.kind !== 'ready_threshold_ecdsa_export_material') {
      throw new Error(`expected ready threshold export material, got ${material.kind}`);
    }
    expect(material.cachedExportArtifact).toEqual(cachedExportArtifact);
  });

  test('fresh Email OTP export material carries verified public facts', async () => {
    const record = makeRecord();
    const material = await resolveFreshEmailOtpEcdsaExportMaterialForLane(
      depsForRecord(record),
      await exactExportLane(record),
    );

    expect(material.kind).toBe('fresh_email_otp');
    expect(material.publicFacts.kind).toBe('verified_ecdsa_public_facts');
    expect(material.publicFacts.publicKeyB64u).toBe(PUBLIC_KEY_B64U);
    expect(material.publicFacts.participantIds.map(Number)).toEqual([1, 2]);
    expect(material.publicFacts.thresholdOwnerAddress).toBe(OWNER_ADDRESS);
    expect(material.authSubjectId).toBe('google:alice');
    expect('publicKey' in material).toBe(false);
    expect('participantIds' in material).toBe(false);
  });

  test('fresh Email OTP export material rejects missing verified public key facts', async () => {
    const record = makeRecord({
      ecdsaThresholdKeyId: 'ehss-export-key-missing-public-key',
      thresholdEcdsaPublicKeyB64u: undefined,
      thresholdSessionId: 'threshold-session-2',
      walletSigningSessionId: 'wallet-signing-session-2',
    });
    const selectedLane = await exactExportLane(
      makeRecord({
        ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
        thresholdSessionId: record.thresholdSessionId,
        walletSigningSessionId: record.walletSigningSessionId,
      }),
    );

    await expect(
      resolveFreshEmailOtpEcdsaExportMaterialForLane(depsForRecord(record), selectedLane),
    ).rejects.toThrow(/thresholdEcdsaPublicKeyB64u is required/);
  });

  test('ready export material rejects lane public facts that do not match stored record', async () => {
    const record = makeRecord();
    const lane = await exactExportLane(record);
    const mismatchedLane: ExactEcdsaExportLane = {
      ...lane,
      publicFacts: {
        ...lane.publicFacts,
        thresholdOwnerAddress: toThresholdOwnerAddress(
          '0x2222222222222222222222222222222222222222',
        ),
      },
    };

    await expect(
      resolveEcdsaExportMaterialForLane(depsForRecord(record), mismatchedLane, RP_ID),
    ).rejects.toThrow(/ready export lane public facts mismatch: thresholdOwnerAddress/);
  });

  test('fresh Email OTP export material rejects lane public facts that do not match resolved material', async () => {
    const record = makeRecord();
    const lane = await exactExportLane(record);
    const mismatchedLane: ExactEcdsaExportLane = {
      ...lane,
      publicFacts: {
        ...lane.publicFacts,
        thresholdOwnerAddress: toThresholdOwnerAddress(
          '0x2222222222222222222222222222222222222222',
        ),
      },
    };

    await expect(
      resolveFreshEmailOtpEcdsaExportMaterialForLane(depsForRecord(record), mismatchedLane),
    ).rejects.toThrow(/fresh Email OTP export lane public facts mismatch: thresholdOwnerAddress/);
  });
});
