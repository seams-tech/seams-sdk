import { expect, test } from '@playwright/test';
import { SigningEngine } from '@/core/signingEngine/SigningEngine';
import type { SigningSessionSnapshot } from '@/core/signingEngine/session/snapshotReader';

const ACCOUNT_ID = 'export-selection.testnet';

function makeSnapshot(
  candidates: SigningSessionSnapshot['candidates']['ed25519']['near'],
): SigningSessionSnapshot {
  return {
    walletId: ACCOUNT_ID as any,
    generation: 1,
    lanes: {
      ed25519: {
        near: candidates[0] || {
          curve: 'ed25519',
          chain: 'near',
          state: 'missing',
        },
      },
      ecdsa: {
        tempo: { curve: 'ecdsa', chain: 'tempo', state: 'missing' },
        evm: { curve: 'ecdsa', chain: 'evm', state: 'missing' },
      },
    },
    candidates: {
      ed25519: { near: candidates },
      ecdsa: { tempo: [], evm: [] },
    },
  };
}

function makeEcdsaSnapshot(args: {
  chain: 'evm' | 'tempo';
  candidates: SigningSessionSnapshot['candidates']['ecdsa']['evm'];
}): SigningSessionSnapshot {
  return {
    walletId: ACCOUNT_ID as any,
    generation: 1,
    lanes: {
      ed25519: {
        near: {
          curve: 'ed25519',
          chain: 'near',
          state: 'missing',
        },
      },
      ecdsa: {
        tempo:
          args.chain === 'tempo'
            ? args.candidates[0] || { curve: 'ecdsa', chain: 'tempo', state: 'missing' }
            : { curve: 'ecdsa', chain: 'tempo', state: 'missing' },
        evm:
          args.chain === 'evm'
            ? args.candidates[0] || { curve: 'ecdsa', chain: 'evm', state: 'missing' }
            : { curve: 'ecdsa', chain: 'evm', state: 'missing' },
      },
    },
    candidates: {
      ed25519: { near: [] },
      ecdsa: {
        tempo: args.chain === 'tempo' ? args.candidates : [],
        evm: args.chain === 'evm' ? args.candidates : [],
      },
    },
  };
}

function makeEngine(snapshot: SigningSessionSnapshot) {
  const selectedLanes: unknown[] = [];
  const engine: any = Object.create(SigningEngine.prototype);
  engine.readPersistedSigningSessionSnapshot = async () => snapshot;
  engine.tryExportNearEd25519SingleKeyHssWithAuthorization = async (args: unknown) => {
    selectedLanes.push((args as { exportLane: unknown }).exportLane);
    return {
      accountId: ACCOUNT_ID,
      exportedSchemes: ['ed25519'],
    };
  };
  return { engine, selectedLanes };
}

function makeEcdsaExportEngine(snapshot: SigningSessionSnapshot) {
  const selectedLanes: unknown[] = [];
  const engine: any = Object.create(SigningEngine.prototype);
  engine.readPersistedSigningSessionSnapshot = async () => snapshot;
  engine.resolveEcdsaExportMaterialForLane = async (exportLane: unknown) => ({
    kind: 'ready',
    keyRef: {
      type: 'threshold-ecdsa-secp256k1',
      thresholdSessionId: (exportLane as { thresholdSessionId: string }).thresholdSessionId,
      walletSigningSessionId: (exportLane as { walletSigningSessionId: string })
        .walletSigningSessionId,
    },
  });
  engine.exportThresholdEcdsaKeyWithAuthorization = async (args: unknown) => {
    selectedLanes.push((args as { exportLane: unknown }).exportLane);
    return {
      accountId: ACCOUNT_ID,
      exportedSchemes: ['secp256k1'],
    };
  };
  return { engine, selectedLanes };
}

test('NEAR Ed25519 export selects the single active runtime lane over durable history', async () => {
  const { engine, selectedLanes } = makeEngine(
    makeSnapshot([
      {
        curve: 'ed25519',
        chain: 'near',
        authMethod: 'email_otp',
        state: 'ready',
        source: 'runtime_and_durable',
        walletSigningSessionId: 'wsess-email-runtime',
        thresholdSessionId: 'tsess-email-runtime',
        remainingUses: 1,
        expiresAtMs: Date.now() + 60_000,
        updatedAtMs: 30,
      },
      {
        curve: 'ed25519',
        chain: 'near',
        authMethod: 'passkey',
        state: 'restorable',
        source: 'durable_sealed_record',
        walletSigningSessionId: 'wsess-passkey-durable',
        thresholdSessionId: 'tsess-passkey-durable',
        updatedAtMs: 20,
      },
    ]),
  );

  await expect(
    engine.exportKeypairWithUI(ACCOUNT_ID as any, { chain: 'near', variant: 'modal' }),
  ).resolves.toEqual({
    accountId: ACCOUNT_ID,
    exportedSchemes: ['ed25519'],
  });

  expect(selectedLanes).toHaveLength(1);
  expect(selectedLanes[0]).toMatchObject({
    authMethod: 'email_otp',
    walletSigningSessionId: 'wsess-email-runtime',
    thresholdSessionId: 'tsess-email-runtime',
  });
});

test('NEAR Ed25519 export succeeds when exactly one concrete lane exists', async () => {
  const { engine, selectedLanes } = makeEngine(
    makeSnapshot([
      {
        curve: 'ed25519',
        chain: 'near',
        authMethod: 'email_otp',
        state: 'ready',
        source: 'durable_sealed_record',
        walletSigningSessionId: 'wsess-email-new',
        thresholdSessionId: 'tsess-email-new',
        updatedAtMs: 20,
      },
    ]),
  );

  await expect(
    engine.exportKeypairWithUI(ACCOUNT_ID as any, { chain: 'near', variant: 'modal' }),
  ).resolves.toEqual({
    accountId: ACCOUNT_ID,
    exportedSchemes: ['ed25519'],
  });

  expect(selectedLanes).toHaveLength(1);
  expect(selectedLanes[0]).toMatchObject({
    authMethod: 'email_otp',
    walletSigningSessionId: 'wsess-email-new',
    thresholdSessionId: 'tsess-email-new',
  });
});

test('ECDSA export rejects multiple exact lanes instead of filtering by account auth metadata', async () => {
  const { engine, selectedLanes } = makeEcdsaExportEngine(
    makeEcdsaSnapshot({
      chain: 'evm',
      candidates: [
        {
          curve: 'ecdsa',
          chain: 'evm',
          authMethod: 'email_otp',
          state: 'ready',
          source: 'runtime_session_record',
          walletSigningSessionId: 'wsess-email-old',
          thresholdSessionId: 'tsess-email-old',
          updatedAtMs: 10,
        },
        {
          curve: 'ecdsa',
          chain: 'evm',
          authMethod: 'passkey',
          state: 'ready',
          source: 'runtime_session_record',
          walletSigningSessionId: 'wsess-passkey-newer',
          thresholdSessionId: 'tsess-passkey-newer',
          updatedAtMs: 30,
        },
        {
          curve: 'ecdsa',
          chain: 'evm',
          authMethod: 'email_otp',
          state: 'ready',
          source: 'runtime_session_record',
          walletSigningSessionId: 'wsess-email-new',
          thresholdSessionId: 'tsess-email-new',
          updatedAtMs: 20,
        },
      ],
    }),
  );

  await expect(
    engine.exportKeypairWithUI(ACCOUNT_ID as any, { chain: 'evm', variant: 'modal' }),
  ).rejects.toThrow('ambiguous_candidates');

  expect(selectedLanes).toHaveLength(0);
});

test('ECDSA export ignores missing runtime inventory when one durable exact lane exists', async () => {
  const { engine, selectedLanes } = makeEcdsaExportEngine(
    makeEcdsaSnapshot({
      chain: 'evm',
      candidates: [
        {
          curve: 'ecdsa',
          chain: 'evm',
          authMethod: 'email_otp',
          state: 'restorable',
          source: 'durable_sealed_record',
          walletSigningSessionId: 'wsess-email-durable',
          thresholdSessionId: 'tsess-email-durable',
          updatedAtMs: 20,
        },
        {
          curve: 'ecdsa',
          chain: 'evm',
          authMethod: 'email_otp',
          state: 'missing',
          source: 'runtime_session_record',
          walletSigningSessionId: 'wsess-email-missing-runtime',
          thresholdSessionId: 'tsess-email-missing-runtime',
          updatedAtMs: 30,
        },
      ],
    }),
  );

  await expect(
    engine.exportKeypairWithUI(ACCOUNT_ID as any, { chain: 'evm', variant: 'modal' }),
  ).resolves.toEqual({
    accountId: ACCOUNT_ID,
    exportedSchemes: ['secp256k1'],
  });

  expect(selectedLanes).toHaveLength(1);
  expect(selectedLanes[0]).toMatchObject({
    authMethod: 'email_otp',
    walletSigningSessionId: 'wsess-email-durable',
    thresholdSessionId: 'tsess-email-durable',
  });
});

test('ECDSA export succeeds when exactly one concrete lane exists', async () => {
  const { engine, selectedLanes } = makeEcdsaExportEngine(
    makeEcdsaSnapshot({
      chain: 'evm',
      candidates: [
        {
          curve: 'ecdsa',
          chain: 'evm',
          authMethod: 'email_otp',
          state: 'ready',
          source: 'runtime_session_record',
          walletSigningSessionId: 'wsess-email-only',
          thresholdSessionId: 'tsess-email-only',
          updatedAtMs: 20,
        },
      ],
    }),
  );

  await expect(
    engine.exportKeypairWithUI(ACCOUNT_ID as any, { chain: 'evm', variant: 'modal' }),
  ).resolves.toEqual({
    accountId: ACCOUNT_ID,
    exportedSchemes: ['secp256k1'],
  });

  expect(selectedLanes).toHaveLength(1);
  expect(selectedLanes[0]).toMatchObject({
    authMethod: 'email_otp',
    walletSigningSessionId: 'wsess-email-only',
    thresholdSessionId: 'tsess-email-only',
  });
});
