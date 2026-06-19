import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
  type EvmEip155ChainTarget,
  type TempoChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { buildRelayerKeyId, type CredentialIdB64u } from '@/core/platform';
import {
  createExportKeysUseCase,
  type ExportKeysDeps,
} from '@/core/signingEngine/useCases/exportKeys';
import type {
  EcdsaRelayerKeyId,
  Ed25519RelayerKeyId,
  ExportKeyArtifact,
  ExportKeysAuthorization,
  ExportKeysInput,
  EcdsaUseCaseReadyLane,
  ReadyEd25519Lane,
  UnixTimeMs,
  WarmSessionRemainingUses,
} from '@/core/signingEngine/useCases/lifecycle';
import type {
  ThresholdSessionId,
  SigningGrantId,
} from '@/core/signingEngine/session/operationState/types';

function b64u(length: number, fill: number): string {
  return base64UrlEncode(new Uint8Array(length).fill(fill));
}

function publicKey33(fill: number): string {
  const bytes = new Uint8Array(33).fill(fill);
  bytes[0] = fill % 2 === 0 ? 2 : 3;
  return base64UrlEncode(bytes);
}

function asBrand<T>(value: unknown): T {
  return value as T;
}

const walletId = toWalletId('phase7-wallet');
const rpId = toRpId('wallet.example');
const evmTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
}) as EvmEip155ChainTarget;
const tempoTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
}) as TempoChainTarget;
const credentialIdB64u = buildEcdsaRoleLocalPasskeyAuthMethod({
  credentialIdB64u: 'credential-phase7',
  rpId,
}).credentialIdB64u;
const ecdsaKeyHandle = 'key-handle-phase7';
const thresholdSessionId = asBrand<ThresholdSessionId>('threshold-session');
const signingGrantId = asBrand<SigningGrantId>('wallet-session');
const expiresAtMs = asBrand<UnixTimeMs>(1_900_000_000_000);
const remainingUses = asBrand<WarmSessionRemainingUses>(8);

function readyEcdsaLane(): EcdsaUseCaseReadyLane {
  const publicFacts = buildEcdsaRoleLocalPublicFacts({
    walletId,
    rpId,
    chainTarget: evmTarget,
    keyHandle: ecdsaKeyHandle,
    ecdsaThresholdKeyId: 'ecdsa-key',
    signingRootId: 'signing-root',
    signingRootVersion: 'v1',
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: [1, 2],
    contextBinding32B64u: b64u(32, 7),
    hssClientSharePublicKey33B64u: publicKey33(8),
    relayerPublicKey33B64u: publicKey33(10),
    groupPublicKey33B64u: publicKey33(12),
    ethereumAddress: '0x1111111111111111111111111111111111111111',
  });
  const readyRecord = buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: b64u(64, 13),
    },
    publicFacts,
    authMethod: buildEcdsaRoleLocalPasskeyAuthMethod({
      credentialIdB64u,
      rpId,
    }),
  });
  return {
    kind: 'ecdsa_ready_lane_v1',
    walletId,
    rpId,
    chainTarget: evmTarget,
    readyRecord,
    relayerKeyId: buildRelayerKeyId('ecdsa-relayer') as EcdsaRelayerKeyId,
    thresholdSessionId,
    signingGrantId,
    remainingUses,
    expiresAtMs,
  };
}

function readyEd25519Lane(): ReadyEd25519Lane {
  return {
    kind: 'ed25519_ready_lane_v1',
    walletId,
    rpId,
    thresholdSessionId,
    signingGrantId,
    relayerKeyId: buildRelayerKeyId('ed25519-relayer') as Ed25519RelayerKeyId,
    remainingUses,
    expiresAtMs,
  };
}

function passkeyAuthorization(): ExportKeysAuthorization {
  return {
    kind: 'passkey_export_authorized',
    walletId,
    rpId,
    credentialIdB64u: credentialIdB64u as CredentialIdB64u,
    scopes: [
      { kind: 'ed25519_export_scope', curve: 'ed25519', chain: 'near' },
      { kind: 'ecdsa_export_scope', curve: 'ecdsa', chainTarget: evmTarget },
    ],
    issuedAtMs: asBrand<UnixTimeMs>(1_800_000_000_000),
    expiresAtMs: asBrand<UnixTimeMs>(1_900_000_000_000),
  };
}

function exportInput(
  authorization: ExportKeysAuthorization = passkeyAuthorization(),
): ExportKeysInput {
  return {
    walletId,
    rpId,
    requestedKeys: [{ kind: 'near_ed25519' }, { kind: 'ecdsa_secp256k1', chainTarget: evmTarget }],
    authorization,
  };
}

function ed25519Artifact(): ExportKeyArtifact {
  return {
    kind: 'near_ed25519_export_artifact_v1',
    walletId,
    publicKey: 'ed25519-public',
    privateKey: 'ed25519-private',
    seed: { kind: 'available', seedB64u: b64u(32, 21) },
  };
}

function ecdsaArtifact(lane = readyEcdsaLane()): ExportKeyArtifact {
  return {
    kind: 'ecdsa_secp256k1_export_artifact_v1',
    walletId,
    chainTarget: evmTarget,
    ethereumAddress: lane.readyRecord.publicFacts.ethereumAddress,
    exportPayloadB64u: b64u(96, 22),
    publicFacts: lane.readyRecord.publicFacts,
  };
}

test('ExportKeysUseCase opens viewer only after all requested artifacts are built', async () => {
  const ed25519 = readyEd25519Lane();
  const ecdsa = readyEcdsaLane();
  const lifecycle: string[] = [];
  const artifactOrder: string[] = [];
  const deps: ExportKeysDeps = {
    clock: { nowMs: () => 1_850_000_000_000 },
    materialLoader: { load: async () => ({ ok: true, material: [ed25519, ecdsa] }) },
    artifactBuilder: {
      buildEd25519: async () => {
        artifactOrder.push('ed25519');
        return { ok: true, artifact: ed25519Artifact() };
      },
      buildEcdsa: async () => {
        artifactOrder.push('ecdsa');
        return { ok: true, artifact: ecdsaArtifact(ecdsa) };
      },
    },
    viewer: {
      open: async ({ artifacts }) => {
        artifactOrder.push(`viewer:${artifacts.length}`);
        return { ok: true, viewerSessionId: 'viewer-session' };
      },
    },
    lifecycle: {
      transition: (state) => {
        lifecycle.push(state.kind);
      },
    },
  };

  const result = await createExportKeysUseCase(deps).export(exportInput());

  expect(result).toMatchObject({
    ok: true,
    viewerSessionId: 'viewer-session',
    artifacts: [
      { kind: 'near_ed25519_export_artifact_v1' },
      { kind: 'ecdsa_secp256k1_export_artifact_v1' },
    ],
  });
  expect(artifactOrder).toEqual(['ed25519', 'ecdsa', 'viewer:2']);
  expect(lifecycle).toEqual([
    'received_input',
    'validating_authorization',
    'loading_material',
    'building_artifacts',
    'opening_viewer',
    'ready',
  ]);
});

test('ExportKeysUseCase rejects expired export authorization before material loading', async () => {
  let loadCalls = 0;
  const expiredAuthorization: ExportKeysAuthorization = {
    ...passkeyAuthorization(),
    expiresAtMs: asBrand<UnixTimeMs>(1_840_000_000_000),
  };
  const deps: ExportKeysDeps = {
    clock: { nowMs: () => 1_850_000_000_000 },
    materialLoader: {
      load: async () => {
        loadCalls += 1;
        return { ok: true, material: [readyEd25519Lane()] };
      },
    },
    artifactBuilder: {
      buildEd25519: async () => ({ ok: true, artifact: ed25519Artifact() }),
      buildEcdsa: async () => ({ ok: true, artifact: ecdsaArtifact() }),
    },
    viewer: { open: async () => ({ ok: true, viewerSessionId: 'viewer-session' }) },
  };

  const result = await createExportKeysUseCase(deps).export(exportInput(expiredAuthorization));

  expect(result).toMatchObject({ ok: false, code: 'authorization_failed' });
  expect(loadCalls).toBe(0);
});

test('ExportKeysUseCase requires exact ECDSA export authorization scope', async () => {
  let loadCalls = 0;
  const mismatchedAuthorization: ExportKeysAuthorization = {
    ...passkeyAuthorization(),
    scopes: [
      { kind: 'ed25519_export_scope', curve: 'ed25519', chain: 'near' },
      { kind: 'ecdsa_export_scope', curve: 'ecdsa', chainTarget: tempoTarget },
    ],
  };
  const deps: ExportKeysDeps = {
    clock: { nowMs: () => 1_850_000_000_000 },
    materialLoader: {
      load: async () => {
        loadCalls += 1;
        return { ok: true, material: [readyEd25519Lane(), readyEcdsaLane()] };
      },
    },
    artifactBuilder: {
      buildEd25519: async () => ({ ok: true, artifact: ed25519Artifact() }),
      buildEcdsa: async () => ({ ok: true, artifact: ecdsaArtifact() }),
    },
    viewer: { open: async () => ({ ok: true, viewerSessionId: 'viewer-session' }) },
  };

  const result = await createExportKeysUseCase(deps).export(exportInput(mismatchedAuthorization));

  expect(result).toMatchObject({ ok: false, code: 'authorization_failed' });
  expect(loadCalls).toBe(0);
});

test('ExportKeysUseCase returns no partial artifacts after an ECDSA artifact failure', async () => {
  const ed25519 = readyEd25519Lane();
  const ecdsa = readyEcdsaLane();
  let viewerCalls = 0;
  const deps: ExportKeysDeps = {
    clock: { nowMs: () => 1_850_000_000_000 },
    materialLoader: { load: async () => ({ ok: true, material: [ed25519, ecdsa] }) },
    artifactBuilder: {
      buildEd25519: async () => ({ ok: true, artifact: ed25519Artifact() }),
      buildEcdsa: async () => ({
        ok: false,
        code: 'signer_crypto_command_failed',
        source: 'signer_crypto',
        message: 'signer command failed',
        retryable: false,
      }),
    },
    viewer: {
      open: async () => {
        viewerCalls += 1;
        return { ok: true, viewerSessionId: 'viewer-session' };
      },
    },
  };

  const result = await createExportKeysUseCase(deps).export(exportInput());

  expect(result).toMatchObject({ ok: false, code: 'signer_crypto_command_failed' });
  expect('partialArtifacts' in result).toBe(false);
  expect(viewerCalls).toBe(0);
});
