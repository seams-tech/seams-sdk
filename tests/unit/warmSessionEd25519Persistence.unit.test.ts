import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
} from '@/core/signingEngine/session/persistence/records';
import {
  classifyRouterAbEd25519PersistedSigningRecord,
  clearRouterAbEd25519WorkerMaterialRuntimeValidation,
  markRouterAbEd25519WorkerMaterialRuntimeValidated,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmCapabilities/persistence';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import {
  parseEd25519ClientVerifyingShareB64u,
  parseEd25519SealedWorkerMaterialRef,
  parseEd25519WorkerMaterialBindingDigest,
  parseEd25519WorkerMaterialHandle,
  parseEd25519WorkerMaterialKeyId,
} from '@/core/signingEngine/session/keyMaterialBrands';

const nearAccountId = toAccountId('ed25519-material-retention.testnet');
const walletId = 'frost-vermillion-k7p9m2';
const ed25519KeyScopeId = walletId;
const thresholdSessionId = 'threshold-ed25519-material-retention';
const signingGrantId = 'signing-grant-ed25519-material-retention';
const runtimePolicyScope = {
  orgId: 'org-material-retention',
  projectId: 'project-material-retention',
  envId: 'dev',
  signingRootVersion: 'default',
} as const;
const materialWalletSessionJwt = fixtureEd25519WalletSessionJwt({
  label: 'with-material',
  sessionId: thresholdSessionId,
  grantId: signingGrantId,
});
const runtimeHandleWalletSessionJwt = fixtureEd25519WalletSessionJwt({
  label: 'with-runtime-handle',
  sessionId: thresholdSessionId,
  grantId: signingGrantId,
});
const remintedWalletSessionJwt = fixtureEd25519WalletSessionJwt({
  label: 'reminted',
  sessionId: thresholdSessionId,
  grantId: signingGrantId,
});
const clientVerifyingShareB64u = parseEd25519ClientVerifyingShareB64u('client-verifier');
const ed25519WorkerMaterialHandle = parseEd25519WorkerMaterialHandle(
  'runtime-material-handle',
);
const ed25519WorkerMaterialBindingDigest =
  parseEd25519WorkerMaterialBindingDigest('material-binding-digest');
const sealedWorkerMaterialRef = parseEd25519SealedWorkerMaterialRef('sealed-material-ref');
const materialKeyId = parseEd25519WorkerMaterialKeyId('material-key-id');

function fixtureEd25519WalletSessionJwt(args: {
  label: string;
  sessionId: string;
  grantId: string;
}): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
      sub: walletId,
      walletId,
      nearAccountId,
      ed25519KeyScopeId,
      thresholdSessionId: args.sessionId,
      signingGrantId: args.grantId,
      relayerKeyId: 'ed25519:material-retention-relayer',
      rpId: 'localhost',
      runtimePolicyScope,
      participantIds: [1, 2],
      label: args.label,
    }),
  ).toString('base64url');
  return `${header}.${payload}.fixture`;
}

function persistMaterialBackedSession(args: { signingWorkerId: string }): void {
  persistWarmSessionEd25519Capability({
    kind: 'jwt_passkey',
    passkeyCredentialIdB64u: 'credential-ed25519-material-retention',
    walletId,
    nearAccountId,
    ed25519KeyScopeId,
    rpId: 'localhost',
    relayerUrl: 'https://localhost:9444',
    relayerKeyId: 'ed25519:material-retention-relayer',
    participantIds: [1, 2],
    sessionKind: 'jwt',
    sessionId: thresholdSessionId,
    signingGrantId,
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 3,
    signerSlot: 1,
    jwt: materialWalletSessionJwt,
    runtimePolicyScope,
    routerAbNormalSigning: {
      kind: 'router_ab_ed25519_normal_signing_v1',
      signingWorkerId: args.signingWorkerId,
    },
    clientVerifyingShareB64u,
    ed25519WorkerMaterialHandle,
    ed25519WorkerMaterialBindingDigest,
    sealedWorkerMaterialRef,
    sealedWorkerMaterialB64u: 'sealed-material',
    materialFormatVersion: 'ed25519_sealed_worker_material_v1',
    materialKeyId,
    materialCreatedAtMs: 1_800_000_000_000,
    keyVersion: 'threshold-ed25519-hss-v1',
    source: 'registration',
  });
}

function persistRuntimeHandleOnlySession(args: { signingWorkerId: string }): void {
  persistWarmSessionEd25519Capability({
    kind: 'jwt_passkey',
    passkeyCredentialIdB64u: 'credential-ed25519-material-retention',
    walletId,
    nearAccountId,
    ed25519KeyScopeId,
    rpId: 'localhost',
    relayerUrl: 'https://localhost:9444',
    relayerKeyId: 'ed25519:material-retention-relayer',
    participantIds: [1, 2],
    sessionKind: 'jwt',
    sessionId: thresholdSessionId,
    signingGrantId,
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 3,
    signerSlot: 1,
    jwt: runtimeHandleWalletSessionJwt,
    runtimePolicyScope,
    routerAbNormalSigning: {
      kind: 'router_ab_ed25519_normal_signing_v1',
      signingWorkerId: args.signingWorkerId,
    },
    clientVerifyingShareB64u,
    ed25519WorkerMaterialHandle,
    ed25519WorkerMaterialBindingDigest,
    materialCreatedAtMs: 1_800_000_000_000,
    keyVersion: 'threshold-ed25519-hss-v1',
    source: 'registration',
  });
}

function remintSessionWithoutMaterial(args: { signingWorkerId: string }): void {
  persistWarmSessionEd25519Capability({
    kind: 'jwt_passkey',
    passkeyCredentialIdB64u: 'credential-ed25519-material-retention',
    walletId,
    nearAccountId,
    ed25519KeyScopeId,
    rpId: 'localhost',
    relayerUrl: 'https://localhost:9444',
    relayerKeyId: 'ed25519:material-retention-relayer',
    participantIds: [1, 2],
    sessionKind: 'jwt',
    sessionId: thresholdSessionId,
    signingGrantId,
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 3,
    signerSlot: 1,
    jwt: remintedWalletSessionJwt,
    runtimePolicyScope,
    routerAbNormalSigning: {
      kind: 'router_ab_ed25519_normal_signing_v1',
      signingWorkerId: args.signingWorkerId,
    },
    source: 'login',
  });
}

function remintNewSessionWithoutMaterial(args: {
  thresholdSessionId: string;
  signingGrantId: string;
  signingWorkerId: string;
}): void {
  persistWarmSessionEd25519Capability({
    kind: 'jwt_passkey',
    passkeyCredentialIdB64u: 'credential-ed25519-material-retention',
    walletId,
    nearAccountId,
    ed25519KeyScopeId,
    rpId: 'localhost',
    relayerUrl: 'https://localhost:9444',
    relayerKeyId: 'ed25519:material-retention-relayer',
    participantIds: [1, 2],
    sessionKind: 'jwt',
    sessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 3,
    signerSlot: 1,
    jwt: fixtureEd25519WalletSessionJwt({
      label: 'reminted-new-session',
      sessionId: args.thresholdSessionId,
      grantId: args.signingGrantId,
    }),
    runtimePolicyScope,
    routerAbNormalSigning: {
      kind: 'router_ab_ed25519_normal_signing_v1',
      signingWorkerId: args.signingWorkerId,
    },
    source: 'login',
  });
}

test.describe('warm Ed25519 session persistence', () => {
  test.beforeEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
    clearRouterAbEd25519WorkerMaterialRuntimeValidation();
  });

  test.afterEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
    clearRouterAbEd25519WorkerMaterialRuntimeValidation();
  });

  test('retains sealed worker-material facts across exact-session Wallet Session remint', () => {
    persistMaterialBackedSession({ signingWorkerId: 'signing-worker-a' });
    remintSessionWithoutMaterial({ signingWorkerId: 'signing-worker-a' });

    const record = getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId);
    expect(record?.walletSessionJwt).toBe(remintedWalletSessionJwt);
    expect(record?.clientVerifyingShareB64u).toBe('client-verifier');
    expect(record?.ed25519WorkerMaterialHandle).toBe('runtime-material-handle');
    expect(record?.ed25519WorkerMaterialBindingDigest).toBe('material-binding-digest');
    expect(record?.sealedWorkerMaterialRef).toBe('sealed-material-ref');
    expect(record?.sealedWorkerMaterialB64u).toBe('sealed-material');
    expect(record?.materialKeyId).toBe('material-key-id');
    expect(record?.materialCreatedAtMs).toBe(1_800_000_000_000);
    expect(record?.keyVersion).toBe('threshold-ed25519-hss-v1');
    expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
      kind: 'restore_available',
      reason: 'loaded_material_missing',
    });
    expect(markRouterAbEd25519WorkerMaterialRuntimeValidated(record)).toBe(true);
    expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
      kind: 'runtime_validated',
    });
  });

  test('retains sealed worker-material facts across same-identity new-session remint', () => {
    const remintedSessionId = 'threshold-ed25519-material-retention-new-session';
    persistMaterialBackedSession({ signingWorkerId: 'signing-worker-a' });
    remintNewSessionWithoutMaterial({
      thresholdSessionId: remintedSessionId,
      signingGrantId: 'signing-grant-ed25519-material-retention-new-session',
      signingWorkerId: 'signing-worker-a',
    });

    const record = getStoredThresholdEd25519SessionRecordByThresholdSessionId(remintedSessionId);
    expect(record?.walletSessionJwt).toBe(
      fixtureEd25519WalletSessionJwt({
        label: 'reminted-new-session',
        sessionId: remintedSessionId,
        grantId: 'signing-grant-ed25519-material-retention-new-session',
      }),
    );
    expect(record?.clientVerifyingShareB64u).toBe('client-verifier');
    expect(record?.ed25519WorkerMaterialHandle).toBe('runtime-material-handle');
    expect(record?.ed25519WorkerMaterialBindingDigest).toBe('material-binding-digest');
    expect(record?.sealedWorkerMaterialRef).toBe('sealed-material-ref');
    expect(record?.sealedWorkerMaterialB64u).toBe('sealed-material');
    expect(record?.materialKeyId).toBe('material-key-id');
    expect(record?.materialCreatedAtMs).toBe(1_800_000_000_000);
    expect(record?.keyVersion).toBe('threshold-ed25519-hss-v1');
    expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
      kind: 'restore_available',
      reason: 'loaded_material_missing',
    });
  });

  test('retains runtime worker-material handle hints across same-identity new-session remint', () => {
    const remintedSessionId = 'threshold-ed25519-runtime-retention-new-session';
    persistRuntimeHandleOnlySession({ signingWorkerId: 'signing-worker-a' });
    remintNewSessionWithoutMaterial({
      thresholdSessionId: remintedSessionId,
      signingGrantId: 'signing-grant-ed25519-runtime-retention-new-session',
      signingWorkerId: 'signing-worker-a',
    });

    const record = getStoredThresholdEd25519SessionRecordByThresholdSessionId(remintedSessionId);
    expect(record?.walletSessionJwt).toBe(
      fixtureEd25519WalletSessionJwt({
        label: 'reminted-new-session',
        sessionId: remintedSessionId,
        grantId: 'signing-grant-ed25519-runtime-retention-new-session',
      }),
    );
    expect(record?.clientVerifyingShareB64u).toBe('client-verifier');
    expect(record?.ed25519WorkerMaterialHandle).toBe('runtime-material-handle');
    expect(record?.ed25519WorkerMaterialBindingDigest).toBe('material-binding-digest');
    expect(record?.sealedWorkerMaterialRef || '').toBe('');
    expect(record?.sealedWorkerMaterialB64u || '').toBe('');
    expect(record?.materialCreatedAtMs).toBe(1_800_000_000_000);
    expect(record?.keyVersion).toBe('threshold-ed25519-hss-v1');
    expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
      kind: 'material_hint_unvalidated',
      reason: 'worker_material_unvalidated',
    });
  });

  test('retains sealed worker-material facts when signing-worker identity changes', () => {
    persistMaterialBackedSession({ signingWorkerId: 'signing-worker-a' });
    remintSessionWithoutMaterial({ signingWorkerId: 'signing-worker-b' });

    const record = getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId);
    expect(record?.walletSessionJwt).toBe(remintedWalletSessionJwt);
    expect(record?.clientVerifyingShareB64u).toBe('client-verifier');
    expect(record?.ed25519WorkerMaterialHandle).toBe('runtime-material-handle');
    expect(record?.ed25519WorkerMaterialBindingDigest).toBe('material-binding-digest');
    expect(record?.sealedWorkerMaterialRef).toBe('sealed-material-ref');
    expect(record?.sealedWorkerMaterialB64u).toBe('sealed-material');
    expect(record?.materialKeyId).toBe('material-key-id');
    expect(record?.materialCreatedAtMs).toBe(1_800_000_000_000);
    expect(record?.keyVersion).toBe('threshold-ed25519-hss-v1');
    expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
      kind: 'restore_available',
      reason: 'loaded_material_missing',
    });
  });
});
