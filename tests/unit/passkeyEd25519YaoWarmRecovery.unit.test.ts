import { expect, test } from '@playwright/test';
import { configureIndexedDB } from '../../packages/wallet/src/core/indexedDB';
import { PASSKEY_PRF_KEK_VERSION_V1 } from '@shared/passkey-custody';
import type { CurrentEd25519SealedSessionRecord } from '../../packages/wallet/src/core/signingEngine/session/persistence/sealedSessionStore';
import {
  requirePasskeyEd25519RestoreAuthorization,
  resolvePasskeyEd25519YaoExportContextWithRuntimeV1,
} from '../../packages/wallet/src/core/signingEngine/session/passkey/ed25519YaoWarmRecovery';
import {
  type WalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  parseWalletAuthMethodId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { buildPasskeyEd25519SealedSessionRecordFixture } from './helpers/sealedSigningSession.fixtures';
import {
  buildMpcMaterialActivationRefFixture,
  buildWalletAuthAuthorityRefForAuthorityFixture,
} from './helpers/ecdsaMaterialRef.fixtures';
import {
  buildLinkedDeviceManagementAuthorityFixture,
  linkedDevicePermissionsForManagementFixture,
} from './helpers/linkedDeviceManagement.fixtures';
import { passkeyCustodyEnvelope } from './helpers/passkeyCustodyEnvelope.fixtures';
import type { WalletSessionAuthorizationExactActiveReadResult } from '../../packages/wallet/src/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';

const NOW_MS = 1_900_000_000_000;
const WALLET_ID = 'wallet:expiry-boundary';
const NEAR_ACCOUNT_ID = 'wallet-expiry-boundary.testnet';
const THRESHOLD_SESSION_ID = 'threshold-session-expiry-boundary';
const RELAYER_URL = 'https://relay.example.test';
const DEFAULT_AUTH_METHOD_ID = 'wallet-auth-method:ed25519-sealed-runtime';

if (typeof indexedDB === 'undefined') {
  configureIndexedDB({ mode: 'disabled' });
}

function requireFixture<T>(result: { ok: true; value: T } | { ok: false; error: unknown }): T {
  if (!result.ok) throw new Error('invalid exact Passkey authority fixture');
  return result.value;
}

function exactPasskeyAuthorityForRecord(
  record: CurrentEd25519SealedSessionRecord,
  walletAuthMethodId = DEFAULT_AUTH_METHOD_ID,
): WalletAuthAuthority {
  return {
    walletId: requireFixture(parseWalletId(record.walletId)),
    factor: {
      kind: 'passkey',
      credentialIdB64u: requireFixture(
        parseWebAuthnCredentialIdB64u(record.ed25519Restore.credentialIdB64u),
      ),
    },
    verifier: {
      kind: 'webauthn',
      rpId: requireFixture(parseWebAuthnRpId(record.ed25519Restore.rpId)),
    },
    bindingId: requireFixture(parseWalletAuthMethodId(walletAuthMethodId)),
  };
}

function exactPasskeyAuthorityRefForRecord(
  record: CurrentEd25519SealedSessionRecord,
  walletAuthMethodId = DEFAULT_AUTH_METHOD_ID,
): WalletAuthAuthorityRef {
  return buildWalletAuthAuthorityRefForAuthorityFixture(
    exactPasskeyAuthorityForRecord(record, walletAuthMethodId),
  );
}

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

async function buildWarmFixture(input: {
  readonly label: string;
  readonly recordExpiresAtMs: number;
  readonly authorizationExpiresAtMs: number;
  readonly thresholdSessionId: string;
}) {
  const materialActivation = buildMpcMaterialActivationRefFixture(
    `ed25519-warm-${input.label}`,
    WALLET_ID,
  );
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: `ed25519-warm-${input.label}`,
    permissions: linkedDevicePermissionsForManagementFixture(),
    provenance: 'wallet_registration',
    keyFamily: 'ed25519',
    materialActivation,
    expiresAtMs: input.authorizationExpiresAtMs,
    identity: {
      walletId: WALLET_ID,
      authorityId: `authority:ed25519-warm-${input.label}`,
      walletAuthMethodId: `wallet-auth-method:ed25519-warm-${input.label}`,
      rpId: 'wallet.example.test',
    },
  });
  const record = buildPasskeyEd25519SealedSessionRecordFixture({
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: `near-ed25519-key:${input.label}`,
    thresholdSessionId: input.thresholdSessionId,
    materialActivation,
    credentialIdB64u: String(fixture.authMethod.credentialIdB64u),
    expiresAtMs: input.recordExpiresAtMs,
    remainingUses: 1,
  });
  const walletAuthMethodId = String(fixture.authMethod.walletAuthMethodId);
  const authorization: Extract<
    WalletSessionAuthorizationExactActiveReadResult,
    { readonly kind: 'found' }
  > = {
    kind: 'found',
    record: fixture.activeWalletSession,
    operationCredential: fixture.operationCredential,
  };
  return { fixture, record, authorization, walletAuthMethodId };
}

function selectedWarmAuthority(
  fixture: Awaited<ReturnType<typeof buildLinkedDeviceManagementAuthorityFixture>>,
) {
  return {
    kind: 'resolved' as const,
    selection: fixture.selection,
    authMethod: fixture.authMethod,
    authority: fixture.authority,
    signerMaterials: [],
    exportRoot: null,
  };
}

async function unexpectedAuthorizationRead(): Promise<never> {
  throw new Error('expired or exhausted material must not read exact Wallet Session authorization');
}

async function unexpectedSelectedAuthorityRead(): Promise<never> {
  throw new Error('expired or exhausted material must not resolve selected Wallet Authority');
}

async function missingPasskeyCustodyEnvelope(): Promise<null> {
  return null;
}

async function resolveRecord(
  record: CurrentEd25519SealedSessionRecord,
  subjectThresholdSessionId = THRESHOLD_SESSION_ID,
) {
  let recoveryBootstrapCalls = 0;
  const result = await resolvePasskeyEd25519YaoExportContextWithRuntimeV1(
    {
      subject: {
        kind: 'owner_sealed_runtime',
        walletId: WALLET_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: record.ed25519Restore.nearEd25519SigningKeyId,
        signerSlot: 1,
        thresholdSessionId: subjectThresholdSessionId,
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
      readPasskeyCustodySessionEnvelope: missingPasskeyCustodyEnvelope,
      resolveSelectedWalletAuthority: unexpectedSelectedAuthorityRead,
      readExactWalletSessionAuthorization: unexpectedAuthorizationRead,
      resolveExactPasskeyWalletAuthAuthorityRef: async () =>
        exactPasskeyAuthorityRefForRecord(record),
      nowMs: () => NOW_MS,
    },
  );
  return { result, recoveryBootstrapCalls };
}

async function warmBootstrapResponse(args: {
  readonly record: CurrentEd25519SealedSessionRecord;
  readonly authorization: Extract<
    WalletSessionAuthorizationExactActiveReadResult,
    { readonly kind: 'found' }
  >;
  readonly capabilityThresholdSessionId: string;
  readonly capabilityAccountId?: string;
  readonly materialActivation?: MpcMaterialActivationRef;
  readonly responseThresholdSessionId?: string;
}): Promise<Record<string, unknown>> {
  const restore = args.record.ed25519Restore;
  return {
    kind: 'router_ab_ed25519_yao_v2_session_bootstrap_v1',
    walletId: args.record.walletId,
    nearAccountId: restore.nearAccountId,
    nearEd25519SigningKeyId: restore.nearEd25519SigningKeyId,
    signerSlot: restore.signerSlot,
    thresholdSessionId: args.responseThresholdSessionId ?? args.record.thresholdSessionIds.ed25519,
    walletSessionId: String(args.authorization.operationCredential.walletSessionId),
    quotaId: String(args.authorization.record.quotaId),
    signingWorkerId: restore.relayerKeyId,
    thresholdExpiresAtMs: args.authorization.record.expiresAtMs,
    participantIds: [...restore.participantIds],
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
      registrationContinuity: {
        kind: 'recovery',
        activationTranscript: [1],
      },
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

test('warm recovery rejects a threshold session substitution before authorization lookup', async () => {
  const resolved = await resolveRecord(
    buildSealedRecord({ expiresAtMs: NOW_MS + 60_000, remainingUses: 1 }),
    'threshold-session-foreign',
  );

  expect(resolved.result).toEqual({
    kind: 'capability_recovery_required',
    reason: 'sealed_session_missing',
  });
  expect(resolved.recoveryBootstrapCalls).toBe(0);
});

test('passkey sealed restore uses the current active authorization bearer', async () => {
  const warm = await buildWarmFixture({
    label: 'current-token',
    recordExpiresAtMs: NOW_MS + 60_000,
    authorizationExpiresAtMs: NOW_MS + 60_000,
    thresholdSessionId: THRESHOLD_SESSION_ID,
  });
  const exactAuthorization = {
    kind: 'found' as const,
    record: warm.fixture.activeWalletSession,
    operationCredential: warm.fixture.operationCredential,
  };

  const resolved = await requirePasskeyEd25519RestoreAuthorization({
    record: warm.record,
    authorizationRead: exactAuthorization,
    expectedAuthorityRef: exactPasskeyAuthorityRefForRecord(warm.record, warm.walletAuthMethodId),
    expectedAuthorityId: warm.fixture.authority.authorityId,
    expectedAuthorityDigestB64u: warm.fixture.authority.authorityDigestB64u,
    expectedAuthorityRevocationEpoch: warm.fixture.authority.revocationEpoch,
    nowMs: NOW_MS,
  });

  expect(warm.record).not.toHaveProperty('walletSessionJwt');
  expect(warm.record.ed25519Restore).not.toHaveProperty('walletSessionJwt');
  expect(resolved?.operationCredential.token).toBe(warm.fixture.operationCredential.token);
});

test('warm recovery accepts a renewed Wallet Session credential with the owner custody envelope', async () => {
  const warm = await buildWarmFixture({
    label: 'renewed',
    recordExpiresAtMs: NOW_MS + 60_000,
    authorizationExpiresAtMs: NOW_MS + 120_000,
    thresholdSessionId: THRESHOLD_SESSION_ID,
  });
  const { record, authorization, fixture, walletAuthMethodId } = warm;
  const response = await warmBootstrapResponse({
    record,
    authorization,
    capabilityThresholdSessionId: record.thresholdSessionIds.ed25519,
    responseThresholdSessionId: record.thresholdSessionIds.ed25519,
  });
  expect(response.thresholdExpiresAtMs).toBeGreaterThan(record.expiresAtMs);

  let requestBody: Record<string, unknown> | null = null;
  let requestAuthorization = '';
  let exactReadInput: {
    readonly walletId: string;
    readonly authorityId: string;
    readonly authMethodId: string;
  } | null = null;
  const resolved = await resolvePasskeyEd25519YaoExportContextWithRuntimeV1(
    {
      subject: {
        kind: 'owner_sealed_runtime',
        walletId: record.walletId,
        nearAccountId: record.ed25519Restore.nearAccountId,
        nearEd25519SigningKeyId: record.ed25519Restore.nearEd25519SigningKeyId,
        signerSlot: record.ed25519Restore.signerSlot,
        thresholdSessionId: record.thresholdSessionIds.ed25519,
        materialActivation: record.ed25519Restore.materialActivation,
      },
      relayerUrl: RELAYER_URL,
      fetch: async (_input, init) => {
        requestBody = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
        requestAuthorization = String(new Headers(init?.headers).get('Authorization') || '');
        return new Response(JSON.stringify(response), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      },
    },
    {
      readExactEd25519SealedSession: async () => record,
      readPasskeyCustodySessionEnvelope: async () =>
        passkeyCustodyEnvelope({
          walletId: record.walletId,
          envelopeId: `passkey-envelope-${record.walletId}`,
          factor: {
            kind: 'passkey',
            rpId: record.ed25519Restore.rpId,
            credentialIdB64u: record.ed25519Restore.credentialIdB64u,
            kekVersion: PASSKEY_PRF_KEK_VERSION_V1,
          },
        }),
      resolveExactPasskeyWalletAuthAuthorityRef: async () =>
        exactPasskeyAuthorityRefForRecord(record, walletAuthMethodId),
      resolveSelectedWalletAuthority: async () => selectedWarmAuthority(fixture),
      readExactWalletSessionAuthorization: async (readInput) => {
        exactReadInput = {
          walletId: String(readInput.walletId),
          authorityId: String(readInput.authorityId),
          authMethodId: String(readInput.authMethodId),
        };
        return {
          kind: 'found',
          record: fixture.activeWalletSession,
          operationCredential: fixture.operationCredential,
        };
      },
      nowMs: () => NOW_MS,
    },
  );

  expect(requestBody?.thresholdSessionId).toBe(record.thresholdSessionIds.ed25519);
  expect(requestAuthorization).toBe(`Bearer ${fixture.operationCredential.token}`);
  expect(exactReadInput).toEqual({
    walletId: record.walletId,
    authorityId: String(fixture.authority.authorityId),
    authMethodId: walletAuthMethodId,
  });
  expect(resolved.kind).toBe('ready');
  if (resolved.kind !== 'ready') throw new Error('warm recovery did not resolve');
  expect(resolved.context.walletCustodyEnvelope.walletId).toBe(record.walletId);
  expect(resolved.context.walletCustodyEnvelope.binding.kind).toBe('wallet_custody_seed_v1');
});

test('warm recovery fails closed when the selected exact Wallet Session is unavailable', async () => {
  const warm = await buildWarmFixture({
    label: 'missing-exact-session',
    recordExpiresAtMs: NOW_MS + 60_000,
    authorizationExpiresAtMs: NOW_MS + 60_000,
    thresholdSessionId: THRESHOLD_SESSION_ID,
  });
  let recoveryBootstrapCalls = 0;
  const result = await resolvePasskeyEd25519YaoExportContextWithRuntimeV1(
    {
      subject: {
        kind: 'owner_sealed_runtime',
        walletId: warm.record.walletId,
        nearAccountId: warm.record.ed25519Restore.nearAccountId,
        nearEd25519SigningKeyId: warm.record.ed25519Restore.nearEd25519SigningKeyId,
        signerSlot: warm.record.ed25519Restore.signerSlot,
        thresholdSessionId: warm.record.thresholdSessionIds.ed25519,
        materialActivation: warm.record.ed25519Restore.materialActivation,
      },
      relayerUrl: RELAYER_URL,
      fetch: async () => {
        recoveryBootstrapCalls += 1;
        throw new Error('missing exact session must not invoke Yao recovery');
      },
    },
    {
      readExactEd25519SealedSession: async () => warm.record,
      readPasskeyCustodySessionEnvelope: missingPasskeyCustodyEnvelope,
      resolveExactPasskeyWalletAuthAuthorityRef: async () =>
        exactPasskeyAuthorityRefForRecord(warm.record, warm.walletAuthMethodId),
      resolveSelectedWalletAuthority: async () => selectedWarmAuthority(warm.fixture),
      readExactWalletSessionAuthorization: async () => ({ kind: 'missing' as const }),
      nowMs: () => NOW_MS,
    },
  );

  expect(result).toEqual({
    kind: 'capability_recovery_required',
    reason: 'wallet_session_expired',
  });
  expect(recoveryBootstrapCalls).toBe(0);
});

test('warm recovery rejects identity, material, and extra-field substitutions', async () => {
  const warm = await buildWarmFixture({
    label: 'substitution',
    recordExpiresAtMs: NOW_MS + 60_000,
    authorizationExpiresAtMs: NOW_MS + 60_000,
    thresholdSessionId: THRESHOLD_SESSION_ID,
  });
  const { record, authorization, fixture, walletAuthMethodId } = warm;
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
    {
      label: 'extra-field',
      response: {
        ...(await warmBootstrapResponse({
          record,
          authorization,
          capabilityThresholdSessionId: record.thresholdSessionIds.ed25519,
        })),
        authority: {},
      },
    },
  ];

  for (const substitution of substitutions) {
    await expect(
      resolvePasskeyEd25519YaoExportContextWithRuntimeV1(
        {
          subject: {
            kind: 'owner_sealed_runtime',
            walletId: record.walletId,
            nearAccountId: record.ed25519Restore.nearAccountId,
            nearEd25519SigningKeyId: record.ed25519Restore.nearEd25519SigningKeyId,
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
          readPasskeyCustodySessionEnvelope: missingPasskeyCustodyEnvelope,
          resolveExactPasskeyWalletAuthAuthorityRef: async () =>
            exactPasskeyAuthorityRefForRecord(record, walletAuthMethodId),
          resolveSelectedWalletAuthority: async () => selectedWarmAuthority(fixture),
          readExactWalletSessionAuthorization: async () => ({
            kind: 'found',
            record: fixture.activeWalletSession,
            operationCredential: fixture.operationCredential,
          }),
          nowMs: () => NOW_MS,
        },
      ),
      substitution.label,
    ).rejects.toThrow();
  }
});
