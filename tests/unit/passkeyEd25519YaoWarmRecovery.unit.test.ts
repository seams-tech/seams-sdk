import { expect, test } from '@playwright/test';
import { configureIndexedDB } from '../../packages/wallet/src/core/indexedDB';
import type { CurrentEd25519SealedSessionRecord } from '../../packages/wallet/src/core/signingEngine/session/persistence/sealedSessionStore';
import {
  requirePasskeyEd25519RestoreAuthorization,
  resolvePasskeyEd25519YaoExportContextWithRuntimeV1,
} from '../../packages/wallet/src/core/signingEngine/session/passkey/ed25519YaoWarmRecovery';
import { buildActiveLinkedDeviceExecutionBundleV1 } from '../../packages/wallet/src/core/signingEngine/session/lanes/linkedDeviceExecutionBundle';
import {
  rememberEd25519YaoClientRootEnvelopeV1,
} from '../../packages/wallet/src/core/signingEngine/session/passkey/passkeyCustodySessionCache';
import {
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  buildFullOwnerDelegatedWalletAuthorityV1,
} from '@shared/authorization/delegatedAuthority';
import {
  buildActiveWalletSessionAuthorizationProjection,
} from '../../packages/wallet/src/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parseEd25519PublicKeyB64u,
} from '@shared/passkey-custody/primitives';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  PASSKEY_PRF_KEK_VERSION_V1,
  parsePasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import { buildR103ActiveExecutionFixture } from './helpers/deviceLinkContracts.fixtures';
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

if (typeof indexedDB === 'undefined') {
  configureIndexedDB({ mode: 'disabled' });
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

async function unexpectedAuthorizationRead(): Promise<never> {
  throw new Error('expired or exhausted material must not read Wallet Session authorization');
}

async function resolveRecord(record: CurrentEd25519SealedSessionRecord) {
  let recoveryBootstrapCalls = 0;
  const result = await resolvePasskeyEd25519YaoExportContextWithRuntimeV1(
    {
      subject: {
        kind: 'owner_sealed_runtime',
        walletId: WALLET_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: record.ed25519Restore.nearEd25519SigningKeyId,
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
      registrationContinuity: {
        kind: 'recovery',
        activationTranscript: [1],
      },
    },
  };
}

async function delegatedExportFixture() {
  const fixture = await buildR103ActiveExecutionFixture();
  const initialBundle = await buildActiveLinkedDeviceExecutionBundleV1({
    approval: fixture.deviceLink.approval,
    targetPreparation: fixture.targetCredential.preparation,
    targetCredentialRegistration: fixture.targetCredential.registration,
    provisioningDeliveries: fixture.provisioning.deliveries,
    enrollmentReceipt: fixture.deviceLink.receipt,
    walletSessionDelivery: fixture.walletSession,
  });
  const execution = initialBundle.orderedExecutions[0];
  if (!execution || execution.keyFamily !== 'ed25519') {
    throw new Error('delegated export fixture requires one Ed25519 execution');
  }
  const targetPreparation = {
    ...initialBundle.targetPreparation,
    ed25519ExportRoot: {
      kind: 'linked_device_ed25519_export_root_preparation_v1' as const,
      walletKeyId: execution.walletKeyId,
      applicationBindingDigestB64u: parseDigestB64u(
        base64UrlEncode(new Uint8Array(32).fill(21)),
      ),
      registeredPublicKeyB64u: parseEd25519PublicKeyB64u(execution.job.registeredPublicKeyB64u),
      revocationEpoch: initialBundle.revocationEpoch,
    },
  };
  const bundle = {
    ...initialBundle,
    targetPreparation,
    permission: buildFullOwnerDelegatedWalletAuthorityV1(),
    remainingUses: 1,
    issuedAtMs: NOW_MS,
    activatedAtMs: NOW_MS,
    expiresAtMs: NOW_MS + 60_000,
  };
  const ownerEnrollment = bundle.targetPreparation.ownerEnrollment.registration;
  if (!ownerEnrollment || bundle.targetCredentialRegistration.targetFactor.kind !== 'passkey_prf') {
    throw new Error('delegated export fixture is missing the owner Passkey registration');
  }
  const rootIdentity = {
    walletId: String(bundle.walletId),
    linkSessionId: String(bundle.linkSessionId),
    walletKeyId: String(execution.walletKeyId),
    enrollmentId: String(bundle.enrollmentId),
    deviceId: String(bundle.deviceId),
    applicationBindingDigestB64u: String(targetPreparation.ed25519ExportRoot.applicationBindingDigestB64u),
    registeredPublicKeyB64u: String(targetPreparation.ed25519ExportRoot.registeredPublicKeyB64u),
    revocationEpoch: targetPreparation.ed25519ExportRoot.revocationEpoch,
    targetFactor: {
      kind: 'passkey_prf' as const,
      rpId: String(ownerEnrollment.rpId),
      credentialIdB64u: String(
        bundle.targetCredentialRegistration.webauthnRegistration?.credentialIdB64u,
      ),
    },
  };
  const rootEnvelope = parsePasskeyCustodyEnvelopeRecord({
    kind: 'wallet_custody_envelope_v2',
    envelopeId: 'delegated-ed25519-root-envelope',
    walletId: rootIdentity.walletId,
    binding: {
      kind: 'ed25519_yao_client_root_v1',
      linkSessionId: rootIdentity.linkSessionId,
      walletKeyId: rootIdentity.walletKeyId,
      targetFactor: { kind: rootIdentity.targetFactor.kind },
      applicationBindingDigestB64u: rootIdentity.applicationBindingDigestB64u,
      registeredPublicKeyB64u: rootIdentity.registeredPublicKeyB64u,
      enrollmentId: rootIdentity.enrollmentId,
      deviceId: rootIdentity.deviceId,
      revocationEpoch: rootIdentity.revocationEpoch,
    },
    factor: {
      kind: 'passkey',
      rpId: rootIdentity.targetFactor.rpId,
      credentialIdB64u: rootIdentity.targetFactor.credentialIdB64u,
      kekVersion: PASSKEY_PRF_KEK_VERSION_V1,
    },
    envelopeVersion: 'wallet_custody_envelope_v2',
    envelopeRevision: 1,
    nonceB64u: base64UrlEncode(new Uint8Array(12).fill(3)),
    sealedCustodySecretB64u: base64UrlEncode(new Uint8Array(64).fill(4)),
    ciphertextDigestB64u: base64UrlEncode(new Uint8Array(32).fill(5)),
    aadHashB64u: base64UrlEncode(new Uint8Array(32).fill(6)),
    lifecycle: { state: 'active', activatedAtMs: NOW_MS },
    createdAtMs: NOW_MS,
    updatedAtMs: NOW_MS,
  });
  await rememberEd25519YaoClientRootEnvelopeV1({ identity: rootIdentity, envelope: rootEnvelope });
  const authority = buildPasskeyWalletAuthAuthority({
    walletId: String(bundle.walletId),
    rpId: rootIdentity.targetFactor.rpId,
    credentialIdB64u: rootIdentity.targetFactor.credentialIdB64u,
  });
  const walletSessionId = parseWalletSessionId(String(bundle.walletSessionId));
  const quotaId = parseMpcWalletSigningQuotaId(String(bundle.quotaId));
  if (!walletSessionId.ok || !quotaId.ok) throw new Error('delegated export fixture ids are invalid');
  const authorization = buildActiveWalletSessionAuthorizationProjection({
    walletId: bundle.walletId,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    walletSessionTokens: {
      kind: 'near_ed25519',
      ed25519: {
        authorizationId: String(bundle.authorizationId),
        walletSessionToken: 'opaque-linked-wallet-session-jwt',
        thresholdSessionId: 'threshold-linked-target',
      },
    },
    authMethod: 'passkey',
    authority: await walletAuthAuthorityRef({ authority }),
    expiresAtMs: NOW_MS + 60_000,
  });
  const source = execution.job.source;
  const sourceThresholdSessionId = 'threshold-owner-source';
  const capability = {
    kind: 'router_ab_ed25519_yao_active_capability_v1',
    materialActivation: routerAbMpcMaterialActivationRefToWire(source.materialActivation),
    activeCapabilityBinding: new Array<number>(32).fill(8),
    registeredPublicKey: Array.from(base64UrlDecode(execution.job.registeredPublicKeyB64u)),
    nearAccountId: String(bundle.nearAccountId),
    applicationBinding: {
      wallet_id: String(bundle.walletId),
      near_ed25519_signing_key_id: String(execution.job.nearEd25519SigningKeyId),
      signing_root_id: 'project:r103:test',
      key_creation_signer_slot: execution.job.keyCreationSignerSlot,
    },
    participantIds: [...source.ownerParticipantContinuity.participantIds],
    runtimePolicyScope: {
      orgId: 'org:r103',
      projectId: 'project:r103',
      envId: 'test',
      signingRootVersion: 'v1',
    },
    lifecycle: {
      lifecycleId: 'lifecycle:r103',
      rootShareEpoch: 'v1',
      accountId: String(bundle.walletId),
      thresholdSessionId: sourceThresholdSessionId,
      signerSetId: 'near-primary',
      signingWorkerId: String(source.ownerParticipantContinuity.signingWorkerId),
    },
    stateEpoch: 1,
    registrationContinuity: { kind: 'recovery', activationTranscript: [1] },
  };
  const response = {
    kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_v1',
    walletId: String(bundle.walletId),
    nearAccountId: String(bundle.nearAccountId),
    nearEd25519SigningKeyId: String(execution.job.nearEd25519SigningKeyId),
    signerSlot: execution.job.keyCreationSignerSlot,
    thresholdSessionId: sourceThresholdSessionId,
    walletSessionId: String(bundle.walletSessionId),
    quotaId: String(bundle.quotaId),
    signingWorkerId: String(source.ownerParticipantContinuity.signingWorkerId),
    thresholdExpiresAtMs: NOW_MS + 60_000,
    participantIds: [...source.ownerParticipantContinuity.participantIds],
    runtimePolicyScope: capability.runtimePolicyScope,
    routerAbNormalSigning: {
      kind: 'router_ab_ed25519_normal_signing_v1',
      signingWorkerId: String(source.ownerParticipantContinuity.signingWorkerId),
    },
    capability,
  };
  return {
    bundle,
    execution,
    authorization,
    response,
    sourceMaterialActivation: source.materialActivation,
    targetMaterialActivation: execution.materialActivation,
    sourceThresholdSessionId,
    subject: {
      kind: 'delegated_active_bundle' as const,
      walletId: String(bundle.walletId),
      nearAccountId: String(bundle.nearAccountId),
      nearEd25519SigningKeyId: String(execution.job.nearEd25519SigningKeyId),
      signerSlot: execution.job.keyCreationSignerSlot,
      targetMaterialActivation: execution.materialActivation,
      sourceMaterialActivation: source.materialActivation,
      bundle,
      sourceOwnerCapability: source,
    },
  };
}

type DelegatedExportFixture = Awaited<ReturnType<typeof delegatedExportFixture>>;

async function resolveDelegatedExportFixture(args: {
  readonly fixture: DelegatedExportFixture;
  readonly subject: DelegatedExportFixture['subject'];
  readonly response: Record<string, unknown>;
}): Promise<{
  readonly resolved: Awaited<ReturnType<typeof resolvePasskeyEd25519YaoExportContextWithRuntimeV1>>;
  readonly requestBody: Record<string, unknown> | null;
}> {
  let requestBody: Record<string, unknown> | null = null;
  const resolved = await resolvePasskeyEd25519YaoExportContextWithRuntimeV1(
    {
      subject: args.subject,
      relayerUrl: RELAYER_URL,
      fetch: async (_input, init) => {
        requestBody = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
        return new Response(JSON.stringify(args.response), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      },
    },
    {
      readExactEd25519SealedSession: async () => null,
      readActiveWalletSessionAuthorization: async () => ({
        kind: 'found',
        projection: args.fixture.authorization,
      }),
      nowMs: () => NOW_MS,
    },
  );
  return { resolved, requestBody };
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
  expect(resolved).toEqual({
    kind: 'capability_recovery_required',
    reason: 'wallet_custody_envelope_missing',
  });
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

test('delegated export bootstraps from the owner source lane and rejects target substitution', async () => {
  const fixture = await delegatedExportFixture();
  const resolved = await resolveDelegatedExportFixture({
    fixture,
    subject: fixture.subject,
    response: fixture.response,
  });
  expect(resolved.requestBody?.thresholdSessionId).toBe('threshold-linked-target');
  expect(resolved.resolved.kind).toBe('ready');
  if (resolved.resolved.kind === 'ready') {
    expect(resolved.resolved.context.material.capability.materialActivation).toEqual(
      fixture.sourceMaterialActivation,
    );
    expect(resolved.resolved.context.material.capability.lifecycle.thresholdSessionId).toBe(
      fixture.sourceThresholdSessionId,
    );
  }

  await expect(
    resolveDelegatedExportFixture({
      fixture,
      subject: {
        ...fixture.subject,
        sourceMaterialActivation: fixture.targetMaterialActivation,
      },
      response: fixture.response,
    }),
  ).rejects.toThrow();

  await expect(
    resolveDelegatedExportFixture({
      fixture,
      subject: fixture.subject,
      response: {
        ...fixture.response,
        capability: {
          ...fixture.response.capability,
          materialActivation: routerAbMpcMaterialActivationRefToWire(
            fixture.targetMaterialActivation,
          ),
        },
      },
    }),
  ).rejects.toThrow();
});
