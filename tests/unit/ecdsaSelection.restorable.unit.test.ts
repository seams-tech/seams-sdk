import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import { ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import type { RouterAbEcdsaHssNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaHss';
import { toAccountId } from '@/core/types/accountIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { resolveEvmFamilyEcdsaSigningSelection } from '@/core/signingEngine/flows/signEvmFamily/ecdsaSelection';
import {
  laneCandidateAuthMethod,
  type EcdsaLaneCandidate,
} from '@/core/signingEngine/session/identity/laneIdentity';
import type { EvmFamilyEcdsaSigningSelectionDeps } from '@/core/signingEngine/flows/signEvmFamily/ecdsaSelection';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  buildVerifiedEcdsaPublicFacts,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { buildReauthAnchorIdentity } from '@/core/signingEngine/session/operationState/transactionState';
import {
  buildEvmTransactionSigningLane,
  buildTempoTransactionSigningLane,
} from '@/core/signingEngine/session/operationState/lanes';
import { exactSigningLaneIdentity } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { buildFreshStepUpRequired } from '@/core/signingEngine/session/operationState/stepUpFreshness';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import {
  clearRouterAbEcdsaHssWorkerMaterialRuntimeValidation,
  markRouterAbEcdsaHssWorkerMaterialRuntimeValidated,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';

type EmailOtpEcdsaSessionRecord = Extract<ThresholdEcdsaSessionRecord, { source: 'email_otp' }>;
type PasskeyEcdsaSessionRecord = Exclude<ThresholdEcdsaSessionRecord, { source: 'email_otp' }>;

type DirectEcdsaLaneCandidate = Extract<
  EcdsaLaneCandidate,
  {
    source: 'durable_sealed_record' | 'runtime_session_record' | 'runtime_and_durable' | 'unknown';
  }
>;

const chainTarget = {
  kind: 'evm' as const,
  namespace: 'eip155' as const,
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};

const tempoChainTarget = {
  kind: 'tempo' as const,
  chainId: 42431,
  networkSlug: 'tempo-testnet',
};

const walletId = toWalletId('restorable.testnet');
const validThresholdEcdsaPublicKeyB64u = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const validRelayerEcdsaPublicKeyB64u = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const applicationBindingDigestB64u = base64UrlEncode(new Uint8Array(32).fill(7));
const contextBinding32B64u = base64UrlEncode(new Uint8Array(32).fill(8));
const stateBlobB64u = base64UrlEncode(new Uint8Array(64).fill(9));
const passkeyCredentialIdB64u = 'restorable-passkey-credential';
const rpId = toRpId('example.localhost');
const walletKeyId = 'wallet-key-restorable';
const passkeyAuth = {
  kind: 'passkey',
  rpId,
  credentialIdB64u: passkeyCredentialIdB64u,
} as const;
const emailOtpAuth = {
  kind: 'email_otp',
  providerSubjectId: 'google:restorable',
} as const;

function makeWalletSessionJwt(args: {
  thresholdSessionId: string;
  signingGrantId: string;
}): string {
  const encode = (value: unknown) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode({
    kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    exp: 1_900_000_000,
  })}.signature`;
}

function ethereumAddress20B64u(address: string): string {
  const hex = address.replace(/^0x/, '');
  const bytes = new Uint8Array(hex.match(/.{2}/g)?.map((part) => Number.parseInt(part, 16)) || []);
  return base64UrlEncode(bytes);
}

function routerAbEcdsaHssNormalSigningStateForCandidate(
  input: EcdsaLaneCandidate,
): RouterAbEcdsaHssNormalSigningStateV1 {
  return {
    kind: 'router_ab_ecdsa_hss_normal_signing_v1',
    scope: {
      wallet_key_id: input.key.walletKeyId,
      wallet_id: input.walletId,
      ecdsa_threshold_key_id: input.key.ecdsaThresholdKeyId,
      signing_root_id: input.key.signingRootId,
      signing_root_version: input.key.signingRootVersion,
      context: {
        application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
      },
      public_identity: {
        context_binding_b64u: contextBinding32B64u,
        client_public_key33_b64u: validThresholdEcdsaPublicKeyB64u,
        server_public_key33_b64u: validRelayerEcdsaPublicKeyB64u,
        threshold_public_key33_b64u: validThresholdEcdsaPublicKeyB64u,
        ethereum_address20_b64u: ethereumAddress20B64u(input.key.thresholdOwnerAddress),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      signing_worker: {
        server_id: 'signing-worker-restorable',
        key_epoch: 'worker-epoch-restorable',
        recipient_encryption_key:
          'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      activation_epoch: input.thresholdSessionId,
    },
  };
}

function candidate(state: EcdsaLaneCandidate['state']): DirectEcdsaLaneCandidate {
  return {
    kind: 'lane_candidate',
    auth: passkeyAuth,
    curve: 'ecdsa',
    chain: 'evm',
    walletId,
    key: buildEvmFamilyEcdsaKeyIdentity({
      walletId,
      walletKeyId,
      ecdsaThresholdKeyId: 'ek-restorable',
      signingRootId: 'proj_local:dev',
      signingRootVersion: 'default',
      participantIds: [1, 2],
      thresholdOwnerAddress: `0x${'aa'.repeat(20)}`,
    }),
    keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-restorable'),
    chainTarget,
    signingGrantId: 'wsess-restorable',
    thresholdSessionId: 'tsess-restorable',
    state,
    remainingUses: null,
    expiresAtMs: null,
    updatedAtMs: Date.now(),
    source: 'durable_sealed_record',
  };
}

function sharedTempoCandidate(): EcdsaLaneCandidate {
  const base = candidate('deferred');
  return {
    ...base,
    chain: 'tempo',
    chainTarget: tempoChainTarget,
    source: 'evm_family_shared_key',
    sourceChainTarget: chainTarget,
  };
}

function emailOtpCandidate(state: EcdsaLaneCandidate['state']): EcdsaLaneCandidate {
  return {
    ...candidate(state),
    auth: emailOtpAuth,
    source: 'runtime_session_record',
  };
}

function emailOtpSharedTempoCandidate(): EcdsaLaneCandidate {
  return {
    ...sharedTempoCandidate(),
    auth: emailOtpAuth,
  };
}

function emailOtpSharedEvmCandidateFromTempo(): EcdsaLaneCandidate {
  return {
    ...emailOtpCandidate('ready'),
    source: 'evm_family_shared_key',
    sourceChainTarget: tempoChainTarget,
  };
}

function reauthAnchorForCandidate(input: EcdsaLaneCandidate) {
  const buildLane =
    input.chainTarget.kind === 'tempo'
      ? buildTempoTransactionSigningLane
      : buildEvmTransactionSigningLane;
  const lane = buildLane(
    laneCandidateAuthMethod(input) === 'email_otp'
      ? {
          key: input.key,
          keyHandle: input.keyHandle,
          walletId: input.walletId,
          auth: emailOtpAuth,
          chainTarget: input.chainTarget,
          signingGrantId: SigningSessionIds.signingGrant(
            input.signingGrantId,
          ),
          thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(input.thresholdSessionId),
          retention: 'session',
          sessionOrigin: 'per_operation',
        }
      : {
          key: input.key,
          keyHandle: input.keyHandle,
          walletId: input.walletId,
          auth: passkeyAuth,
          chainTarget: input.chainTarget,
          signingGrantId: SigningSessionIds.signingGrant(
            input.signingGrantId,
          ),
          thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(input.thresholdSessionId),
          storageSource: 'login',
        },
  );
  const laneIdentity = exactSigningLaneIdentity(lane);
  const freshness = buildFreshStepUpRequired({
    walletId: input.walletId,
    operationId: SigningSessionIds.signingOperation(`operation-${input.thresholdSessionId}`),
    operationFingerprint: SigningSessionIds.signingOperationFingerprint(
      `fingerprint-${input.thresholdSessionId}`,
    ),
    laneIdentity,
    projection: { kind: 'unavailable', reason: 'restored_record_has_no_projection' },
    expiry: { kind: 'unavailable', reason: 'restored_record_has_no_expiry' },
    provenance: {
      kind: 'restored_sealed_record_status',
      recordVersion: 'test-record',
      updatedAtMs: input.updatedAtMs || 1,
    },
    reason: 'threshold_session_exhausted',
  });
  return buildReauthAnchorIdentity({
    freshness,
    sourceState: {
      kind: 'reauth_anchor_source_state',
      availabilitySource: input.source === 'unknown' ? 'durable_sealed_record' : input.source,
      storeSource: laneCandidateAuthMethod(input) === 'email_otp' ? 'email_otp' : 'login',
      retention: laneCandidateAuthMethod(input) === 'email_otp' ? 'single_use' : 'session',
      remainingUses: input.remainingUses,
      expiry: freshness.expiry,
      projection: freshness.projection,
    },
  });
}

function selectionDeps(): EvmFamilyEcdsaSigningSelectionDeps {
  const missing = () => {
    throw new Error('missing exact material');
  };
  return {
    walletSignerStore: {
      getActiveWalletSignerForChainTarget: async () => null,
      listActiveWalletSigners: async () => [],
    } as EvmFamilyEcdsaSigningSelectionDeps['walletSignerStore'],
    getEmailOtpThresholdEcdsaSessionRecordForSigning: missing,
    getPasskeyThresholdEcdsaSessionRecordForSigning: missing,
    listThresholdEcdsaSessionRecordsForSigning: () => [],
    listThresholdEcdsaKeyRefsForSigning: () => [],
    getThresholdEcdsaSessionRecordByKey: () => null,
  };
}

function roleLocalReadyRecordForCandidate(
  input: EcdsaLaneCandidate,
  materialChainTarget: typeof chainTarget | typeof tempoChainTarget,
) {
  const publicFacts = buildEcdsaRoleLocalPublicFacts({
    walletId: input.walletId,
    walletKeyId: input.key.walletKeyId,
    chainTarget: materialChainTarget,
    keyHandle: input.keyHandle,
    ecdsaThresholdKeyId: input.key.ecdsaThresholdKeyId,
    signingRootId: input.key.signingRootId,
    signingRootVersion: input.key.signingRootVersion,
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: [1, 2],
    applicationBindingDigestB64u,
    contextBinding32B64u,
    hssClientSharePublicKey33B64u: validThresholdEcdsaPublicKeyB64u,
    relayerPublicKey33B64u: validRelayerEcdsaPublicKeyB64u,
    groupPublicKey33B64u: validThresholdEcdsaPublicKeyB64u,
    ethereumAddress: input.key.thresholdOwnerAddress,
  });
  return buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u,
    },
    publicFacts,
    authMethod:
      laneCandidateAuthMethod(input) === 'email_otp'
        ? buildEcdsaRoleLocalEmailOtpAuthMethod({
            authSubjectId: `google:${String(input.walletId)}`,
          })
        : buildEcdsaRoleLocalPasskeyAuthMethod({
            credentialIdB64u: passkeyCredentialIdB64u,
            rpId,
          }),
  });
}

function recordForChainTarget(
  input: EcdsaLaneCandidate,
  materialChainTarget: typeof chainTarget | typeof tempoChainTarget,
): PasskeyEcdsaSessionRecord {
  return markRuntimeValidated({
    walletId: input.walletId,
    authMetadata: { walletKeyId },
    chainTarget: materialChainTarget,
    relayerUrl: 'https://relay.example',
    keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-restorable'),
    ecdsaThresholdKeyId: input.key.ecdsaThresholdKeyId,
    signingRootId: input.key.signingRootId,
    signingRootVersion: input.key.signingRootVersion,
    relayerKeyId: 'rk-restorable',
    clientVerifyingShareB64u: validThresholdEcdsaPublicKeyB64u,
    ecdsaRoleLocalReadyRecord: roleLocalReadyRecordForCandidate(input, materialChainTarget),
    participantIds: [1, 2],
    ethereumAddress: `0x${'aa'.repeat(20)}`,
    verifiedPublicFacts: buildVerifiedEcdsaPublicFacts({
      keyHandle: input.keyHandle,
      publicKeyB64u: validThresholdEcdsaPublicKeyB64u,
      participantIds: [1, 2],
      thresholdOwnerAddress: `0x${'aa'.repeat(20)}`,
    }),
    runtimePolicyScope: {
      orgId: 'org',
      projectId: 'proj_local',
      envId: 'dev',
      signingRootVersion: input.key.signingRootVersion,
    },
    thresholdSessionKind: 'jwt',
    thresholdSessionId: input.thresholdSessionId,
    signingGrantId: input.signingGrantId,
    walletSessionJwt: makeWalletSessionJwt({
      thresholdSessionId: input.thresholdSessionId,
      signingGrantId: input.signingGrantId,
    }),
    expiresAtMs: Date.now() + 60_000,
    remainingUses: input.state === 'exhausted' ? 0 : 1,
    routerAbEcdsaHssNormalSigning: routerAbEcdsaHssNormalSigningStateForCandidate(input),
    thresholdEcdsaPublicKeyB64u: validThresholdEcdsaPublicKeyB64u,
    relayerVerifyingShareB64u: validRelayerEcdsaPublicKeyB64u,
    updatedAtMs: Date.now(),
    source: 'registration',
  });
}

function emailOtpRecordForChainTarget(
  input: EcdsaLaneCandidate,
  materialChainTarget: typeof chainTarget | typeof tempoChainTarget,
  options: {
    retention?: EmailOtpEcdsaSessionRecord['emailOtpAuthContext']['retention'];
    remainingUses?: EmailOtpEcdsaSessionRecord['remainingUses'];
  } = {},
): EmailOtpEcdsaSessionRecord {
  const workerOwnedRecord = recordForChainTarget(input, materialChainTarget);
  return markRuntimeValidated({
    ...workerOwnedRecord,
    source: 'email_otp',
    emailOtpAuthContext: {
      policy: options.retention === 'single_use' ? 'per_operation' : 'session',
      retention: options.retention ?? 'session',
      reason: 'login',
      authMethod: 'email_otp',
      authSubjectId: emailOtpAuth.providerSubjectId,
    },
    clientAdditiveShareHandle: {
      kind: 'email_otp_worker_session',
      sessionId: 'email-otp-worker-session',
    },
    remainingUses: options.remainingUses ?? workerOwnedRecord.remainingUses,
  });
}

function markRuntimeValidated<T extends ThresholdEcdsaSessionRecord>(record: T): T {
  if (record.remainingUses <= 0 || record.expiresAtMs <= Date.now()) return record;
  if (!markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record)) {
    throw new Error('failed to mark ECDSA-HSS test record runtime-validated');
  }
  return record;
}

function selectionDepsWithExactMaterial(
  input: EcdsaLaneCandidate,
): EvmFamilyEcdsaSigningSelectionDeps {
  const deps = selectionDeps();
  return {
    ...deps,
    getThresholdEcdsaSessionRecordByKey: () => recordForChainTarget(input, input.chainTarget),
  };
}

test.describe('ECDSA restorable lane selection', () => {
  test.afterEach(() => {
    clearRouterAbEcdsaHssWorkerMaterialRuntimeValidation();
  });

  test('routes restorable passkey lanes without hot material through reauth', async () => {
    const selection = await resolveEvmFamilyEcdsaSigningSelection({
      deps: selectionDeps(),
      walletId,
      chain: 'evm',
      chainTarget,
      senderSignatureAlgorithm: 'webauthnP256',
      authMethod: 'passkey',
      laneCandidate: candidate('restorable'),
    });

    expect(selection.kind).toBe('reauth_required');
    expect(selection.kind === 'reauth_required' ? selection.reason : '').toBe(
      'missing_hot_material',
    );
  });

  test('keeps ready lanes strict when exact material is missing', async () => {
    const selection = await resolveEvmFamilyEcdsaSigningSelection({
      deps: selectionDeps(),
      walletId,
      chain: 'evm',
      chainTarget,
      senderSignatureAlgorithm: 'webauthnP256',
      authMethod: 'passkey',
      laneCandidate: candidate('ready'),
    });

    expect(selection.kind).toBe('missing_material');
  });

  test('routes exhausted passkey lanes through reauth without marking stale material ready', async () => {
    const exhaustedCandidate = candidate('exhausted');
    const selection = await resolveEvmFamilyEcdsaSigningSelection({
      deps: selectionDepsWithExactMaterial(exhaustedCandidate),
      walletId,
      chain: 'evm',
      chainTarget,
      senderSignatureAlgorithm: 'webauthnP256',
      authMethod: 'passkey',
      laneCandidate: exhaustedCandidate,
      reauthAnchor: reauthAnchorForCandidate(exhaustedCandidate),
    });

    expect(selection.kind).toBe('reauth_required');
    if (selection.kind !== 'reauth_required') return;
    expect(selection.reason).toBe('exhausted');
    expect(selection.material).toMatchObject({
      kind: 'reauth_required',
      reason: 'exhausted',
    });
  });

  test('uses source material for deferred shared EVM-family lanes without passkey reauth', async () => {
    const tempoCandidate = sharedTempoCandidate();
    const sourceRecord = recordForChainTarget(tempoCandidate, chainTarget);
    const deps: EvmFamilyEcdsaSigningSelectionDeps = {
      ...selectionDeps(),
      getPasskeyThresholdEcdsaSessionRecordForSigning: ({
        chainTarget: requestedChainTarget,
        source,
      }) => {
        if (
          source === 'registration' &&
          requestedChainTarget.kind === chainTarget.kind &&
          requestedChainTarget.chainId === chainTarget.chainId
        ) {
          return sourceRecord;
        }
        throw new Error('missing source record');
      },
    };

    const selection = await resolveEvmFamilyEcdsaSigningSelection({
      deps,
      walletId,
      chain: 'tempo',
      chainTarget: tempoChainTarget,
      senderSignatureAlgorithm: 'webauthnP256',
      authMethod: 'passkey',
      laneCandidate: tempoCandidate,
    });

    expect(selection.kind).toBe('ready');
    if (selection.kind !== 'ready') return;
    expect(selection.lane.chainTarget).toEqual(tempoChainTarget);
    expect(selection.material.chainTarget).toEqual(tempoChainTarget);
    expect(selection.material.record.chainTarget).toEqual(chainTarget);
    expect(selection.material.sharedKeyState).toMatchObject({
      kind: 'ready_to_sign',
      sourceChainTarget: chainTarget,
      signerMaterial: {
        kind: 'source_chain_material',
        sourceChainTarget: chainTarget,
      },
    });
    expect(selection.diagnostics.selectedLaneCandidate).toMatchObject({
      source: 'evm_family_shared_key',
      sourceChainTarget: chainTarget,
    });
  });

  test('keeps Email OTP exact material out of passkey diagnostics selection', async () => {
    const input = emailOtpCandidate('ready');
    const emailOtpRecord = emailOtpRecordForChainTarget(input, input.chainTarget);
    const deps: EvmFamilyEcdsaSigningSelectionDeps = {
      ...selectionDeps(),
      getThresholdEcdsaSessionRecordByKey: () => emailOtpRecord,
      getEmailOtpThresholdEcdsaSessionRecordForSigning: () => emailOtpRecord,
    };

    const selection = await resolveEvmFamilyEcdsaSigningSelection({
      deps,
      walletId,
      chain: 'evm',
      chainTarget,
      senderSignatureAlgorithm: 'secp256k1',
      authMethod: 'email_otp',
      laneCandidate: input,
      reauthAnchor: reauthAnchorForCandidate(input),
    });

    expect(selection.kind).toBe('ready');
    if (selection.kind !== 'ready') return;
    expect(selection.authMethod).toBe('email_otp');
    expect(selection.source).toBe('email_otp');
    expect(selection.material.record.source).toBe('email_otp');
    expect(selection.diagnostics.selectedPasskeyMaterial).toEqual({ present: false });
    expect(selection.diagnostics.visibleEmailOtpMaterial).toMatchObject({
      present: true,
      authMethod: 'email_otp',
      source: 'email_otp',
    });
  });

  test('uses single-use Email OTP exact material while the record still has signing budget', async () => {
    const input = emailOtpCandidate('ready');
    const emailOtpRecord = emailOtpRecordForChainTarget(input, input.chainTarget, {
      retention: 'single_use',
      remainingUses: 1,
    });
    const deps: EvmFamilyEcdsaSigningSelectionDeps = {
      ...selectionDeps(),
      getThresholdEcdsaSessionRecordByKey: () => emailOtpRecord,
      getEmailOtpThresholdEcdsaSessionRecordForSigning: () => emailOtpRecord,
    };

    const selection = await resolveEvmFamilyEcdsaSigningSelection({
      deps,
      walletId,
      chain: 'evm',
      chainTarget,
      senderSignatureAlgorithm: 'secp256k1',
      authMethod: 'email_otp',
      laneCandidate: input,
    });

    expect(selection.kind).toBe('ready');
    if (selection.kind !== 'ready') return;
    expect(selection.authMethod).toBe('email_otp');
    expect(selection.material.record.source).toBe('email_otp');
    if (selection.material.record.source !== 'email_otp') return;
    expect(selection.material.record.emailOtpAuthContext.retention).toBe('single_use');
    expect(selection.material.record.remainingUses).toBe(1);
  });

  test('uses Email OTP source material for shared Tempo ECDSA lanes', async () => {
    const input = emailOtpSharedTempoCandidate();
    const emailOtpRecord = emailOtpRecordForChainTarget(input, chainTarget);
    const deps: EvmFamilyEcdsaSigningSelectionDeps = {
      ...selectionDeps(),
      getEmailOtpThresholdEcdsaSessionRecordForSigning: ({ chainTarget: requestedChainTarget }) => {
        if (
          requestedChainTarget.kind === chainTarget.kind &&
          requestedChainTarget.chainId === chainTarget.chainId
        ) {
          return emailOtpRecord;
        }
        throw new Error('missing Email OTP source record');
      },
    };

    const selection = await resolveEvmFamilyEcdsaSigningSelection({
      deps,
      walletId,
      chain: 'tempo',
      chainTarget: tempoChainTarget,
      senderSignatureAlgorithm: 'secp256k1',
      authMethod: 'email_otp',
      laneCandidate: input,
      reauthAnchor: reauthAnchorForCandidate(input),
    });

    expect(selection.kind).toBe('ready');
    if (selection.kind !== 'ready') return;
    expect(selection.authMethod).toBe('email_otp');
    expect(selection.lane.chainTarget).toEqual(tempoChainTarget);
    expect(selection.material.chainTarget).toEqual(tempoChainTarget);
    expect(selection.material.record.chainTarget).toEqual(chainTarget);
    expect(selection.material.sharedKeyState).toMatchObject({
      kind: 'ready_to_sign',
      sourceChainTarget: chainTarget,
      signerMaterial: {
        kind: 'source_chain_material',
        sourceChainTarget: chainTarget,
      },
    });
    expect(selection.diagnostics.selectedPasskeyMaterial).toEqual({ present: false });
  });

  test('uses Email OTP source material for shared EVM lanes even when exact target has public identity only', async () => {
    const input = emailOtpSharedEvmCandidateFromTempo();
    const tempoSourceRecord = emailOtpRecordForChainTarget(input, tempoChainTarget);
    const { clientAdditiveShareHandle: _workerShare, ...arcPublicOnlyRecord } =
      emailOtpRecordForChainTarget(input, chainTarget);
    const deps: EvmFamilyEcdsaSigningSelectionDeps = {
      ...selectionDeps(),
      getThresholdEcdsaSessionRecordByKey: () => arcPublicOnlyRecord,
      getEmailOtpThresholdEcdsaSessionRecordForSigning: ({ chainTarget: requestedChainTarget }) => {
        if (
          requestedChainTarget.kind === tempoChainTarget.kind &&
          requestedChainTarget.chainId === tempoChainTarget.chainId
        ) {
          return tempoSourceRecord;
        }
        throw new Error('missing Email OTP source record');
      },
    };

    const selection = await resolveEvmFamilyEcdsaSigningSelection({
      deps,
      walletId,
      chain: 'evm',
      chainTarget,
      senderSignatureAlgorithm: 'secp256k1',
      authMethod: 'email_otp',
      laneCandidate: input,
    });

    expect(selection.kind).toBe('ready');
    if (selection.kind !== 'ready') return;
    expect(selection.authMethod).toBe('email_otp');
    expect(selection.lane.chainTarget).toEqual(chainTarget);
    expect(selection.material.chainTarget).toEqual(chainTarget);
    expect(selection.material.record.chainTarget).toEqual(tempoChainTarget);
    expect(selection.material.sharedKeyState).toMatchObject({
      kind: 'ready_to_sign',
      sourceChainTarget: tempoChainTarget,
      signerMaterial: {
        kind: 'source_chain_material',
        sourceChainTarget: tempoChainTarget,
      },
    });
    expect(selection.diagnostics.exactCandidateMaterial).toMatchObject({
      present: true,
      kind: 'ready_to_sign',
      signerMaterialPresent: true,
      chainTarget,
    });
  });

  test('routes exhausted shared Tempo Email OTP lanes to source-chain OTP reauth', async () => {
    const input: EcdsaLaneCandidate = {
      ...emailOtpSharedTempoCandidate(),
      state: 'exhausted',
      remainingUses: 0,
    };

    const selection = await resolveEvmFamilyEcdsaSigningSelection({
      deps: selectionDeps(),
      walletId,
      chain: 'tempo',
      chainTarget: tempoChainTarget,
      senderSignatureAlgorithm: 'secp256k1',
      authMethod: 'email_otp',
      laneCandidate: input,
      reauthAnchor: reauthAnchorForCandidate(input),
    });

    expect(selection.kind).toBe('reauth_required');
    if (selection.kind !== 'reauth_required') return;
    expect(selection.authMethod).toBe('email_otp');
    expect(selection.reason).toBe('exhausted');
    expect(selection.reauthAuthority).toEqual({
      kind: 'email_otp_signing_session',
      thresholdSessionId: 'tsess-restorable',
      chainTarget,
    });
    expect(selection.diagnostics.selectedPasskeyMaterial).toEqual({ present: false });
  });

  test('keeps exhausted shared Tempo Email OTP lanes backed by registration material available for reauth signing', async () => {
    const input: EcdsaLaneCandidate = {
      ...emailOtpSharedTempoCandidate(),
      state: 'exhausted',
      remainingUses: 0,
    };
    const { clientAdditiveShareHandle: _clientAdditiveShareHandle, ...emailOtpRecordRaw } = {
      ...emailOtpRecordForChainTarget(input, chainTarget),
      remainingUses: 1,
    };
    const emailOtpRecord = markRuntimeValidated(emailOtpRecordRaw);
    const deps: EvmFamilyEcdsaSigningSelectionDeps = {
      ...selectionDeps(),
      getEmailOtpThresholdEcdsaSessionRecordForSigning: ({ chainTarget: requestedChainTarget }) => {
        if (
          requestedChainTarget.kind === chainTarget.kind &&
          requestedChainTarget.chainId === chainTarget.chainId
        ) {
          return emailOtpRecord;
        }
        throw new Error('missing Email OTP source record');
      },
    };

    const selection = await resolveEvmFamilyEcdsaSigningSelection({
      deps,
      walletId,
      chain: 'tempo',
      chainTarget: tempoChainTarget,
      senderSignatureAlgorithm: 'secp256k1',
      authMethod: 'email_otp',
      laneCandidate: input,
      reauthAnchor: reauthAnchorForCandidate(input),
    });

    expect(selection.kind).toBe('reauth_required');
    if (selection.kind !== 'reauth_required') return;
    expect(selection.authMethod).toBe('email_otp');
    expect(selection.reason).toBe('exhausted');
    expect(selection.material).toMatchObject({
      kind: 'ready_to_sign',
      authMethod: 'email_otp',
    });
    expect(selection.diagnostics.exactCandidateMaterial).toMatchObject({
      present: true,
      kind: 'ready_to_sign',
      hasRecord: true,
      publicIdentityPresent: true,
      signerMaterialPresent: true,
    });
    expect(selection.reauthAuthority).toEqual({
      kind: 'email_otp_signing_session',
      thresholdSessionId: 'tsess-restorable',
      chainTarget,
    });
  });
});
