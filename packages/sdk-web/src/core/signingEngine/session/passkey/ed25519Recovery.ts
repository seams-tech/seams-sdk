import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { AccountId } from '@/core/types/accountIds';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  upsertThresholdEd25519SessionFact,
  type ThresholdEd25519MaterialReadySessionRecord,
  type ThresholdEd25519RestoreAvailableSessionRecord,
  type ThresholdEd25519SessionRecord,
  type ThresholdEd25519UpsertMaterialFields,
} from '../persistence/records';
import type {
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
} from '../warmCapabilities/types';
import {
  sealedRecoverySessionKind,
  sealedRecoveryWalletSessionJwt,
  type PasskeyEd25519SealedRecoveryRecord,
} from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import type { RestorePersistedEd25519SessionPurpose } from '@/core/signingEngine/session/sealedRecovery/sealedRecovery.types';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import {
  parseEd25519ClientVerifyingShareB64u,
  parseEd25519SealedWorkerMaterialRef,
  parseEd25519WorkerMaterialBindingDigest,
  parseEd25519WorkerMaterialHandle,
  parseEd25519WorkerMaterialKeyId,
  parseSigningSessionSealKeyVersion,
  type Ed25519ClientVerifyingShareB64u,
  type Ed25519SealedWorkerMaterialRef,
  type Ed25519WorkerMaterialBindingDigest,
  type Ed25519WorkerMaterialHandle,
  type Ed25519WorkerMaterialKeyId,
  type SigningSessionSealKeyVersion,
} from '../keyMaterialBrands';
import { publishResolvedIdentity } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type { ThresholdEd25519WebAuthnPrfSecretSource } from '../../threshold/ed25519/walletSession';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  isRouterAbEd25519WorkerMaterialRuntimeValidated,
  markRouterAbEd25519WorkerMaterialRuntimeValidated,
} from '../routerAbSigningWalletSession';
import {
  exactEd25519SigningLaneIdentity,
  nearEd25519SignerBindingFromBoundaryFields,
} from '../identity/exactSigningLaneIdentity';
import { toRpId } from '../identity/evmFamilyEcdsaIdentity';

type PasskeyEd25519ReconnectRuntimeHandle =
  | {
      kind: 'runtime_handle_available';
      ed25519WorkerMaterialHandle: Ed25519WorkerMaterialHandle;
    }
  | {
      kind: 'runtime_handle_absent';
      ed25519WorkerMaterialHandle?: never;
    };

type PasskeyEd25519ReconnectWorkerMaterialFacts = PasskeyEd25519ReconnectRuntimeHandle & {
  clientVerifyingShareB64u: Ed25519ClientVerifyingShareB64u;
  ed25519WorkerMaterialBindingDigest: Ed25519WorkerMaterialBindingDigest;
  sealedWorkerMaterialRef: Ed25519SealedWorkerMaterialRef;
  sealedWorkerMaterialB64u?: string;
  materialFormatVersion: string;
  materialKeyId: Ed25519WorkerMaterialKeyId;
  materialCreatedAtMs: number;
  signerSlot: number;
};

type PasskeyEd25519ReconnectWorkerMaterialSourceRecord =
  | ThresholdEd25519MaterialReadySessionRecord
  | ThresholdEd25519RestoreAvailableSessionRecord;

type PasskeyEd25519ReconnectCommonWorkerMaterialFacts = {
  clientVerifyingShareB64u: Ed25519ClientVerifyingShareB64u;
  ed25519WorkerMaterialBindingDigest: Ed25519WorkerMaterialBindingDigest;
  sealedWorkerMaterialRef: Ed25519SealedWorkerMaterialRef;
  sealedWorkerMaterialB64u?: string;
  materialFormatVersion: string;
  materialKeyId: Ed25519WorkerMaterialKeyId;
  materialCreatedAtMs: number;
  signerSlot: number;
};

type PasskeyEd25519SealedPolicy = {
  expiresAtMs: number;
  remainingUses: number;
};

function nonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

function positiveInteger(value: unknown): number {
  const parsed = Math.floor(Number(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function sameParticipantIds(left: readonly number[], right: readonly number[]): boolean {
  const normalizedLeft = normalizeThresholdEd25519ParticipantIds(left);
  const normalizedRight = normalizeThresholdEd25519ParticipantIds(right);
  return Boolean(
    normalizedLeft &&
      normalizedRight &&
      normalizedLeft.length === normalizedRight.length &&
      normalizedLeft.every((value, index) => value === normalizedRight[index]),
  );
}

function passkeyEd25519SigningRootId(record: PasskeyEd25519SealedRecoveryRecord): string {
  const scope = record.runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(record.runtimePolicyScope)
    : null;
  return nonEmptyString(scope?.signingRootId);
}

function passkeyEd25519SigningRootVersion(record: PasskeyEd25519SealedRecoveryRecord): string {
  const scope = record.runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(record.runtimePolicyScope)
    : null;
  return nonEmptyString(scope?.signingRootVersion);
}

function shouldDeletePasskeyEd25519SealedRecordAfterRestoreFailure(
  status: WarmSessionStatusResult,
): boolean {
  if (status.ok) return false;
  switch (status.code) {
    case 'expired':
    case 'not_found':
    case 'invalid_args':
    case 'invalid_response':
      return true;
    case 'exhausted':
      return false;
    default:
      return false;
  }
}

function readPasskeyEd25519ReconnectWorkerMaterialFacts(
  record: ThresholdEd25519SessionRecord,
): PasskeyEd25519ReconnectWorkerMaterialFacts | null {
  switch (record.materialState) {
    case 'material_ready':
      return readReadyPasskeyEd25519ReconnectWorkerMaterialFacts(record);
    case 'restore_available':
      return readRestorablePasskeyEd25519ReconnectWorkerMaterialFacts(record);
    case 'auth_ready_material_pending':
      return null;
  }
}

function readPasskeyEd25519ReconnectCommonWorkerMaterialFacts(
  record: PasskeyEd25519ReconnectWorkerMaterialSourceRecord,
): PasskeyEd25519ReconnectCommonWorkerMaterialFacts | null {
  const sealedWorkerMaterialB64u = nonEmptyString(record.sealedWorkerMaterialB64u);
  const signerSlot = positiveInteger(record.signerSlot);
  if (!signerSlot) {
    return null;
  }
  return {
    clientVerifyingShareB64u: parseEd25519ClientVerifyingShareB64u(
      record.clientVerifyingShareB64u,
    ),
    ed25519WorkerMaterialBindingDigest: parseEd25519WorkerMaterialBindingDigest(
      record.ed25519WorkerMaterialBindingDigest,
    ),
    sealedWorkerMaterialRef: parseEd25519SealedWorkerMaterialRef(record.sealedWorkerMaterialRef),
    ...(sealedWorkerMaterialB64u ? { sealedWorkerMaterialB64u } : {}),
    materialFormatVersion: record.materialFormatVersion,
    materialKeyId: parseEd25519WorkerMaterialKeyId(record.materialKeyId),
    materialCreatedAtMs: record.materialCreatedAtMs,
    signerSlot,
  };
}

function readReadyPasskeyEd25519ReconnectWorkerMaterialFacts(
  record: ThresholdEd25519MaterialReadySessionRecord,
): PasskeyEd25519ReconnectWorkerMaterialFacts | null {
  const commonFacts = readPasskeyEd25519ReconnectCommonWorkerMaterialFacts(record);
  if (!commonFacts) return null;
  return {
    kind: 'runtime_handle_available',
    ed25519WorkerMaterialHandle: parseEd25519WorkerMaterialHandle(
      record.ed25519WorkerMaterialHandle,
    ),
    ...commonFacts,
  };
}

function readRestorablePasskeyEd25519ReconnectWorkerMaterialFacts(
  record: ThresholdEd25519RestoreAvailableSessionRecord,
): PasskeyEd25519ReconnectWorkerMaterialFacts | null {
  const commonFacts = readPasskeyEd25519ReconnectCommonWorkerMaterialFacts(record);
  if (!commonFacts) return null;
  return {
    kind: 'runtime_handle_absent',
    ...commonFacts,
  };
}

function passkeyEd25519MaterialFieldsFromFacts(
  facts: PasskeyEd25519ReconnectWorkerMaterialFacts,
): ThresholdEd25519UpsertMaterialFields | null {
  switch (facts.kind) {
    case 'runtime_handle_available':
      if (!facts.sealedWorkerMaterialB64u) return null;
      return {
        clientVerifyingShareB64u: facts.clientVerifyingShareB64u,
        ed25519WorkerMaterialHandle: facts.ed25519WorkerMaterialHandle,
        ed25519WorkerMaterialBindingDigest: facts.ed25519WorkerMaterialBindingDigest,
        sealedWorkerMaterialRef: facts.sealedWorkerMaterialRef,
        sealedWorkerMaterialB64u: facts.sealedWorkerMaterialB64u,
        materialFormatVersion: facts.materialFormatVersion,
        materialKeyId: facts.materialKeyId,
        materialCreatedAtMs: facts.materialCreatedAtMs,
      };
    case 'runtime_handle_absent':
      return {
        clientVerifyingShareB64u: facts.clientVerifyingShareB64u,
        ed25519WorkerMaterialBindingDigest: facts.ed25519WorkerMaterialBindingDigest,
        sealedWorkerMaterialRef: facts.sealedWorkerMaterialRef,
        ...(facts.sealedWorkerMaterialB64u
          ? { sealedWorkerMaterialB64u: facts.sealedWorkerMaterialB64u }
          : {}),
        materialFormatVersion: facts.materialFormatVersion,
        materialKeyId: facts.materialKeyId,
        materialCreatedAtMs: facts.materialCreatedAtMs,
      };
    default:
      facts satisfies never;
      return null;
  }
}

function passkeyEd25519MaterialFieldsFromSealedRecord(
  record: PasskeyEd25519SealedRecoveryRecord,
): ThresholdEd25519UpsertMaterialFields {
  return {
    clientVerifyingShareB64u: record.clientVerifyingShareB64u,
    ed25519WorkerMaterialBindingDigest: record.ed25519WorkerMaterialBindingDigest,
    sealedWorkerMaterialRef: record.sealedWorkerMaterialRef,
    ...(record.sealedWorkerMaterialB64u
      ? { sealedWorkerMaterialB64u: record.sealedWorkerMaterialB64u }
      : {}),
    materialFormatVersion: record.materialFormatVersion,
    materialKeyId: record.materialKeyId,
    materialCreatedAtMs: record.materialCreatedAtMs,
  };
}

function canRetainPasskeyEd25519ReconnectWorkerMaterial(args: {
  sourceRecord: ThresholdEd25519SessionRecord;
  targetRecord: ThresholdEd25519SessionRecord;
  facts: PasskeyEd25519ReconnectWorkerMaterialFacts;
}): boolean {
  const source = args.sourceRecord;
  const target = args.targetRecord;
  return (
    nonEmptyString(source.nearAccountId) === nonEmptyString(target.nearAccountId) &&
    nonEmptyString(source.rpId) === nonEmptyString(target.rpId) &&
    nonEmptyString(source.relayerUrl) === nonEmptyString(target.relayerUrl) &&
    nonEmptyString(source.relayerKeyId) === nonEmptyString(target.relayerKeyId) &&
    sameParticipantIds(source.participantIds, target.participantIds) &&
    nonEmptyString(source.signingRootId) === nonEmptyString(target.signingRootId) &&
    nonEmptyString(source.signingRootVersion) === nonEmptyString(target.signingRootVersion) &&
    positiveInteger(target.signerSlot) === args.facts.signerSlot
  );
}

function canRetainPasskeyEd25519SealedRecordWorkerMaterial(args: {
  currentRecord: ThresholdEd25519SessionRecord;
  sealedRecord: PasskeyEd25519SealedRecoveryRecord;
  facts: PasskeyEd25519ReconnectWorkerMaterialFacts;
}): boolean {
  const current = args.currentRecord;
  const sealed = args.sealedRecord;
  return (
    nonEmptyString(current.walletId) === nonEmptyString(sealed.walletId) &&
    nonEmptyString(current.nearAccountId) === nonEmptyString(sealed.nearAccountId) &&
    nonEmptyString(current.nearEd25519SigningKeyId) ===
      nonEmptyString(sealed.nearEd25519SigningKeyId) &&
    nonEmptyString(current.rpId) === nonEmptyString(sealed.authority.verifier.rpId) &&
    nonEmptyString(current.passkeyCredentialIdB64u) ===
      nonEmptyString(sealed.authority.factor.credentialIdB64u) &&
    nonEmptyString(current.relayerUrl) === nonEmptyString(sealed.relayerUrl) &&
    nonEmptyString(current.relayerKeyId) === nonEmptyString(sealed.relayerKeyId) &&
    sameParticipantIds(current.participantIds, sealed.participantIds) &&
    nonEmptyString(current.signingRootId) === passkeyEd25519SigningRootId(sealed) &&
    nonEmptyString(current.signingRootVersion) === passkeyEd25519SigningRootVersion(sealed) &&
    positiveInteger(current.signerSlot) === args.facts.signerSlot
  );
}

function retainPasskeyEd25519ReconnectWorkerMaterialFacts(args: {
  sourceRecord: ThresholdEd25519SessionRecord;
  targetSessionId: string;
  targetSigningGrantId: string;
}): ThresholdEd25519SessionRecord {
  const targetRecord = getStoredThresholdEd25519SessionRecordByThresholdSessionId(
    args.targetSessionId,
  );
  if (!targetRecord) {
    throw new Error(
      '[SigningEngine][near] passkey Ed25519 reconnect did not publish the planned session record',
    );
  }
  if (nonEmptyString(targetRecord.signingGrantId) !== args.targetSigningGrantId) {
    throw new Error(
      '[SigningEngine][near] passkey Ed25519 reconnect returned a signing grant mismatch',
    );
  }
  if (readPasskeyEd25519ReconnectWorkerMaterialFacts(targetRecord)) return targetRecord;

  const sourceFacts = readPasskeyEd25519ReconnectWorkerMaterialFacts(args.sourceRecord);
  if (
    !sourceFacts ||
    !canRetainPasskeyEd25519ReconnectWorkerMaterial({
      sourceRecord: args.sourceRecord,
      targetRecord,
      facts: sourceFacts,
    })
  ) {
    return targetRecord;
  }

  const targetBase = {
    walletId: targetRecord.walletId,
    nearAccountId: targetRecord.nearAccountId,
    nearEd25519SigningKeyId: targetRecord.nearEd25519SigningKeyId,
    rpId: targetRecord.rpId,
    passkeyCredentialIdB64u: targetRecord.passkeyCredentialIdB64u,
    relayerUrl: targetRecord.relayerUrl,
    relayerKeyId: targetRecord.relayerKeyId,
    participantIds: targetRecord.participantIds,
    ...(targetRecord.signingRootId ? { signingRootId: targetRecord.signingRootId } : {}),
    ...(targetRecord.signingRootVersion
      ? { signingRootVersion: targetRecord.signingRootVersion }
      : {}),
    ...(targetRecord.runtimePolicyScope
      ? { runtimePolicyScope: targetRecord.runtimePolicyScope }
      : {}),
    signerSlot: sourceFacts.signerSlot,
    routerAbNormalSigning: targetRecord.routerAbNormalSigning,
    thresholdSessionKind: targetRecord.thresholdSessionKind,
    thresholdSessionId: targetRecord.thresholdSessionId,
    signingGrantId: targetRecord.signingGrantId,
    ...(targetRecord.walletSessionJwt ? { walletSessionJwt: targetRecord.walletSessionJwt } : {}),
    expiresAtMs: targetRecord.expiresAtMs,
    remainingUses: targetRecord.remainingUses,
    // Preserve the exact session generation so material retention cannot steal
    // the broad current slot from a concurrently newer record.
    updatedAtMs: targetRecord.updatedAtMs,
    source: targetRecord.source,
  };
  const updated =
    sourceFacts.kind === 'runtime_handle_available' && sourceFacts.sealedWorkerMaterialB64u
      ? upsertThresholdEd25519SessionFact({
          ...targetBase,
          clientVerifyingShareB64u: sourceFacts.clientVerifyingShareB64u,
          ed25519WorkerMaterialHandle: sourceFacts.ed25519WorkerMaterialHandle,
          ed25519WorkerMaterialBindingDigest: sourceFacts.ed25519WorkerMaterialBindingDigest,
          sealedWorkerMaterialRef: sourceFacts.sealedWorkerMaterialRef,
          sealedWorkerMaterialB64u: sourceFacts.sealedWorkerMaterialB64u,
          materialFormatVersion: sourceFacts.materialFormatVersion,
          materialKeyId: sourceFacts.materialKeyId,
          materialCreatedAtMs: sourceFacts.materialCreatedAtMs,
        })
      : upsertThresholdEd25519SessionFact({
          ...targetBase,
          clientVerifyingShareB64u: sourceFacts.clientVerifyingShareB64u,
          ed25519WorkerMaterialBindingDigest: sourceFacts.ed25519WorkerMaterialBindingDigest,
          sealedWorkerMaterialRef: sourceFacts.sealedWorkerMaterialRef,
          ...(sourceFacts.sealedWorkerMaterialB64u
            ? { sealedWorkerMaterialB64u: sourceFacts.sealedWorkerMaterialB64u }
            : {}),
          materialFormatVersion: sourceFacts.materialFormatVersion,
          materialKeyId: sourceFacts.materialKeyId,
          materialCreatedAtMs: sourceFacts.materialCreatedAtMs,
        });
  if (!updated) {
    throw new Error(
      '[SigningEngine][near] passkey Ed25519 reconnect could not retain worker material facts',
    );
  }
  return updated;
}

function passkeyEd25519SealedRecordRetainedMaterial(args: {
  currentRecord: ThresholdEd25519SessionRecord | null;
  sealedRecord: PasskeyEd25519SealedRecoveryRecord;
}): ThresholdEd25519UpsertMaterialFields | null {
  if (!args.currentRecord) return null;
  const currentFacts = readPasskeyEd25519ReconnectWorkerMaterialFacts(args.currentRecord);
  if (!currentFacts) return null;
  if (
    !canRetainPasskeyEd25519SealedRecordWorkerMaterial({
      currentRecord: args.currentRecord,
      sealedRecord: args.sealedRecord,
      facts: currentFacts,
    })
  ) {
    return null;
  }
  return passkeyEd25519MaterialFieldsFromFacts(currentFacts);
}

function publishPasskeyEd25519SealedRecordForAccount(args: {
  walletId: string;
  record: PasskeyEd25519SealedRecoveryRecord;
  thresholdSessionId: string;
  signingGrantId: string;
  policy: PasskeyEd25519SealedPolicy;
}): ThresholdEd25519SessionRecord | null {
  const walletSessionJwt = sealedRecoveryWalletSessionJwt(args.record.walletSessionAuth);
  const routerAbNormalSigning = args.record.routerAbNormalSigning;
  if (!routerAbNormalSigning) {
    throw new Error('passkey Ed25519 sealed restore requires Router A/B signing metadata');
  }
  const updatedAtMs = Date.now();
  const currentRecord = getStoredThresholdEd25519SessionRecordByThresholdSessionId(
    args.thresholdSessionId,
  );
  const retainedMaterialFields = passkeyEd25519SealedRecordRetainedMaterial({
    currentRecord,
    sealedRecord: args.record,
  });
  const currentRecordWasRuntimeValidated = retainedMaterialFields
    ? isRouterAbEd25519WorkerMaterialRuntimeValidated(currentRecord)
    : false;
  const record = upsertThresholdEd25519SessionFact({
    walletId: args.record.walletId,
    nearAccountId: args.record.nearAccountId,
    nearEd25519SigningKeyId: args.record.nearEd25519SigningKeyId,
    rpId: args.record.authority.verifier.rpId,
    passkeyCredentialIdB64u: args.record.authority.factor.credentialIdB64u,
    relayerUrl: args.record.relayerUrl,
    relayerKeyId: args.record.relayerKeyId,
    participantIds: [...args.record.participantIds],
    signerSlot: args.record.signerSlot,
    ...(args.record.runtimePolicyScope
      ? { runtimePolicyScope: args.record.runtimePolicyScope }
      : {}),
    ...(retainedMaterialFields || passkeyEd25519MaterialFieldsFromSealedRecord(args.record)),
    routerAbNormalSigning,
    thresholdSessionKind: sealedRecoverySessionKind(args.record.walletSessionAuth),
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    ...(walletSessionJwt ? { walletSessionJwt } : {}),
    expiresAtMs: args.policy.expiresAtMs,
    remainingUses: args.policy.remainingUses,
    updatedAtMs,
    source: retainedMaterialFields ? currentRecord?.source || 'login' : 'login',
  });
  if (!record) return null;
  if (currentRecordWasRuntimeValidated) {
    markRouterAbEd25519WorkerMaterialRuntimeValidated(record);
  }
  publishResolvedIdentity({
    walletId: args.walletId,
    authMethod: 'passkey',
    curve: 'ed25519',
    chain: 'near',
    signingGrantId: args.signingGrantId,
    thresholdSessionId: args.thresholdSessionId,
    updatedAtMs,
  });
  return record;
}

function exactPasskeyEd25519ReconnectLaneIdentity(args: {
  nearAccountId: AccountId;
  record: ThresholdEd25519SessionRecord;
  signerSlot: number;
  sessionId: string;
  signingGrantId: string;
}) {
  return exactEd25519SigningLaneIdentity({
    signer: nearEd25519SignerBindingFromBoundaryFields({
      walletId: args.record.walletId,
      nearAccountId: args.nearAccountId,
      nearEd25519SigningKeyId: args.record.nearEd25519SigningKeyId,
      signerSlot: args.signerSlot,
    }),
    auth: {
      kind: 'passkey',
      rpId: toRpId(args.record.rpId),
      credentialIdB64u: String(args.record.passkeyCredentialIdB64u || '').trim(),
    },
    signingGrantId: args.signingGrantId,
    thresholdSessionId: args.sessionId,
  });
}

export async function reconnectPasskeyEd25519CapabilityForSigning(args: {
  nearAccountId: AccountId;
  record: ThresholdEd25519SessionRecord;
  policySecretSource: ThresholdEd25519WebAuthnPrfSecretSource;
  remainingUses?: number;
  sessionId: string;
  signingGrantId: string;
  provisionThresholdEd25519Session: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  restorePasskeyEd25519SigningMaterial: (args: {
    nearAccountId: AccountId;
    credential: ThresholdEd25519WebAuthnPrfSecretSource['credential'];
    signerSlot: number;
    thresholdSessionId: string;
  }) => Promise<void>;
  readStoredThresholdEd25519SessionRecordByThresholdSessionId?: (
    thresholdSessionId: string,
  ) => ThresholdEd25519SessionRecord | null;
}): Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }> {
  const reconnectRemainingUses = Math.max(1, Math.floor(Number(args.remainingUses) || 1));
  const sessionId = String(args.sessionId || '').trim();
  const signingGrantId = String(args.signingGrantId || '').trim();
  const signerSlot = Math.floor(Number(args.record.signerSlot) || 0);
  if (!sessionId || !signingGrantId) {
    throw new Error('Passkey Ed25519 signing session reconnect requires exact session identity');
  }
  if (signerSlot <= 0) {
    throw new Error('[SigningEngine][near] passkey Ed25519 reconnect requires signer slot');
  }
  const provisioned = await args.provisionThresholdEd25519Session({
    kind: 'exact_ed25519_provisioning',
    laneIdentity: exactPasskeyEd25519ReconnectLaneIdentity({
      nearAccountId: args.nearAccountId,
      record: args.record,
      signerSlot,
      sessionId,
      signingGrantId,
    }),
    relayerUrl: args.record.relayerUrl,
    relayerKeyId: args.record.relayerKeyId,
    source: 'login',
    authority: {
      kind: 'wallet_auth_authority',
      authority: buildPasskeyWalletAuthAuthority({
        walletId: args.record.walletId,
        rpId: args.record.rpId,
        credentialIdB64u: args.record.passkeyCredentialIdB64u,
      }),
    },
    auth: {
      kind: 'threshold_session_policy_webauthn',
      policySecretSource: args.policySecretSource,
    },
    ...(args.record.runtimePolicyScope
      ? { runtimePolicyScope: args.record.runtimePolicyScope }
      : {}),
    routerAbNormalSigning: args.record.routerAbNormalSigning,
    participantIds: args.record.participantIds,
    sessionKind: 'jwt',
    remainingUses: reconnectRemainingUses,
  });
  if (!provisioned.ok) {
    throw new Error(
      provisioned.message || provisioned.code || 'Passkey Ed25519 signing session reconnect failed',
    );
  }
  retainPasskeyEd25519ReconnectWorkerMaterialFacts({
    sourceRecord: args.record,
    targetSessionId: sessionId,
    targetSigningGrantId: signingGrantId,
  });
  await args.restorePasskeyEd25519SigningMaterial({
    nearAccountId: args.nearAccountId,
    credential: args.policySecretSource.credential,
    signerSlot,
    thresholdSessionId: sessionId,
  });
  const refreshedRecord =
    args.readStoredThresholdEd25519SessionRecordByThresholdSessionId?.(sessionId) ||
    getStoredThresholdEd25519SessionRecordByThresholdSessionId(sessionId);
  if (!refreshedRecord) {
    throw new Error(
      '[SigningEngine][near] passkey Ed25519 reconnect did not publish the planned session record',
    );
  }
  if (String(refreshedRecord.signingGrantId || '').trim() !== signingGrantId) {
    throw new Error(
      '[SigningEngine][near] passkey Ed25519 reconnect returned a signing grant mismatch',
    );
  }
  return {
    sessionId: provisioned.sessionId,
    record: refreshedRecord,
  };
}

export async function restorePasskeyEd25519SealedRecordForAccount(args: {
  walletId: string;
  record: PasskeyEd25519SealedRecoveryRecord;
  purpose: RestorePersistedEd25519SessionPurpose & { authMethod: 'passkey' };
  transport: WarmSessionSealTransportInput;
  shamirPrimeB64u: string;
  rehydrateWarmSessionMaterial: (args: {
    sessionId: string;
    sealedSecretB64u: string;
    signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
    expiresAtMs: number;
    remainingUses: number;
    transport: WarmSessionSealTransportInput;
  }) => Promise<WarmSessionStatusResult>;
  deletePersistedRecord: () => Promise<void>;
  recordSessionMaterialRestored: (status: WarmSessionStatusResult) => Promise<void>;
  readWarmSessionStatusFromWorker: (sessionId: string) => Promise<WarmSessionStatusResult | null>;
  updatePersistedPolicy: (args: {
    expiresAtMs: number;
    remainingUses: number;
    updatedAtMs: number;
  }) => Promise<void>;
}): Promise<WarmSessionStatusResult | null> {
  const thresholdSessionId = String(args.purpose.thresholdSessionId || '').trim();
  const signingGrantId = String(args.purpose.signingGrantId || '').trim();
  if (
    !thresholdSessionId ||
    !signingGrantId ||
    !args.shamirPrimeB64u ||
    String(args.walletId || '').trim() !== String(args.record.walletId || '').trim()
  ) {
    return null;
  }
  const sealedSessionKeyVersion = nonEmptyString(args.record.keyVersion);
  if (!sealedSessionKeyVersion) return null;
  const routerAbNormalSigning = args.record.routerAbNormalSigning;
  if (!routerAbNormalSigning) return null;

  try {
    publishPasskeyEd25519SealedRecordForAccount({
      walletId: args.walletId,
      record: args.record,
      thresholdSessionId,
      signingGrantId,
      policy: {
        expiresAtMs: Math.floor(Number(args.record.expiresAtMs) || 0),
        remainingUses: Math.max(0, Math.floor(Number(args.record.remainingUses) || 0)),
      },
    });
  } catch (error) {
    return {
      ok: false,
      code: 'invalid_persisted_record',
      message: error instanceof Error ? error.message : String(error),
    };
  }

  const rehydrated = await args.rehydrateWarmSessionMaterial({
    sessionId: thresholdSessionId,
    sealedSecretB64u: args.record.sealedSecretB64u,
    signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(args.record.keyVersion),
    expiresAtMs: args.record.expiresAtMs,
    remainingUses: Math.max(1_000_000, Math.floor(Number(args.record.remainingUses) || 0)),
    transport: {
      ...args.transport,
      shamirPrimeB64u: args.shamirPrimeB64u,
    },
  });
  if (!rehydrated.ok) {
    if (rehydrated.code === 'exhausted') {
      publishPasskeyEd25519SealedRecordForAccount({
        walletId: args.walletId,
        record: args.record,
        thresholdSessionId,
        signingGrantId,
        policy: {
          expiresAtMs: Math.floor(Number(args.record.expiresAtMs) || 0),
          remainingUses: 0,
        },
      });
    }
    if (shouldDeletePasskeyEd25519SealedRecordAfterRestoreFailure(rehydrated)) {
      await args.deletePersistedRecord().catch(() => undefined);
    }
    await args.recordSessionMaterialRestored(rehydrated);
    return rehydrated;
  }

  const parsed = await args.readWarmSessionStatusFromWorker(thresholdSessionId);
  if (!parsed) {
    const failed: WarmSessionStatusResult = {
      ok: false,
      code: 'worker_error',
      message: 'Warm-session status read failed after rehydrate',
    };
    await args.recordSessionMaterialRestored(failed);
    return failed;
  }
  if (!parsed.ok) {
    if (parsed.code === 'exhausted') {
      publishPasskeyEd25519SealedRecordForAccount({
        walletId: args.walletId,
        record: args.record,
        thresholdSessionId,
        signingGrantId,
        policy: {
          expiresAtMs: Math.floor(Number(args.record.expiresAtMs) || 0),
          remainingUses: 0,
        },
      });
    }
    if (shouldDeletePasskeyEd25519SealedRecordAfterRestoreFailure(parsed)) {
      await args.deletePersistedRecord().catch(() => undefined);
    }
    await args.recordSessionMaterialRestored(parsed);
    return parsed;
  }
  publishPasskeyEd25519SealedRecordForAccount({
    walletId: args.walletId,
    record: args.record,
    thresholdSessionId,
    signingGrantId,
    policy: {
      expiresAtMs: parsed.expiresAtMs,
      remainingUses: parsed.remainingUses,
    },
  });
  await args.recordSessionMaterialRestored(parsed);
  await args
    .updatePersistedPolicy({
      expiresAtMs: parsed.expiresAtMs,
      remainingUses: parsed.remainingUses,
      updatedAtMs: Date.now(),
    })
    .catch(() => undefined);
  return parsed;
}
