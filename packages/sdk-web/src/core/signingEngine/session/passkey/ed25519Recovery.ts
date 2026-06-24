import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { AccountId } from '@/core/types/accountIds';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  upsertStoredThresholdEd25519SessionRecord,
  type ThresholdEd25519SessionRecord,
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
  sealedWorkerMaterialB64u: string;
  materialFormatVersion: string;
  materialKeyId: Ed25519WorkerMaterialKeyId;
  materialCreatedAtMs: number;
  signerSlot: number;
  keyVersion: string;
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

function readPasskeyEd25519ReconnectWorkerMaterialFacts(
  record: ThresholdEd25519SessionRecord,
): PasskeyEd25519ReconnectWorkerMaterialFacts | null {
  const clientVerifyingShareB64u = nonEmptyString(record.clientVerifyingShareB64u);
  const ed25519WorkerMaterialBindingDigest = nonEmptyString(
    record.ed25519WorkerMaterialBindingDigest,
  );
  const sealedWorkerMaterialRef = nonEmptyString(record.sealedWorkerMaterialRef);
  const sealedWorkerMaterialB64u = nonEmptyString(record.sealedWorkerMaterialB64u);
  const materialFormatVersion = nonEmptyString(record.materialFormatVersion);
  const materialKeyId = nonEmptyString(record.materialKeyId);
  const materialCreatedAtMs = positiveInteger(record.materialCreatedAtMs);
  const signerSlot = positiveInteger(record.signerSlot);
  const keyVersion = nonEmptyString(record.keyVersion);
  if (
    !clientVerifyingShareB64u ||
    !ed25519WorkerMaterialBindingDigest ||
    !sealedWorkerMaterialRef ||
    !sealedWorkerMaterialB64u ||
    !materialFormatVersion ||
    !materialKeyId ||
    !materialCreatedAtMs ||
    !signerSlot ||
    !keyVersion
  ) {
    return null;
  }
  const ed25519WorkerMaterialHandle = nonEmptyString(record.ed25519WorkerMaterialHandle);
  const commonFacts = {
    clientVerifyingShareB64u: parseEd25519ClientVerifyingShareB64u(clientVerifyingShareB64u),
    ed25519WorkerMaterialBindingDigest: parseEd25519WorkerMaterialBindingDigest(
      ed25519WorkerMaterialBindingDigest,
    ),
    sealedWorkerMaterialRef: parseEd25519SealedWorkerMaterialRef(sealedWorkerMaterialRef),
    sealedWorkerMaterialB64u,
    materialFormatVersion,
    materialKeyId: parseEd25519WorkerMaterialKeyId(materialKeyId),
    materialCreatedAtMs,
    signerSlot,
    keyVersion,
  };
  if (ed25519WorkerMaterialHandle) {
    return {
      kind: 'runtime_handle_available',
      ed25519WorkerMaterialHandle: parseEd25519WorkerMaterialHandle(
        ed25519WorkerMaterialHandle,
      ),
      ...commonFacts,
    };
  }
  return {
    kind: 'runtime_handle_absent',
    ...commonFacts,
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

  const updated = upsertStoredThresholdEd25519SessionRecord({
    walletId: targetRecord.walletId,
    nearAccountId: targetRecord.nearAccountId,
    ed25519KeyScopeId: targetRecord.ed25519KeyScopeId,
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
    clientVerifyingShareB64u: sourceFacts.clientVerifyingShareB64u,
    ...(sourceFacts.kind === 'runtime_handle_available'
      ? { ed25519WorkerMaterialHandle: sourceFacts.ed25519WorkerMaterialHandle }
      : {}),
    ed25519WorkerMaterialBindingDigest: sourceFacts.ed25519WorkerMaterialBindingDigest,
    sealedWorkerMaterialRef: sourceFacts.sealedWorkerMaterialRef,
    sealedWorkerMaterialB64u: sourceFacts.sealedWorkerMaterialB64u,
    materialFormatVersion: sourceFacts.materialFormatVersion,
    materialKeyId: sourceFacts.materialKeyId,
    materialCreatedAtMs: sourceFacts.materialCreatedAtMs,
    signerSlot: sourceFacts.signerSlot,
    keyVersion: sourceFacts.keyVersion,
    ...(targetRecord.routerAbNormalSigning
      ? { routerAbNormalSigning: targetRecord.routerAbNormalSigning }
      : {}),
    thresholdSessionKind: targetRecord.thresholdSessionKind,
    thresholdSessionId: targetRecord.thresholdSessionId,
    signingGrantId: targetRecord.signingGrantId,
    ...(targetRecord.walletSessionJwt ? { walletSessionJwt: targetRecord.walletSessionJwt } : {}),
    expiresAtMs: targetRecord.expiresAtMs,
    remainingUses: targetRecord.remainingUses,
    updatedAtMs: Date.now(),
    source: targetRecord.source,
  });
  if (!updated) {
    throw new Error(
      '[SigningEngine][near] passkey Ed25519 reconnect could not retain worker material facts',
    );
  }
  return updated;
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
    walletId: String(args.record.walletId),
    nearAccountId: args.nearAccountId,
    ed25519KeyScopeId: String(args.record.ed25519KeyScopeId),
    relayerUrl: args.record.relayerUrl,
    relayerKeyId: args.record.relayerKeyId,
    source: 'login',
    auth: {
      kind: 'threshold_session_policy_webauthn',
      policySecretSource: args.policySecretSource,
    },
    ...(args.record.runtimePolicyScope
      ? { runtimePolicyScope: args.record.runtimePolicyScope }
      : {}),
    ...(args.record.routerAbNormalSigning
      ? { routerAbNormalSigning: args.record.routerAbNormalSigning }
      : {}),
    participantIds: args.record.participantIds,
    sessionKind: 'jwt',
    signerSlot,
    sessionId,
    signingGrantId,
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

  const publishRecord = (policy: { expiresAtMs: number; remainingUses: number }): void => {
    const walletSessionJwt = sealedRecoveryWalletSessionJwt(args.record.walletSessionAuth);
    upsertStoredThresholdEd25519SessionRecord({
      walletId: args.record.walletId,
      nearAccountId: args.record.nearAccountId,
      ed25519KeyScopeId: args.record.ed25519KeyScopeId,
      rpId: args.record.rpId,
      passkeyCredentialIdB64u: args.record.credentialIdB64u,
      relayerUrl: args.record.relayerUrl,
      relayerKeyId: args.record.relayerKeyId,
      participantIds: [...args.record.participantIds],
      signerSlot: args.record.signerSlot,
      ...(args.record.runtimePolicyScope
        ? { runtimePolicyScope: args.record.runtimePolicyScope }
        : {}),
      ...(args.record.routerAbNormalSigning
        ? { routerAbNormalSigning: args.record.routerAbNormalSigning }
        : {}),
      thresholdSessionKind: sealedRecoverySessionKind(args.record.walletSessionAuth),
      thresholdSessionId,
      signingGrantId,
      ...(walletSessionJwt ? { walletSessionJwt: walletSessionJwt } : {}),
      expiresAtMs: policy.expiresAtMs,
      remainingUses: policy.remainingUses,
      updatedAtMs: Date.now(),
      source: 'login',
    });
    publishResolvedIdentity({
      walletId: args.record.walletId,
      authMethod: 'passkey',
      curve: 'ed25519',
      chain: 'near',
      signingGrantId,
      thresholdSessionId,
    });
  };

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
    await args.deletePersistedRecord().catch(() => undefined);
    await args.recordSessionMaterialRestored(rehydrated);
    return rehydrated;
  }

  const parsed = await args.readWarmSessionStatusFromWorker(thresholdSessionId);
  if (!parsed) {
    await args.deletePersistedRecord().catch(() => undefined);
    const failed: WarmSessionStatusResult = {
      ok: false,
      code: 'worker_error',
      message: 'Warm-session status read failed after rehydrate',
    };
    await args.recordSessionMaterialRestored(failed);
    return failed;
  }
  if (!parsed.ok) {
    await args.deletePersistedRecord().catch(() => undefined);
    await args.recordSessionMaterialRestored(parsed);
    return parsed;
  }
  publishRecord({
    expiresAtMs: parsed.expiresAtMs,
    remainingUses: parsed.remainingUses,
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
