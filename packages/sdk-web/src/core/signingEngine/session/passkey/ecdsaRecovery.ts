import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { RestorePersistedEcdsaSessionPurpose } from '@/core/signingEngine/session/sealedRecovery/sealedRecovery.types';
import {
  sealedRecoverySessionKind,
  sealedRecoveryWalletSessionJwt,
  type PasskeyEcdsaSealedRecoveryRecord,
} from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import { thresholdEcdsaChainTargetsEqual } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toEvmFamilyEcdsaKeyHandle } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { publishResolvedIdentity } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  parseSigningSessionSealKeyVersion,
  parseEcdsaRoleLocalDurableMaterialRef,
  type SigningSessionSealKeyVersion,
} from '../keyMaterialBrands';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  toExactEcdsaSigningLaneIdentity,
  upsertRestoredThresholdEcdsaSessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import {
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import { buildEcdsaSessionIdentity } from '@/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan';
import { claimWarmSessionPrfFirst, type PasskeyWarmSessionRecoveryPorts } from './prfClaim';
import { requireEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import {
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
  parseSdkEcdsaDerivationThresholdKeyId,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';

type PasskeySessionRestoreIdentity = {
  touchConfirm: PasskeyWarmSessionRecoveryPorts;
  walletId: string;
  signingGrantId: string;
  thresholdSessionId: string;
};

type PasskeyEcdsaSealedPolicy = {
  expiresAtMs: number;
  remainingUses: number;
};

function shouldDeletePasskeyEcdsaSealedRecordAfterRestoreFailure(
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

export type PasskeyEcdsaPrfClaimArgs = PasskeySessionRestoreIdentity & {
  chainTarget: ThresholdEcdsaChainTarget;
  errorContext: string;
  uses?: number;
  consume?: boolean;
};

function passkeyEcdsaRoleLocalParticipantIds(participantIds: readonly number[]): readonly [1, 2] {
  if (participantIds.length !== 2 || participantIds[0] !== 1 || participantIds[1] !== 2) {
    throw new Error('passkey ECDSA restore requires participantIds [1, 2]');
  }
  return [1, 2] as const;
}

function passkeyEcdsaRoleLocalAuthMethod(args: {
  walletId: string;
  record: PasskeyEcdsaSealedRecoveryRecord;
}) {
  if (String(args.record.authority.walletId) !== String(toWalletId(args.walletId))) {
    throw new Error('passkey ECDSA restore authority wallet does not match record wallet');
  }
  return buildEcdsaRoleLocalPasskeyAuthMethod({
    credentialIdB64u: args.record.authority.factor.credentialIdB64u,
    rpId: args.record.authority.verifier.rpId,
  });
}

function passkeyEcdsaRoleLocalPublicFacts(args: {
  walletId: string;
  record: PasskeyEcdsaSealedRecoveryRecord;
}) {
  const capability = args.record.publicCapability;
  const publicIdentity = capability.public_identity;
  return buildEcdsaRoleLocalPublicFacts({
    walletId: toWalletId(args.walletId),
    evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(
      args.record.evmFamilySigningKeySlotId,
      'evmFamilySigningKeySlotId',
    ),
    chainTarget: args.record.chainTarget,
    keyHandle: args.record.keyHandle,
    ecdsaThresholdKeyId: parseSdkEcdsaDerivationThresholdKeyId(args.record.ecdsaThresholdKeyId),
    signingRootId: parseSdkEcdsaDerivationSigningRootId(args.record.signingRootId),
    signingRootVersion: parseSdkEcdsaDerivationSigningRootVersion(args.record.signingRootVersion),
    applicationBindingDigestB64u: capability.context.application_binding_digest_b64u,
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: passkeyEcdsaRoleLocalParticipantIds(args.record.participantIds),
    contextBinding32B64u: publicIdentity.context_binding_b64u,
    derivationClientSharePublicKey33B64u: publicIdentity.derivation_client_share_public_key33_b64u,
    relayerPublicKey33B64u: publicIdentity.server_public_key33_b64u,
    groupPublicKey33B64u: publicIdentity.threshold_public_key33_b64u,
    ethereumAddress: args.record.ethereumAddress,
    publicCapability: capability,
  });
}

async function publishPasskeyEcdsaSealedRecordForWallet(args: {
  walletId: string;
  record: PasskeyEcdsaSealedRecoveryRecord;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
  signingGrantId: string;
  policy: PasskeyEcdsaSealedPolicy;
}): Promise<void> {
  const walletSessionJwt = sealedRecoveryWalletSessionJwt(args.record.walletSessionAuth);
  const existingRecord = getStoredThresholdEcdsaSessionRecordByThresholdSessionId(
    args.thresholdSessionId,
  );
  const ecdsaRoleLocalAuthMethod = passkeyEcdsaRoleLocalAuthMethod({
    walletId: args.walletId,
    record: args.record,
  });
  const ecdsaRoleLocalPublicFacts = passkeyEcdsaRoleLocalPublicFacts({
    walletId: args.walletId,
    record: args.record,
  });
  const updatedAtMs = Date.now();

  upsertRestoredThresholdEcdsaSessionRecord({
    purpose: 'transaction_signing',
    walletId: toWalletId(args.walletId),
    evmFamilySigningKeySlotId: args.record.evmFamilySigningKeySlotId,
    chainTarget: args.record.chainTarget,
    relayerUrl: args.record.relayerUrl,
    keyHandle: toEvmFamilyEcdsaKeyHandle(args.record.keyHandle),
    ecdsaThresholdKeyId: args.record.ecdsaThresholdKeyId,
    signingRootId: args.record.signingRootId,
    signingRootVersion: args.record.signingRootVersion,
    relayerKeyId: args.record.relayerKeyId,
    clientVerifyingShareB64u: args.record.clientVerifyingShareB64u,
    roleLocalDurableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef(
      args.record.roleLocalDurableMaterialRef,
    ),
    ecdsaRoleLocalAuthMethod,
    ecdsaRoleLocalPublicFacts,
    participantIds: [...args.record.participantIds],
    thresholdEcdsaPublicKeyB64u: args.record.thresholdEcdsaPublicKeyB64u,
    ethereumAddress: args.record.ethereumAddress,
    ...(args.record.runtimePolicyScope
      ? { runtimePolicyScope: args.record.runtimePolicyScope }
      : existingRecord?.runtimePolicyScope
        ? { runtimePolicyScope: existingRecord.runtimePolicyScope }
        : {}),
    routerAbEcdsaDerivationNormalSigning: args.record.routerAbEcdsaDerivationNormalSigning,
    thresholdSessionKind: sealedRecoverySessionKind(args.record.walletSessionAuth),
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    ...(walletSessionJwt ? { walletSessionJwt } : {}),
    ...(args.record.keyVersion ? { signingSessionSealKeyVersion: args.record.keyVersion } : {}),
    ...(args.record.shamirPrimeB64u
      ? { signingSessionSealShamirPrimeB64u: args.record.shamirPrimeB64u }
      : {}),
    expiresAtMs: args.policy.expiresAtMs,
    remainingUses: args.policy.remainingUses,
    updatedAtMs,
    source: args.record.source,
  });
  publishResolvedIdentity({
    walletId: args.walletId,
    authMethod: 'passkey',
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    signingGrantId: args.signingGrantId,
    thresholdSessionId: args.thresholdSessionId,
    updatedAtMs,
  });
}

export async function restorePasskeyEcdsaSessionBeforeClaim(
  args: PasskeySessionRestoreIdentity & { chainTarget: ThresholdEcdsaChainTarget },
): Promise<void> {
  if (typeof args.touchConfirm.restorePersistedSessionForSigning !== 'function') return;
  const identity = buildEcdsaSessionIdentity({
    signingGrantId: args.signingGrantId,
    thresholdSessionId: args.thresholdSessionId,
  });
  const record = getStoredThresholdEcdsaSessionRecordByThresholdSessionId(
    identity.thresholdSessionId,
  );
  if (!record || !thresholdEcdsaChainTargetsEqual(record.chainTarget, args.chainTarget)) {
    throw new Error('[SigningEngine][ecdsa] exact restore identity unavailable before PRF claim');
  }
  const laneIdentity = toExactEcdsaSigningLaneIdentity(record);
  await args.touchConfirm.restorePersistedSessionForSigning({
    walletId: String(args.walletId).trim(),
    authMethod: 'passkey',
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    signingGrantId: identity.signingGrantId,
    thresholdSessionId: identity.thresholdSessionId,
    reason: 'transaction',
    materialRestoreIdentity: {
      kind: 'ecdsa_role_local_restore',
      lane: laneIdentity,
      ecdsaThresholdKeyId: laneIdentity.signer.key.ecdsaThresholdKeyId,
    },
  });
}

export async function claimPasskeyEcdsaPrfFirst(args: PasskeyEcdsaPrfClaimArgs): Promise<string> {
  return await claimWarmSessionPrfFirst({
    touchConfirm: args.touchConfirm,
    thresholdSessionId: args.thresholdSessionId,
    errorContext: args.errorContext,
    uses: args.uses,
    ...(typeof args.consume === 'boolean' ? { consume: args.consume } : {}),
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    restoreBeforeClaim: () =>
      restorePasskeyEcdsaSessionBeforeClaim({
        touchConfirm: args.touchConfirm,
        walletId: args.walletId,
        signingGrantId: args.signingGrantId,
        thresholdSessionId: args.thresholdSessionId,
        chainTarget: args.chainTarget,
      }),
  });
}

export async function restorePasskeyEcdsaSealedRecordForWallet(args: {
  walletId: string;
  record: PasskeyEcdsaSealedRecoveryRecord;
  purpose: RestorePersistedEcdsaSessionPurpose & { authMethod: 'passkey' };
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
  if (!thresholdEcdsaChainTargetsEqual(args.record.chainTarget, args.purpose.chainTarget)) {
    return null;
  }
  const thresholdSessionId = String(args.purpose.thresholdSessionId || '').trim();
  const signingGrantId = String(args.purpose.signingGrantId || '').trim();
  if (!thresholdSessionId || !signingGrantId || !args.shamirPrimeB64u) {
    return null;
  }

  try {
    await publishPasskeyEcdsaSealedRecordForWallet({
      walletId: args.walletId,
      record: args.record,
      chainTarget: args.purpose.chainTarget,
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
      code: 'invalid_role_local_durable_restore',
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
      await publishPasskeyEcdsaSealedRecordForWallet({
        walletId: args.walletId,
        record: args.record,
        chainTarget: args.purpose.chainTarget,
        thresholdSessionId,
        signingGrantId,
        policy: {
          expiresAtMs: Math.floor(Number(args.record.expiresAtMs) || 0),
          remainingUses: 0,
        },
      }).catch(() => undefined);
    }
    if (shouldDeletePasskeyEcdsaSealedRecordAfterRestoreFailure(rehydrated)) {
      await args.deletePersistedRecord().catch(() => undefined);
    }
    await args.recordSessionMaterialRestored(rehydrated);
    return rehydrated;
  }

  try {
    await publishPasskeyEcdsaSealedRecordForWallet({
      walletId: args.walletId,
      record: args.record,
      chainTarget: args.purpose.chainTarget,
      thresholdSessionId,
      signingGrantId,
      policy: {
        expiresAtMs: rehydrated.expiresAtMs,
        remainingUses: rehydrated.remainingUses,
      },
    });
  } catch (error) {
    return {
      ok: false,
      code: 'invalid_role_local_durable_restore',
      message: error instanceof Error ? error.message : String(error),
    };
  }
  await args.recordSessionMaterialRestored(rehydrated);
  const parsed = await args.readWarmSessionStatusFromWorker(thresholdSessionId);
  if (!parsed) {
    return {
      ok: false,
      code: 'worker_error',
      message: 'Warm-session status read failed after rehydrate',
    };
  }
  if (parsed.ok) {
    await publishPasskeyEcdsaSealedRecordForWallet({
      walletId: args.walletId,
      record: args.record,
      chainTarget: args.purpose.chainTarget,
      thresholdSessionId,
      signingGrantId,
      policy: {
        expiresAtMs: parsed.expiresAtMs,
        remainingUses: parsed.remainingUses,
      },
    }).catch(() => undefined);
    await args
      .updatePersistedPolicy({
        expiresAtMs: parsed.expiresAtMs,
        remainingUses: parsed.remainingUses,
        updatedAtMs: Date.now(),
      })
      .catch(() => undefined);
  } else {
    if (parsed.code === 'exhausted') {
      await publishPasskeyEcdsaSealedRecordForWallet({
        walletId: args.walletId,
        record: args.record,
        chainTarget: args.purpose.chainTarget,
        thresholdSessionId,
        signingGrantId,
        policy: {
          expiresAtMs: Math.floor(Number(args.record.expiresAtMs) || 0),
          remainingUses: 0,
        },
      });
    }
    if (shouldDeletePasskeyEcdsaSealedRecordAfterRestoreFailure(parsed)) {
      await args.deletePersistedRecord().catch(() => undefined);
    }
  }
  return parsed;
}
