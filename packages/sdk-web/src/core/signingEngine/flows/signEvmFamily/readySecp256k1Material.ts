import {
  buildKnownReadyThresholdEcdsaSessionPolicy,
  buildReadyEcdsaSignerSession,
  buildThresholdEcdsaSecp256k1KeyRefFromSessionRecord,
  toVerifiedEcdsaPublicFactsFromRecord,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  thresholdEcdsaRecordRpId,
  type ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import {
  classifyRouterAbEcdsaHssPersistedSigningRecord,
  requireRouterAbEcdsaHssSigningWalletSessionFromRecord,
} from '../../session/routerAbSigningWalletSession';
import {
  buildReadySecp256k1SigningMaterial,
  type ReadySecp256k1SigningMaterial,
} from './signers/secp256k1';

type EcdsaSessionChain = 'tempo' | 'evm';

function inferThresholdEcdsaSessionChainFromLabel(labelRaw: unknown): EcdsaSessionChain | null {
  const label = String(labelRaw || '')
    .trim()
    .toLowerCase();
  if (!label) return null;
  if (label === 'tempo' || label.startsWith('tempo:')) return 'tempo';
  if (label === 'evm' || label.startsWith('evm:')) return 'evm';
  return null;
}

export async function buildReadySecp256k1SigningMaterialFromRecord(args: {
  record: ThresholdEcdsaSessionRecord;
  requestLabel: unknown;
  rpId: unknown;
}): Promise<ReadySecp256k1SigningMaterial> {
  const rpId = String(args.rpId || '').trim();
  if (!rpId) {
    throw new Error('[multichain] Missing rpId for threshold-ecdsa signing');
  }
  const recordRpId = thresholdEcdsaRecordRpId(args.record);
  if (recordRpId !== rpId) {
    throw new Error('[multichain] threshold-ecdsa rpId mismatch; reconnect threshold session');
  }
  const requestChain = inferThresholdEcdsaSessionChainFromLabel(args.requestLabel);
  if (requestChain && args.record.chainTarget.kind !== requestChain) {
    throw new Error('[multichain] threshold-ecdsa chain mismatch; reconnect threshold session');
  }
  if (
    args.record.source === 'email_otp' &&
    args.record.emailOtpAuthContext?.retention === 'single_use' &&
    Number(args.record.emailOtpAuthContext.consumedAtMs) > 0
  ) {
    throw new Error(
      `[SigningEngine] ${requestChain || args.record.chainTarget.kind} signing requires fresh Email OTP verification with per_operation policy`,
    );
  }

  const workerMaterial = classifyRouterAbEcdsaHssPersistedSigningRecord(args.record);
  if (workerMaterial.kind !== 'runtime_validated') {
    throw new Error(
      `[multichain] threshold-ecdsa role-local worker material is not runtime-validated: ${workerMaterial.reason}`,
    );
  }

  const signingWalletSession = requireRouterAbEcdsaHssSigningWalletSessionFromRecord(args.record);
  const walletSessionJwt = signingWalletSession.auth.walletSessionJwt;

  const keyRef = buildThresholdEcdsaSecp256k1KeyRefFromSessionRecord({
    record: args.record,
  });
  const publicFacts = await toVerifiedEcdsaPublicFactsFromRecord({ record: args.record });
  const signerSession = buildReadyEcdsaSignerSession({
    keyRef,
    publicFacts,
    sessionPolicy: buildKnownReadyThresholdEcdsaSessionPolicy({
      remainingUses: args.record.remainingUses,
      expiresAtMs: args.record.expiresAtMs,
    }),
    walletSessionJwt,
  });

  return buildReadySecp256k1SigningMaterial({
    walletId: args.record.walletId,
    signerSession,
    singleUseEmailOtpSession:
      args.record.source === 'email_otp' &&
      args.record.emailOtpAuthContext?.retention === 'single_use',
  });
}
