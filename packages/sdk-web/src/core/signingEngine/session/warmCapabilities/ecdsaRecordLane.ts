import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { SigningLaneAuthBinding } from '../identity/signingLaneAuthBinding';
import type { ExactEcdsaSigningLaneIdentity } from '../identity/exactSigningLaneIdentity';
import { emailOtpAuthContextProviderUserId } from '../identity/laneIdentity';
import { thresholdEcdsaChainTargetsEqual } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';

// Record-boundary helpers for the legacy ThresholdEcdsaSessionRecord family.
// The `record.source` inference stays local to this parser boundary: canonical
// capability and operation logic receives the resulting SigningLaneAuthBinding
// and never branches on the record source itself. Both helpers are deleted
// with the record family in the Unit 3a cutover.

export function ecdsaSigningLaneAuthBindingForRecord(
  record: ThresholdEcdsaSessionRecord,
): SigningLaneAuthBinding {
  if (record.source === SIGNER_AUTH_METHODS.emailOtp) {
    const providerSubjectId = emailOtpAuthContextProviderUserId(record.emailOtpAuthContext);
    if (!providerSubjectId) {
      throw new Error('[WarmSessionStore] Email OTP ECDSA record is missing auth subject');
    }
    return {
      kind: SIGNER_AUTH_METHODS.emailOtp,
      providerSubjectId,
    };
  }
  const authMethod = record.ecdsaRoleLocalAuthMethod;
  if (authMethod.kind !== 'passkey') {
    throw new Error('[WarmSessionStore] passkey ECDSA record has non-passkey role-local auth');
  }
  return {
    kind: SIGNER_AUTH_METHODS.passkey,
    rpId: authMethod.rpId,
    credentialIdB64u: authMethod.credentialIdB64u,
  };
}

function signingLaneAuthBindingsEqual(
  left: SigningLaneAuthBinding,
  right: SigningLaneAuthBinding,
): boolean {
  if (left.kind === SIGNER_AUTH_METHODS.passkey && right.kind === SIGNER_AUTH_METHODS.passkey) {
    return (
      String(left.rpId) === String(right.rpId) &&
      left.credentialIdB64u === right.credentialIdB64u
    );
  }
  if (left.kind === SIGNER_AUTH_METHODS.emailOtp && right.kind === SIGNER_AUTH_METHODS.emailOtp) {
    return left.providerSubjectId === right.providerSubjectId;
  }
  return false;
}

// Matches a legacy record against an exact ECDSA lane identity on the stable
// material identity (wallet, chain target, key handle, material activation)
// and the auth binding. Wallet Session authorization and rotating session or
// grant identifiers deliberately do not participate: the lane's authorization
// proof is independent of which durable record carries the material.
export function ecdsaRecordMatchesExactLaneIdentity(args: {
  record: ThresholdEcdsaSessionRecord;
  lane: ExactEcdsaSigningLaneIdentity;
}): boolean {
  const { record, lane } = args;
  const signer = lane.signer;
  if (String(record.walletId || '').trim() !== String(signer.walletId)) return false;
  if (!thresholdEcdsaChainTargetsEqual(record.chainTarget, signer.chainTarget)) return false;
  if (String(record.keyHandle || '').trim() !== String(signer.keyHandle)) return false;
  if (!mpcMaterialActivationRefsEqual(record.materialActivation, signer.materialActivation)) {
    return false;
  }
  let recordAuth: SigningLaneAuthBinding;
  try {
    recordAuth = ecdsaSigningLaneAuthBindingForRecord(record);
  } catch {
    return false;
  }
  return signingLaneAuthBindingsEqual(recordAuth, lane.auth);
}
