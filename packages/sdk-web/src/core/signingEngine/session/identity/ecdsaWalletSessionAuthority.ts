import { requireEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  decodeJwtPayloadRecord,
  ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
  toWalletSessionThresholdExpiresAtMs,
  type WalletSessionThresholdExpiresAtMs,
} from '@shared/utils/sessionTokens';
import { toWalletId, type WalletId } from '../../interfaces/ecdsaChainTarget';
import { parseEcdsaRelayerKeyId, type EcdsaRelayerKeyId } from '../keyMaterialBrands';
import {
  buildEcdsaWalletSessionTransportAuth,
  toEvmFamilyEcdsaKeyHandle,
  toParticipantId,
  type EvmFamilyEcdsaKeyHandle,
  type EvmFamilySigningKeySlotId,
  type ParticipantId,
  type VerifiedWalletSessionJwt,
} from './evmFamilyEcdsaIdentity';
import {
  type SigningGrantId,
  type ThresholdEcdsaSessionId,
} from '../operationState/types';
import { buildEcdsaSessionIdentity } from '../warmCapabilities/ecdsaProvisionPlan';

export type EcdsaWalletSessionAuthority = {
  kind: 'ecdsa_wallet_session_authority';
  walletSessionJwt: VerifiedWalletSessionJwt;
  walletId: WalletId;
  evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  relayerKeyId: EcdsaRelayerKeyId;
  thresholdSessionId: ThresholdEcdsaSessionId;
  signingGrantId: SigningGrantId;
  thresholdExpiresAtMs: WalletSessionThresholdExpiresAtMs;
  participantIds: readonly ParticipantId[];
};

function requireEcdsaWalletSessionPayload(
  walletSessionJwt: VerifiedWalletSessionJwt,
): Record<string, unknown> {
  const payload = decodeJwtPayloadRecord(walletSessionJwt);
  if (payload?.kind !== ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND) {
    throw new Error('[SigningEngine][ecdsa] Wallet Session JWT kind is invalid');
  }
  return payload;
}

function requireEcdsaWalletSessionParticipantIds(value: unknown): readonly ParticipantId[] {
  const normalized = normalizeThresholdEd25519ParticipantIds(value);
  if (!normalized || normalized.length < 2) {
    throw new Error('[SigningEngine][ecdsa] Wallet Session JWT participantIds are invalid');
  }
  return normalized.map(toParticipantId);
}

function assertEcdsaWalletSessionClaimMatches(args: {
  field: string;
  expected: unknown;
  actual: unknown;
}): void {
  if (String(args.expected) === String(args.actual)) return;
  throw new Error(`[SigningEngine][ecdsa] Wallet Session JWT ${args.field} mismatch`);
}

export function buildEcdsaWalletSessionAuthority(args: {
  walletSessionJwt: string;
  walletId: unknown;
  evmFamilySigningKeySlotId: unknown;
  keyHandle: unknown;
  thresholdSessionId: string;
  signingGrantId: string;
}): EcdsaWalletSessionAuthority {
  const walletSessionAuth = buildEcdsaWalletSessionTransportAuth({
    kind: 'wallet_session_jwt',
    walletSessionJwt: args.walletSessionJwt,
  });
  const identity = buildEcdsaSessionIdentity({
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
  });
  const payload = requireEcdsaWalletSessionPayload(walletSessionAuth.walletSessionJwt);
  const walletId = toWalletId(payload.walletId);
  const evmFamilySigningKeySlotId = requireEvmFamilySigningKeySlotId(
    payload.evmFamilySigningKeySlotId,
  );
  const keyHandle = toEvmFamilyEcdsaKeyHandle(payload.keyHandle);
  const relayerKeyId = parseEcdsaRelayerKeyId(payload.relayerKeyId);
  const claimsIdentity = buildEcdsaSessionIdentity({
    thresholdSessionId: payload.thresholdSessionId,
    signingGrantId: payload.signingGrantId,
  });
  assertEcdsaWalletSessionClaimMatches({
    field: 'walletId',
    expected: args.walletId,
    actual: walletId,
  });
  assertEcdsaWalletSessionClaimMatches({
    field: 'evmFamilySigningKeySlotId',
    expected: args.evmFamilySigningKeySlotId,
    actual: evmFamilySigningKeySlotId,
  });
  assertEcdsaWalletSessionClaimMatches({
    field: 'keyHandle',
    expected: args.keyHandle,
    actual: keyHandle,
  });
  if (
    claimsIdentity.thresholdSessionId !== identity.thresholdSessionId ||
    claimsIdentity.signingGrantId !== identity.signingGrantId
  ) {
    throw new Error('[SigningEngine][ecdsa] Wallet Session JWT identity mismatch');
  }
  return {
    kind: 'ecdsa_wallet_session_authority',
    walletSessionJwt: walletSessionAuth.walletSessionJwt,
    walletId,
    evmFamilySigningKeySlotId,
    keyHandle,
    relayerKeyId,
    thresholdSessionId: identity.thresholdSessionId,
    signingGrantId: identity.signingGrantId,
    thresholdExpiresAtMs: toWalletSessionThresholdExpiresAtMs(payload.thresholdExpiresAtMs),
    participantIds: requireEcdsaWalletSessionParticipantIds(payload.participantIds),
  };
}
