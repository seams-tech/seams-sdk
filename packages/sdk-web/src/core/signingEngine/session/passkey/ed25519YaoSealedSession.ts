import type { PasskeyEd25519SealRestoreMetadata } from '@/core/types/secure-confirm-worker';
import type { NearResolvedEd25519SigningSessionState } from '../../interfaces/near';
import type { HydrateSigningSessionInput } from '../warmCapabilities/public';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { RouterAbEd25519NormalSigningState } from '../../threshold/ed25519/routerAbNormalSigningState';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';

export function buildPasskeyEd25519RestoreMetadata(args: {
  rpId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  relayerKeyId: string;
  participantIds: readonly number[];
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  signerSlot: number;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  credentialIdB64u: string;
  materialActivation: MpcMaterialActivationRef;
}): PasskeyEd25519SealRestoreMetadata {
  const rpId = String(args.rpId).trim();
  const nearAccountId = String(args.nearAccountId).trim();
  const nearEd25519SigningKeyId = String(args.nearEd25519SigningKeyId).trim();
  const relayerKeyId = String(args.relayerKeyId).trim();
  const credentialIdB64u = String(args.credentialIdB64u).trim();
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
  const signerSlot = Math.floor(Number(args.signerSlot));
  if (
    !rpId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !relayerKeyId ||
    !credentialIdB64u ||
    !participantIds ||
    !Number.isSafeInteger(signerSlot) ||
    signerSlot < 1
  ) {
    throw new Error('Passkey Ed25519 sealed restore metadata is incomplete');
  }
  return {
    rpId,
    nearAccountId,
    nearEd25519SigningKeyId,
    relayerKeyId,
    participantIds: [...participantIds],
    runtimePolicyScope: args.runtimePolicyScope,
    signerSlot,
    routerAbNormalSigning: args.routerAbNormalSigning,
    credentialIdB64u,
    materialActivation: args.materialActivation,
  };
}

export type PasskeyEd25519YaoSessionPersistencePort = {
  hydrateSigningSession(input: HydrateSigningSessionInput): Promise<void>;
};

export type PersistPasskeyEd25519YaoSessionForRefreshInput = {
  persistence: PasskeyEd25519YaoSessionPersistencePort;
  session: NearResolvedEd25519SigningSessionState;
  prfFirstB64u: string;
  ed25519Restore: PasskeyEd25519SealRestoreMetadata;
  materialActivation: MpcMaterialActivationRef;
};

export async function persistPasskeyEd25519YaoSessionForRefresh(
  input: PersistPasskeyEd25519YaoSessionForRefreshInput,
): Promise<void> {
  const thresholdSessionId = String(input.session.thresholdSessionId || '').trim();
  const walletSessionToken = String(input.session.walletSessionAuth.walletSessionToken || '').trim();
  const walletId = String(
    input.session.signingLane.identity.signer.account.wallet.walletId || '',
  ).trim();
  const prfFirstB64u = String(input.prfFirstB64u || '').trim();
  const expiresAtMs = Math.floor(Number(input.session.signingWalletSession.expiresAtMs) || 0);
  const remainingUses = Math.floor(Number(input.session.remainingUses));
  const laneAuth = input.session.signingLane.identity.auth;
  if (laneAuth.kind !== 'passkey') {
    throw new Error('Ed25519 Yao sealed refresh persistence requires a passkey lane');
  }
  if (
    !thresholdSessionId ||
    !walletSessionToken ||
    !walletId ||
    !prfFirstB64u ||
    expiresAtMs <= 0 ||
    !Number.isSafeInteger(remainingUses) ||
    remainingUses < 0
  ) {
    throw new Error('Ed25519 Yao sealed refresh persistence received an invalid session');
  }
  const signer = input.session.signingLane.identity.signer;
  if (
    walletId !== String(signer.account.wallet.walletId) ||
    input.ed25519Restore.nearAccountId !== String(signer.account.nearAccountId) ||
    input.ed25519Restore.nearEd25519SigningKeyId !== String(signer.nearEd25519SigningKeyId) ||
    input.ed25519Restore.signerSlot !== signer.signerSlot ||
    input.ed25519Restore.rpId !== String(laneAuth.rpId) ||
    input.ed25519Restore.credentialIdB64u !== laneAuth.credentialIdB64u ||
    !mpcMaterialActivationRefsEqual(
      input.ed25519Restore.materialActivation,
      input.materialActivation,
    ) ||
    input.ed25519Restore.routerAbNormalSigning?.signingWorkerId !==
      input.session.routerAbNormalSigning.signingWorkerId
  ) {
    throw new Error('Ed25519 Yao sealed refresh metadata does not match the exact session');
  }
  const transport = {
    curve: 'ed25519',
    authMethod: 'passkey',
    walletId,
    relayerUrl: input.session.relayerUrl,
    walletSessionToken,
    ed25519Restore: input.ed25519Restore,
  } as const;
  await input.persistence.hydrateSigningSession({
    thresholdSessionId,
    prfFirstB64u,
    expiresAtMs,
    remainingUses,
    transport,
  });
}
