import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../signingEngine/interfaces/signing';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../signingEngine/threshold/ecdsa/activation';
import {
  walletSubjectIdFromWalletProfile,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionStoreSource } from '../../signingEngine/session/identity/laneIdentity';
import type { AccountId } from '../../types/accountIds';
import { toAccountId } from '../../types/accountIds';

export type PreparedLinkDeviceThresholdEcdsa = {
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion?: string;
  clientVerifyingShareB64u: string;
  clientAdditiveShare32B64u: string;
  relayerKeyId: string;
  thresholdEcdsaPublicKeyB64u: string;
  ethereumAddress: string;
  relayerVerifyingShareB64u: string;
  participantIds?: number[];
  session?: {
    sessionKind?: string;
    sessionId?: string;
    walletSigningSessionId?: string;
    expiresAtMs?: number;
    expiresAt?: string;
    participantIds?: number[];
    remainingUses?: number;
    jwt?: string;
  };
};

type LinkDeviceThresholdEcdsaSigningPort = {
  upsertThresholdEcdsaSessionFromBootstrap: (args: {
    walletId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: ThresholdEcdsaSessionStoreSource;
  }) => void;
  persistThresholdEcdsaBootstrapForWalletTarget: (args: {
    walletId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
  }) => Promise<void>;
};

function buildThresholdEcdsaBootstrap(args: {
  walletId: AccountId | string;
  relayerUrl: string;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdEcdsa: PreparedLinkDeviceThresholdEcdsa;
}): ThresholdEcdsaSessionBootstrapResult {
  const walletId = toAccountId(args.walletId);
  const session = args.thresholdEcdsa.session || {};
  const ecdsaThresholdKeyId = String(args.thresholdEcdsa.ecdsaThresholdKeyId || '').trim();
  const signingRootId = String(args.thresholdEcdsa.signingRootId || '').trim();
  const signingRootVersion = String(args.thresholdEcdsa.signingRootVersion || '').trim();
  const relayerKeyId = String(args.thresholdEcdsa.relayerKeyId || '').trim();
  const thresholdEcdsaPublicKeyB64u = String(
    args.thresholdEcdsa.thresholdEcdsaPublicKeyB64u || '',
  ).trim();
  const ethereumAddress = String(args.thresholdEcdsa.ethereumAddress || '').trim();
  const relayerVerifyingShareB64u = String(
    args.thresholdEcdsa.relayerVerifyingShareB64u || '',
  ).trim();
  const clientVerifyingShareB64u = String(
    args.thresholdEcdsa.clientVerifyingShareB64u || '',
  ).trim();
  const clientAdditiveShare32B64u = String(
    args.thresholdEcdsa.clientAdditiveShare32B64u || '',
  ).trim();
  const sessionKind = String(session.sessionKind || '')
    .trim()
    .toLowerCase();
  const sessionId = String(session.sessionId || '').trim();
  const walletSigningSessionId = String(session.walletSigningSessionId || '').trim();
  const expiresAtMs = Number(session.expiresAtMs);
  const remainingUses = Number(session.remainingUses);
  const jwt = String(session.jwt || '').trim();
  const participantIds =
    normalizeThresholdEd25519ParticipantIds(session.participantIds) ||
    normalizeThresholdEd25519ParticipantIds(args.thresholdEcdsa.participantIds);

  if (!ecdsaThresholdKeyId) {
    throw new Error('link-device thresholdEcdsa payload missing ecdsaThresholdKeyId');
  }
  if (!signingRootId) {
    throw new Error('link-device thresholdEcdsa payload missing signingRootId');
  }
  if (
    !relayerKeyId ||
    !thresholdEcdsaPublicKeyB64u ||
    !ethereumAddress ||
    !relayerVerifyingShareB64u
  ) {
    throw new Error('link-device thresholdEcdsa payload missing keygen fields');
  }
  if (!clientVerifyingShareB64u) {
    throw new Error('link-device thresholdEcdsa payload missing clientVerifyingShareB64u');
  }
  if (!clientAdditiveShare32B64u) {
    throw new Error('link-device thresholdEcdsa payload missing clientAdditiveShare32B64u');
  }
  if (sessionKind && sessionKind !== 'jwt') {
    throw new Error('link-device thresholdEcdsa sessionKind must be jwt');
  }
  if (!sessionId || !walletSigningSessionId || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    throw new Error('link-device thresholdEcdsa payload missing session fields');
  }
  if (!Number.isFinite(remainingUses) || remainingUses <= 0) {
    throw new Error('link-device thresholdEcdsa payload missing remainingUses');
  }
  if (!participantIds || participantIds.length < 2) {
    throw new Error('link-device thresholdEcdsa payload missing participantIds');
  }

  const thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef = {
    type: 'threshold-ecdsa-secp256k1',
    userId: walletId,
    subjectId: walletSubjectIdFromWalletProfile({ walletId }),
    chainTarget: args.chainTarget,
    relayerUrl: String(args.relayerUrl || '').trim(),
    ecdsaThresholdKeyId,
    signingRootId,
    ...(signingRootVersion ? { signingRootVersion } : {}),
    backendBinding: {
      relayerKeyId,
      clientVerifyingShareB64u,
      clientAdditiveShare32B64u,
    },
    participantIds,
    thresholdEcdsaPublicKeyB64u,
    ethereumAddress,
    relayerVerifyingShareB64u,
    thresholdSessionKind: 'jwt',
    thresholdSessionId: sessionId,
    walletSigningSessionId,
    ...(jwt ? { thresholdSessionAuthToken: jwt } : {}),
  };

  return {
    thresholdEcdsaKeyRef,
    keygen: {
      ok: true,
      ecdsaThresholdKeyId,
      clientVerifyingShareB64u,
      clientAdditiveShare32B64u,
      relayerKeyId,
      thresholdEcdsaPublicKeyB64u,
      ethereumAddress,
      relayerVerifyingShareB64u,
      participantIds,
    },
    session: {
      ok: true,
      sessionId,
      walletSigningSessionId,
      expiresAtMs,
      remainingUses,
      jwt,
      clientVerifyingShareB64u,
    },
  };
}

export async function persistLinkDeviceThresholdEcdsaBootstrap(args: {
  signingEngine: LinkDeviceThresholdEcdsaSigningPort;
  walletId: AccountId | string;
  relayerUrl: string;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdEcdsa: PreparedLinkDeviceThresholdEcdsa;
}): Promise<void> {
  const walletId = toAccountId(args.walletId);
  const bootstrap = buildThresholdEcdsaBootstrap({
    walletId,
    relayerUrl: args.relayerUrl,
    chainTarget: args.chainTarget,
    thresholdEcdsa: args.thresholdEcdsa,
  });

  args.signingEngine.upsertThresholdEcdsaSessionFromBootstrap({
    walletId,
    chainTarget: args.chainTarget,
    bootstrap,
    source: 'manual-bootstrap',
  });
  await args.signingEngine.persistThresholdEcdsaBootstrapForWalletTarget({
    walletId,
    chainTarget: args.chainTarget,
    bootstrap,
  });
}
