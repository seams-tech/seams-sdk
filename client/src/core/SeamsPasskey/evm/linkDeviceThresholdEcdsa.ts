import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { SIGNER_AUTH_METHODS, SIGNER_KINDS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import type { UnifiedIndexedDBManager } from '../../indexedDB';
import { buildNearAccountRefs } from '../../accountData/near/accountRefs';
import { resolveProfileAccountContextFromCandidates } from '../../indexedDB/profileAccountProjection';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../signingEngine/interfaces/signing';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../signingEngine/orchestration/thresholdActivation';
import {
  thresholdEcdsaChainTargetKey,
  toWalletSubjectId,
  type ThresholdEcdsaChainTarget,
} from '../../signingEngine/session/signingSession/ecdsaChainTarget';
import type { ThresholdEcdsaSessionStoreSource } from '../../signingEngine/api/thresholdLifecycle/thresholdSessionStore';
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

export type PreparedLinkDeviceLinkedAccount = {
  chainIdKey: string;
  chainTarget: ThresholdEcdsaChainTarget;
  accountAddress: string;
  accountModel: 'erc4337' | 'tempo-native';
  factory?: string;
  entryPoint?: string;
  salt?: string;
  counterfactualAddress?: string;
};

type LinkDeviceThresholdEcdsaSigningPort = {
  upsertThresholdEcdsaSessionFromBootstrap: (args: {
    nearAccountId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: ThresholdEcdsaSessionStoreSource;
  }) => void;
  persistThresholdEcdsaBootstrapChainAccount: (args: {
    nearAccountId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    smartAccount?: {
      chainId: number;
      factory?: string;
      entryPoint?: string;
      salt?: string;
      counterfactualAddress?: string;
    };
    deployment?: {
      deployed: boolean;
      deploymentTxHash?: string;
    };
  }) => Promise<void>;
};

function dedupeLinkedAccounts(
  linkedAccounts: PreparedLinkDeviceLinkedAccount[],
): PreparedLinkDeviceLinkedAccount[] {
  const seen = new Set<string>();
  const out: PreparedLinkDeviceLinkedAccount[] = [];
  for (const account of linkedAccounts) {
    const key = `${account.chainIdKey}::${thresholdEcdsaChainTargetKey(account.chainTarget)}::${account.accountAddress}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(account);
  }
  return out;
}

function buildThresholdEcdsaBootstrap(args: {
  nearAccountId: AccountId | string;
  relayerUrl: string;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdEcdsa: PreparedLinkDeviceThresholdEcdsa;
}): ThresholdEcdsaSessionBootstrapResult {
  const nearAccountId = toAccountId(args.nearAccountId);
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
    userId: nearAccountId,
    subjectId: toWalletSubjectId(nearAccountId),
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
    ...(jwt ? { thresholdSessionJwt: jwt } : {}),
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
  indexedDB: UnifiedIndexedDBManager;
  signingEngine: LinkDeviceThresholdEcdsaSigningPort;
  nearAccountId: AccountId | string;
  relayerUrl: string;
  signerSlot: number;
  rpId: string;
  credentialIdB64u: string;
  thresholdEcdsa: PreparedLinkDeviceThresholdEcdsa;
  linkedAccounts: PreparedLinkDeviceLinkedAccount[];
}): Promise<void> {
  const linkedAccounts = dedupeLinkedAccounts(args.linkedAccounts || []);
  if (linkedAccounts.length === 0) return;

  const nearAccountId = toAccountId(args.nearAccountId);
  const thresholdOwnerAddress = String(args.thresholdEcdsa.ethereumAddress || '').trim();
  const uniqueTargetKeys = [
    ...new Set(linkedAccounts.map((account) => thresholdEcdsaChainTargetKey(account.chainTarget))),
  ];
  const bootstrapByTargetKey = new Map<string, ThresholdEcdsaSessionBootstrapResult>();
  const bootstrapForTarget = (
    chainTarget: ThresholdEcdsaChainTarget,
  ): ThresholdEcdsaSessionBootstrapResult => {
    const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
    const existing = bootstrapByTargetKey.get(targetKey);
    if (existing) return existing;
    const bootstrap = buildThresholdEcdsaBootstrap({
      nearAccountId,
      relayerUrl: args.relayerUrl,
      chainTarget,
      thresholdEcdsa: args.thresholdEcdsa,
    });
    bootstrapByTargetKey.set(targetKey, bootstrap);
    return bootstrap;
  };
  const signerSlot = Math.max(1, Math.floor(Number(args.signerSlot) || 1));

  for (const targetKey of uniqueTargetKeys) {
    const account = linkedAccounts.find(
      (candidate) => thresholdEcdsaChainTargetKey(candidate.chainTarget) === targetKey,
    );
    if (!account) continue;
    const bootstrap = bootstrapForTarget(account.chainTarget);
    args.signingEngine.upsertThresholdEcdsaSessionFromBootstrap({
      nearAccountId,
      chainTarget: account.chainTarget,
      bootstrap,
      source: 'manual-bootstrap',
    });
  }

  for (const account of linkedAccounts) {
    const bootstrap = bootstrapForTarget(account.chainTarget);
    await args.signingEngine.persistThresholdEcdsaBootstrapChainAccount({
      nearAccountId,
      chainTarget: account.chainTarget,
      bootstrap,
      smartAccount: {
        chainId: account.chainTarget.chainId,
        ...(account.factory ? { factory: account.factory } : {}),
        ...(account.entryPoint ? { entryPoint: account.entryPoint } : {}),
        ...(account.salt ? { salt: account.salt } : {}),
        ...(account.counterfactualAddress
          ? { counterfactualAddress: account.counterfactualAddress }
          : {}),
      },
    });
  }

  const nearContext = await resolveProfileAccountContextFromCandidates(
    args.indexedDB.clientDB,
    buildNearAccountRefs(nearAccountId),
  );
  if (!nearContext?.profileId) {
    throw new Error(`[link-device] missing profile/account mapping for ${String(nearAccountId)}`);
  }

  for (const account of linkedAccounts) {
    const bootstrap = bootstrapForTarget(account.chainTarget);
    await args.indexedDB.stageAccountSigner({
      account: {
        profileId: nearContext.profileId,
        chainIdKey: account.chainIdKey,
        accountAddress: account.accountAddress,
        accountModel: account.accountModel,
      },
      signer: {
        signerId: thresholdOwnerAddress,
        signerSlot,
        signerType: 'threshold',
        signerKind: SIGNER_KINDS.thresholdEcdsa,
        signerAuthMethod: SIGNER_AUTH_METHODS.passkey,
        signerSource: SIGNER_SOURCES.passkeyRegistration,
        metadata: {
          accountModel: account.accountModel,
          ownerAddress: thresholdOwnerAddress,
          ecdsaThresholdKeyId: bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId,
          relayerKeyId: String(args.thresholdEcdsa.relayerKeyId || '').trim(),
          thresholdEcdsaPublicKeyB64u: String(
            args.thresholdEcdsa.thresholdEcdsaPublicKeyB64u || '',
          ).trim(),
          signerSlot,
          credentialIdB64u: String(args.credentialIdB64u || '').trim(),
          rpId: String(args.rpId || '').trim(),
          chainTarget: account.chainTarget,
          chainId: account.chainTarget.chainId,
          ...(Array.isArray(bootstrap.keygen.participantIds)
            ? { participantIds: [...bootstrap.keygen.participantIds] }
            : {}),
          ...(account.factory ? { factory: account.factory } : {}),
          ...(account.entryPoint ? { entryPoint: account.entryPoint } : {}),
          ...(account.salt ? { salt: account.salt } : {}),
          ...(account.counterfactualAddress
            ? { counterfactualAddress: account.counterfactualAddress }
            : {}),
        },
      },
      mutation: { routeThroughOutbox: false },
    });
  }
}
