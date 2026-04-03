import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type { UnifiedIndexedDBManager } from '../../indexedDB';
import { buildNearAccountRefs } from '../../accountData/near/accountRefs';
import { resolveProfileAccountContextFromCandidates } from '../../indexedDB/profileAccountProjection';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../signingEngine/interfaces/signing';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../../signingEngine/orchestration/thresholdActivation';
import type { ThresholdEcdsaSessionStoreSource } from '../../signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import type { AccountId } from '../../types/accountIds';
import { toAccountId } from '../../types/accountIds';

export type PreparedLinkDeviceThresholdEcdsa = {
  relayerKeyId: string;
  groupPublicKeyB64u: string;
  ethereumAddress: string;
  relayerVerifyingShareB64u: string;
  participantIds?: number[];
  session?: {
    sessionKind?: string;
    sessionId?: string;
    expiresAtMs?: number;
    expiresAt?: string;
    participantIds?: number[];
    remainingUses?: number;
    jwt?: string;
  };
};

export type PreparedLinkDeviceLinkedAccount = {
  chainIdKey: string;
  chain: ThresholdEcdsaActivationChain;
  chainId: number;
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
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: ThresholdEcdsaSessionStoreSource;
  }) => void;
  persistThresholdEcdsaBootstrapChainAccount: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
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
    const key = `${account.chainIdKey}::${account.accountAddress}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(account);
  }
  return out;
}

function buildThresholdEcdsaBootstrap(args: {
  nearAccountId: AccountId | string;
  relayerUrl: string;
  clientVerifyingShareB64u: string;
  thresholdEcdsa: PreparedLinkDeviceThresholdEcdsa;
}): ThresholdEcdsaSessionBootstrapResult {
  const nearAccountId = toAccountId(args.nearAccountId);
  const session = args.thresholdEcdsa.session || {};
  const relayerKeyId = String(args.thresholdEcdsa.relayerKeyId || '').trim();
  const groupPublicKeyB64u = String(args.thresholdEcdsa.groupPublicKeyB64u || '').trim();
  const ethereumAddress = String(args.thresholdEcdsa.ethereumAddress || '').trim();
  const relayerVerifyingShareB64u = String(
    args.thresholdEcdsa.relayerVerifyingShareB64u || '',
  ).trim();
  const clientVerifyingShareB64u = String(args.clientVerifyingShareB64u || '').trim();
  const sessionKind = String(session.sessionKind || '').trim().toLowerCase();
  const sessionId = String(session.sessionId || '').trim();
  const expiresAtMs = Number(session.expiresAtMs);
  const remainingUses = Number(session.remainingUses);
  const jwt = String(session.jwt || '').trim();
  const participantIds =
    normalizeThresholdEd25519ParticipantIds(session.participantIds) ||
    normalizeThresholdEd25519ParticipantIds(args.thresholdEcdsa.participantIds);

  if (!relayerKeyId || !groupPublicKeyB64u || !ethereumAddress || !relayerVerifyingShareB64u) {
    throw new Error('link-device thresholdEcdsa payload missing keygen fields');
  }
  if (!clientVerifyingShareB64u) {
    throw new Error('link-device thresholdEcdsa payload missing clientVerifyingShareB64u');
  }
  if (sessionKind && sessionKind !== 'jwt') {
    throw new Error('link-device thresholdEcdsa sessionKind must be jwt');
  }
  if (!sessionId || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
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
    relayerUrl: String(args.relayerUrl || '').trim(),
    relayerKeyId,
    clientVerifyingShareB64u,
    participantIds,
    groupPublicKeyB64u,
    relayerVerifyingShareB64u,
    thresholdSessionKind: 'jwt',
    thresholdSessionId: sessionId,
    ...(jwt ? { thresholdSessionJwt: jwt } : {}),
  };

  return {
    thresholdEcdsaKeyRef,
    keygen: {
      ok: true,
      clientVerifyingShareB64u,
      relayerKeyId,
      groupPublicKeyB64u,
      ethereumAddress,
      relayerVerifyingShareB64u,
      participantIds,
    },
    session: {
      ok: true,
      sessionId,
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
  deviceNumber: number;
  rpId: string;
  credentialIdB64u: string;
  clientVerifyingShareB64u: string;
  thresholdEcdsa: PreparedLinkDeviceThresholdEcdsa;
  linkedAccounts: PreparedLinkDeviceLinkedAccount[];
}): Promise<void> {
  const linkedAccounts = dedupeLinkedAccounts(args.linkedAccounts || []);
  if (linkedAccounts.length === 0) return;

  const nearAccountId = toAccountId(args.nearAccountId);
  const bootstrap = buildThresholdEcdsaBootstrap({
    nearAccountId,
    relayerUrl: args.relayerUrl,
    clientVerifyingShareB64u: args.clientVerifyingShareB64u,
    thresholdEcdsa: args.thresholdEcdsa,
  });
  const thresholdOwnerAddress = String(args.thresholdEcdsa.ethereumAddress || '').trim();
  const uniqueChains = [...new Set(linkedAccounts.map((account) => account.chain))];

  for (const chain of uniqueChains) {
    args.signingEngine.upsertThresholdEcdsaSessionFromBootstrap({
      nearAccountId,
      chain,
      bootstrap,
      source: 'manual-bootstrap',
    });
  }

  for (const account of linkedAccounts) {
    await args.signingEngine.persistThresholdEcdsaBootstrapChainAccount({
      nearAccountId,
      chain: account.chain,
      bootstrap,
      smartAccount: {
        chainId: account.chainId,
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
    throw new Error(
      `[link-device] missing profile/account mapping for ${String(nearAccountId)}`,
    );
  }

  for (const account of linkedAccounts) {
    await args.indexedDB.upsertAccountSigner({
      profileId: nearContext.profileId,
      chainIdKey: account.chainIdKey,
      accountAddress: account.accountAddress,
      signerId: thresholdOwnerAddress,
      signerSlot: args.deviceNumber,
      signerType: 'threshold',
      status: 'pending',
      metadata: {
        accountModel: account.accountModel,
        ownerAddress: thresholdOwnerAddress,
        relayerKeyId: String(args.thresholdEcdsa.relayerKeyId || '').trim(),
        groupPublicKeyB64u: String(args.thresholdEcdsa.groupPublicKeyB64u || '').trim(),
        deviceNumber: args.deviceNumber,
        credentialIdB64u: String(args.credentialIdB64u || '').trim(),
        rpId: String(args.rpId || '').trim(),
        chain: account.chain,
        chainId: account.chainId,
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
      mutation: { routeThroughOutbox: false },
    });
  }
}
