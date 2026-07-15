import type { AccountId } from '@/core/types/accountIds';
import type { NearEd25519YaoSigningCapability } from '@/core/signingEngine/interfaces/near';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  type ThresholdEd25519SessionRecord,
} from '../persistence/records';
import type { ThresholdEd25519WebAuthnPrfSecretSource } from '../../threshold/ed25519/walletSession';
import {
  exactEd25519SigningLaneIdentity,
  exactSigningLaneIdentityKey,
  nearEd25519SignerBindingFromBoundaryFields,
} from '../identity/exactSigningLaneIdentity';
import { toRpId } from '../identity/evmFamilyEcdsaIdentity';
import type {
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
} from '../warmCapabilities/types';
import { resolveRouterAbEd25519WalletSessionStateFromRecord } from '../warmCapabilities/routerAbEd25519WalletSessionState';
import type {
  Ed25519YaoActiveClientIdentityV1,
  Ed25519YaoSameIdentityWalletSessionRefreshResultV1,
} from '../../threshold/ed25519/yaoActiveClientRegistry';

function exactPasskeyEd25519RefreshLaneIdentity(args: {
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

function readRefreshedEd25519Record(args: {
  sessionId: string;
  signingGrantId: string;
  reader?: (thresholdSessionId: string) => ThresholdEd25519SessionRecord | null;
}): ThresholdEd25519SessionRecord {
  const record =
    args.reader?.(args.sessionId) ||
    getStoredThresholdEd25519SessionRecordByThresholdSessionId(args.sessionId);
  if (!record) {
    throw new Error(
      '[SigningEngine][near] passkey Ed25519 budget refresh did not publish the planned session record',
    );
  }
  if (String(record.signingGrantId || '').trim() !== args.signingGrantId) {
    throw new Error(
      '[SigningEngine][near] passkey Ed25519 budget refresh returned a signing grant mismatch',
    );
  }
  return record;
}

function requireRecoveredPasskeyEd25519Capability(args: {
  capability: NearEd25519YaoSigningCapability;
  expectedLaneIdentity: ReturnType<typeof exactPasskeyEd25519RefreshLaneIdentity>;
}): NearEd25519YaoSigningCapability {
  if (args.capability.activeClient.status().kind !== 'active') {
    throw new Error('[SigningEngine][near] recovered passkey Ed25519 Yao client is inactive');
  }
  if (
    exactSigningLaneIdentityKey(args.capability.walletSessionState.signingLane.identity) !==
    exactSigningLaneIdentityKey(args.expectedLaneIdentity)
  ) {
    throw new Error(
      '[SigningEngine][near] recovered passkey Ed25519 Yao capability changed lifecycle identity',
    );
  }
  return args.capability;
}

export async function refreshPasskeyEd25519CapabilityForSigning(args: {
  nearAccountId: AccountId;
  record: ThresholdEd25519SessionRecord;
  policySecretSource: ThresholdEd25519WebAuthnPrfSecretSource;
  operationUsesNeeded: number;
  sessionId: string;
  signingGrantId: string;
  runtimeScopeBootstrap?: {
    projectEnvironmentId: string;
    publishableKey: string;
  };
  provisionThresholdEd25519Session: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  readStoredThresholdEd25519SessionRecordByThresholdSessionId?: (
    thresholdSessionId: string,
  ) => ThresholdEd25519SessionRecord | null;
  resolveActiveEd25519YaoSigningCapability: (
    identity: Ed25519YaoActiveClientIdentityV1,
  ) => NearEd25519YaoSigningCapability | null;
  refreshActiveEd25519YaoWalletSession: (args: {
    identity: Ed25519YaoActiveClientIdentityV1;
    signingGrantId: string;
    nextWalletSessionState: NearEd25519YaoSigningCapability['walletSessionState'];
  }) => Ed25519YaoSameIdentityWalletSessionRefreshResultV1;
  recoverPasskeyEd25519YaoCapabilityForSigning: (args: {
    walletId: ThresholdEd25519SessionRecord['walletId'];
    nearAccountId: AccountId;
    signerSlot: number;
    thresholdSessionId: string;
  }) => Promise<NearEd25519YaoSigningCapability>;
}): Promise<
  { sessionId: string; record: ThresholdEd25519SessionRecord } & NearEd25519YaoSigningCapability
> {
  const operationUsesNeeded = Math.max(1, Math.floor(Number(args.operationUsesNeeded) || 1));
  const sessionId = String(args.sessionId || '').trim();
  const signingGrantId = String(args.signingGrantId || '').trim();
  const recordSessionId = String(args.record.thresholdSessionId || '').trim();
  const recordSigningGrantId = String(args.record.signingGrantId || '').trim();
  const runtimePolicyScope = args.record.runtimePolicyScope;
  const signerSlot = Math.floor(Number(args.record.signerSlot) || 0);
  if (!sessionId || !signingGrantId) {
    throw new Error('Passkey Ed25519 budget refresh requires exact session identity');
  }
  if (sessionId !== recordSessionId || signingGrantId !== recordSigningGrantId) {
    throw new Error(
      '[SigningEngine][near] passkey Ed25519 budget refresh must preserve lifecycle identity',
    );
  }
  if (!runtimePolicyScope) {
    throw new Error(
      '[SigningEngine][near] passkey Ed25519 budget refresh requires runtime policy scope',
    );
  }
  if (signerSlot <= 0) {
    throw new Error('[SigningEngine][near] passkey Ed25519 budget refresh requires signer slot');
  }
  const identity = {
    walletId: args.record.walletId,
    nearAccountId: args.nearAccountId,
    thresholdSessionId: sessionId,
  };
  const previous = args.resolveActiveEd25519YaoSigningCapability(identity);
  const activePrevious = previous?.activeClient.status().kind === 'active' ? previous : null;
  const laneIdentity = exactPasskeyEd25519RefreshLaneIdentity({
    nearAccountId: args.nearAccountId,
    record: args.record,
    signerSlot,
    sessionId,
    signingGrantId,
  });
  const provisioned = await args.provisionThresholdEd25519Session({
    kind: 'exact_ed25519_provisioning',
    laneIdentity,
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
      kind: 'router_ab_ed25519_yao_budget_refresh_v1',
      policySecretSource: args.policySecretSource,
    },
    ...(args.runtimeScopeBootstrap ? { runtimeScopeBootstrap: args.runtimeScopeBootstrap } : {}),
    runtimePolicyScope,
    routerAbNormalSigning: args.record.routerAbNormalSigning,
    participantIds: args.record.participantIds,
    sessionKind: 'jwt',
    remainingUses: operationUsesNeeded,
  });
  if (!provisioned.ok) {
    throw new Error(
      provisioned.message || provisioned.code || 'Passkey Ed25519 budget refresh failed',
    );
  }
  if (provisioned.sessionId !== sessionId || provisioned.signingGrantId !== signingGrantId) {
    throw new Error(
      '[SigningEngine][near] passkey Ed25519 budget refresh returned a different lifecycle identity',
    );
  }
  const record = readRefreshedEd25519Record({
    sessionId,
    signingGrantId,
    reader: args.readStoredThresholdEd25519SessionRecordByThresholdSessionId,
  });
  const nextWalletSessionState = resolveRouterAbEd25519WalletSessionStateFromRecord(record);
  if (!nextWalletSessionState) {
    throw new Error(
      '[SigningEngine][near] passkey Ed25519 budget refresh returned unusable Wallet Session state',
    );
  }
  if (!activePrevious) {
    const recovered = await args.recoverPasskeyEd25519YaoCapabilityForSigning({
      walletId: args.record.walletId,
      nearAccountId: args.nearAccountId,
      signerSlot,
      thresholdSessionId: sessionId,
    });
    return {
      sessionId: provisioned.sessionId,
      record,
      ...requireRecoveredPasskeyEd25519Capability({
        capability: recovered,
        expectedLaneIdentity: laneIdentity,
      }),
    };
  }
  const refreshed = args.refreshActiveEd25519YaoWalletSession({
    identity,
    signingGrantId,
    nextWalletSessionState,
  });
  if (!refreshed.ok) {
    throw new Error(refreshed.message);
  }
  if (refreshed.capability.activeClient !== activePrevious.activeClient) {
    throw new Error('[SigningEngine][near] passkey Ed25519 budget refresh replaced the Yao client');
  }
  return {
    sessionId: provisioned.sessionId,
    record,
    ...refreshed.capability,
  };
}
