import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { connectEd25519Session } from '../../threshold/ed25519/connectSession';
import { cacheCredentialBoundarySetupExportPrfFirst, generateSessionId } from './prfCache';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type {
  MintedEd25519WalletSessionAuthority,
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
} from '../warmCapabilities/types';
import type { PasskeyEd25519SessionPolicyAuthority } from '../../threshold/sessionPolicy';
import { nearProtocolProjectionFromExactLane } from '../identity/exactSigningLaneIdentity';
import { SigningSessionIds } from '../operationState/types';
import { buildPasskeyEd25519RestoreMetadata } from './ed25519YaoSealedSession';
import type { PasskeyEd25519SealRestoreMetadata } from '@/core/types/secure-confirm-worker';
import type { ThresholdEd25519SessionId } from '@shared/utils/domainIds';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { WalletSessionOperationCredentialV1 } from '@shared/device-linking';

type ConnectEd25519SessionInput = Parameters<typeof connectEd25519Session>[0];

type ResolvedEd25519ProvisionProtocol =
  | {
      kind: 'fresh';
      walletId: string;
      nearAccountId: AccountId | string;
      nearEd25519SigningKeyId: string;
      signerSlot: number;
      thresholdSessionId: ThresholdEd25519SessionId;
    }
  | {
      kind: 'exact';
      walletId: string;
      nearAccountId: AccountId | string;
      nearEd25519SigningKeyId: string;
      signerSlot: number;
      thresholdSessionId: ThresholdEd25519SessionId;
      walletSessionId: WalletSessionId;
      quotaId: MpcWalletSigningQuotaId;
    };

export type ProvisionThresholdEd25519SessionDeps = {
  credentialStore: ConnectEd25519SessionInput['credentialStore'];
  touchIdPrompt: ConnectEd25519SessionInput['touchIdPrompt'];
  touchConfirm: Parameters<typeof cacheCredentialBoundarySetupExportPrfFirst>[0];
  defaultRelayerUrl: string;
  getSignerWorkerContext: () => ConnectEd25519SessionInput['workerCtx'];
};

function sealTransportForProvisionedEd25519Session(args: {
  walletId: string;
  relayerUrl: string;
  walletSessionToken: string;
  ed25519Restore: PasskeyEd25519SealRestoreMetadata;
}): WarmSessionSealTransportInput {
  return {
    curve: 'ed25519',
    authMethod: 'passkey',
    walletId: args.walletId,
    relayerUrl: args.relayerUrl,
    walletSessionToken: args.walletSessionToken,
    ed25519Restore: args.ed25519Restore,
  };
}

function passkeyCredentialIdB64uFromAuthority(
  authority: PasskeyEd25519SessionPolicyAuthority,
): string {
  const credentialIdB64u = String(authority.authority.factor.credentialIdB64u || '').trim();
  if (!credentialIdB64u) {
    throw new Error('[threshold-ed25519] passkey authority credential id is required');
  }
  return credentialIdB64u;
}

function resolveEd25519ProvisionProtocol(
  args: ProvisionWarmEd25519CapabilityArgs,
): ResolvedEd25519ProvisionProtocol {
  switch (args.kind) {
    case 'fresh_ed25519_provisioning':
      return {
        kind: 'fresh',
        walletId: args.walletId,
        nearAccountId: args.nearAccountId,
        nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
        signerSlot: args.signerSlot,
        thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
          generateSessionId('threshold-ed25519'),
        ),
      };
    case 'exact_ed25519_provisioning': {
      const projection = nearProtocolProjectionFromExactLane(
        args.laneIdentity,
        'exact Ed25519 capability provisioning',
      );
      return {
        kind: 'exact',
        walletId: String(projection.walletId),
        nearAccountId: projection.nearAccountId,
        nearEd25519SigningKeyId: String(projection.nearEd25519SigningKeyId),
        signerSlot: projection.signerSlot,
        thresholdSessionId: args.laneIdentity.thresholdSessionId,
        walletSessionId: args.laneIdentity.walletSessionId,
        quotaId: args.laneIdentity.quotaId,
      };
    }
  }
  args satisfies never;
  throw new Error('[threshold-ed25519] unsupported Ed25519 provisioning kind');
}

function exactEd25519ProvisionReturnedDifferentIdentity(args: {
  requested: ResolvedEd25519ProvisionProtocol;
  returnedThresholdSessionId: ThresholdEd25519SessionId;
  returnedWalletSessionId: WalletSessionId;
  returnedQuotaId: MpcWalletSigningQuotaId;
}): boolean {
  switch (args.requested.kind) {
    case 'fresh':
      return false;
    case 'exact':
      return (
        args.returnedThresholdSessionId !== args.requested.thresholdSessionId ||
        args.returnedWalletSessionId !== args.requested.walletSessionId ||
        args.returnedQuotaId !== args.requested.quotaId
      );
  }
  args.requested satisfies never;
  throw new Error('[threshold-ed25519] unsupported resolved provisioning identity');
}

type ConnectedEd25519Session = Extract<
  Awaited<ReturnType<typeof connectEd25519Session>>,
  { readonly ok: true }
>;

type ResolvedEd25519ProvisionCredential =
  | {
      readonly ok: true;
      readonly operationCredential: WalletSessionOperationCredentialV1;
    }
  | {
      readonly ok: false;
      readonly code: 'invalid_result' | 'unlock_exact_method';
      readonly message: string;
    };

function resolveEd25519ProvisionOperationCredential(args: {
  connected: ConnectedEd25519Session;
  protocol: ResolvedEd25519ProvisionProtocol;
  existingOperationCredential: WalletSessionOperationCredentialV1 | undefined;
}): ResolvedEd25519ProvisionCredential {
  switch (args.connected.sessionKind) {
    case 'issued_exact_wallet_session':
      if (args.connected.operationCredential.walletSessionId !== args.connected.walletSessionId) {
        return {
          ok: false,
          code: 'invalid_result',
          message: 'Threshold Ed25519 session mint credential does not identify its session',
        };
      }
      return {
        ok: true,
        operationCredential: args.connected.operationCredential,
      };
    case 'already_committed_exact_wallet_session': {
      if (args.protocol.kind !== 'exact' || !args.existingOperationCredential) {
        return {
          ok: false,
          code: 'unlock_exact_method',
          message:
            'Threshold Ed25519 session reuse returned no credential; exact-method unlock is required',
        };
      }
      const operationCredential = args.existingOperationCredential;
      if (operationCredential.walletSessionId !== args.connected.walletSessionId) {
        return {
          ok: false,
          code: 'unlock_exact_method',
          message: 'Threshold Ed25519 reused session credential identifies another session',
        };
      }
      return { ok: true, operationCredential };
    }
    default:
      return assertNeverEd25519ProvisionSessionKind(args.connected);
  }
}

function assertNeverEd25519ProvisionSessionKind(value: never): never {
  throw new Error(`[threshold-ed25519] unsupported connected session kind: ${String(value)}`);
}

export async function provisionThresholdEd25519Session(
  deps: ProvisionThresholdEd25519SessionDeps,
  args: ProvisionWarmEd25519CapabilityArgs,
): Promise<ProvisionWarmEd25519CapabilityResult> {
  const protocol = resolveEd25519ProvisionProtocol(args);
  if (
    args.kind === 'exact_ed25519_provisioning' &&
    args.operationCredential.walletSessionId !== args.laneIdentity.walletSessionId
  ) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Threshold Ed25519 exact credential identifies another Wallet Session',
    };
  }
  const nearAccountId = toAccountId(protocol.nearAccountId);
  const relayerUrl = String(args.relayerUrl || deps.defaultRelayerUrl || '').trim();
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
  if (!relayerUrl) {
    throw new Error('Missing relayer url (configs.network.relayer.url)');
  }
  if (!participantIds) {
    throw new Error('Missing participantIds for threshold Ed25519 session provision');
  }
  const workerCtx = deps.getSignerWorkerContext();
  const connected = await connectEd25519Session({
    credentialStore: deps.credentialStore,
    touchIdPrompt: deps.touchIdPrompt,
    relayerUrl,
    relayerKeyId: args.relayerKeyId,
    walletId: protocol.walletId,
    nearEd25519SigningKeyId: protocol.nearEd25519SigningKeyId,
    authority: args.authority,
    ...(args.auth ? { auth: args.auth } : {}),
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    routerAbNormalSigning: args.routerAbNormalSigning,
    ...(args.runtimeScopeBootstrap ? { runtimeScopeBootstrap: args.runtimeScopeBootstrap } : {}),
    nearAccountId,
    participantIds,
    thresholdSessionId: protocol.thresholdSessionId,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
    workerCtx,
    ...(args.kind === 'exact_ed25519_provisioning'
      ? { existingOperationCredential: args.operationCredential }
      : {}),
  });
  if (!connected.ok) {
    return {
      ok: false,
      code: String(connected.code || 'worker_error').trim() || 'worker_error',
      message: String(connected.message || '').trim() || 'Threshold Ed25519 session mint failed',
    };
  }

  const resolvedThresholdSessionId = connected.thresholdSessionId || protocol.thresholdSessionId;
  const expiresAtMs = Number(connected.expiresAtMs);
  const remainingUses = Number(connected.remainingUses);
  const prfFirstB64u = String(connected.passkeyPrfFirstB64u || '').trim();
  const runtimePolicyScope = connected.runtimePolicyScope;
  if (
    !resolvedThresholdSessionId ||
    !connected.walletSessionId ||
    !connected.authorizationId ||
    !connected.quotaId ||
    !Number.isFinite(expiresAtMs) ||
    !Number.isFinite(remainingUses)
  ) {
    return {
      ok: false,
      code: 'invalid_result',
      message: 'Threshold Ed25519 session mint returned incomplete public session metadata',
    };
  }
  if (
    exactEd25519ProvisionReturnedDifferentIdentity({
      requested: protocol,
      returnedThresholdSessionId: resolvedThresholdSessionId,
      returnedWalletSessionId: connected.walletSessionId,
      returnedQuotaId: connected.quotaId,
    })
  ) {
    return {
      ok: false,
      code: 'invalid_result',
      message: 'Threshold Ed25519 exact provisioning returned a different lifecycle identity',
    };
  }

  const credentialResolution = resolveEd25519ProvisionOperationCredential({
    connected,
    protocol,
    existingOperationCredential:
      args.kind === 'exact_ed25519_provisioning' ? args.operationCredential : undefined,
  });
  if (!credentialResolution.ok) return credentialResolution;
  const { operationCredential } = credentialResolution;
  const walletSessionToken = operationCredential.token;

  const mintedAuthority: MintedEd25519WalletSessionAuthority = {
    kind: 'minted_ed25519_wallet_session_authority',
    thresholdSessionId: resolvedThresholdSessionId,
    walletSessionId: connected.walletSessionId,
    authorizationId: connected.authorizationId,
    quotaId: connected.quotaId,
    expiresAtMs,
    remainingUses,
    runtimePolicyScope,
    operationCredential,
  };
  const rpId = deps.touchIdPrompt.getRpId();
  if (prfFirstB64u && args.source === 'email_otp') {
    return {
      ok: false,
      code: 'invalid_result',
      message: 'Passkey PRF material cannot seal an Email OTP Ed25519 session',
    };
  }
  await args.onWalletSessionAuthorityReady?.(mintedAuthority);

  if (prfFirstB64u && args.source !== 'email_otp') {
    const credentialIdB64u = passkeyCredentialIdB64uFromAuthority(args.authority);
    const ed25519Restore = buildPasskeyEd25519RestoreMetadata({
      rpId,
      nearAccountId: String(nearAccountId),
      nearEd25519SigningKeyId: protocol.nearEd25519SigningKeyId,
      relayerKeyId: args.relayerKeyId,
      participantIds,
      runtimePolicyScope,
      signerSlot: protocol.signerSlot,
      routerAbNormalSigning: args.routerAbNormalSigning,
      credentialIdB64u,
      materialActivation: args.materialActivation,
    });
    const transport = sealTransportForProvisionedEd25519Session({
      walletId: protocol.walletId,
      relayerUrl,
      walletSessionToken,
      ed25519Restore,
    });
    try {
      await cacheCredentialBoundarySetupExportPrfFirst(deps.touchConfirm, {
        thresholdSessionId: String(resolvedThresholdSessionId),
        prfFirstB64u,
        expiresAtMs,
        remainingUses,
        transport,
      });
    } catch (error: unknown) {
      const details = String(
        error && typeof error === 'object' && 'message' in error
          ? (error as { message?: unknown }).message
          : error || '',
      ).trim();
      return {
        ok: false,
        code: 'warm_session_cache_failed',
        message: details || 'Threshold Ed25519 session material could not be cached',
      };
    }
  }

  return {
    ok: true,
    sessionKind: connected.sessionKind,
    thresholdSessionId: resolvedThresholdSessionId,
    walletSessionId: connected.walletSessionId,
    authorizationId: connected.authorizationId,
    quotaId: connected.quotaId,
    expiresAtMs,
    remainingUses,
    runtimePolicyScope,
    operationCredential,
  };
}
