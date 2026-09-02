import { parseThresholdSecp256k1Ecdsa2pParticipantIdsV1 } from '@shared/threshold/secp256k1';
import type {
  RouterAbEcdsaDerivationPresignaturePoolPolicy,
  RouterAbEcdsaDerivationPresignaturePoolPolicyInput,
} from '@/core/types/seams';
import {
  getRouterAbEcdsaDerivationClientPresignaturePoolDepth,
  resolveRouterAbEcdsaDerivationPresignaturePoolPolicy,
  scheduleRouterAbEcdsaDerivationClientPresignaturePoolRefill,
  type RouterAbEcdsaDerivationClientSigningMaterialSource,
  type RouterAbEcdsaDerivationClientPresignatureRefillScheduleResult,
} from '../../routerAb/ecdsaDerivation/presignaturePool';
import type { SignerWorkerManagerContext } from '../../workerManager/SignerWorkerManager';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  LOGIN_PREFILL_MIN_REMAINING_USES,
  LOGIN_PREFILL_TARGET_DEPTH,
  LOGIN_PREFILL_TRIGGER_DEPTH,
} from '@/core/config/defaultConfigs';
import type { ExactEcdsaSealedRuntime } from '../material/ecdsaSealedRuntime';
import type { ActiveEcdsaCapabilityManifest } from '../material/ecdsaCapabilityManifest';
import type {
  ActiveWalletSessionV1,
  WalletSessionAuthorizationExactOperationCredentialReadResult,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { parseEcdsaClientVerifyingShareB64u, parseEcdsaThresholdKeyId } from '../keyMaterialBrands';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  mpcMaterialActivationRefsEqual,
  type WalletAuthorityId,
  type WalletAuthMethodId,
} from '@shared/utils/domainIds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';

export type RouterAbEcdsaDerivationLoginPresignaturePrefillSkippedReason =
  | 'pool_disabled'
  | 'pool_already_warm'
  | 'missing_threshold_session_id'
  | 'exact_wallet_session_unavailable'
  | 'invalid_session_record'
  | 'warm_session_not_active'
  | 'warm_session_expiry_unavailable'
  | 'threshold_session_mismatch'
  | 'low_remaining_uses'
  | 'missing_router_ab_ecdsa_derivation_state'
  | 'refill_not_scheduled';

export type RouterAbEcdsaDerivationLoginPresignaturePrefillResult =
  | {
      status: 'scheduled';
      reason: 'scheduled';
      thresholdSessionId: string;
      remainingUsesBeforeDispense: number;
      remainingUsesAfterDispense: number;
      schedule: RouterAbEcdsaDerivationClientPresignatureRefillScheduleResult;
    }
  | {
      status: 'skipped';
      reason: 'invalid_session_record' | 'missing_threshold_session_id';
      thresholdSessionId: null;
      details: string | null;
    }
  | {
      status: 'skipped';
      reason:
        | 'exact_wallet_session_unavailable'
        | 'warm_session_not_active'
        | 'warm_session_expiry_unavailable'
        | 'missing_router_ab_ecdsa_derivation_state';
      thresholdSessionId: string;
    }
  | {
      status: 'skipped';
      reason: 'threshold_session_mismatch';
      thresholdSessionId: string;
      details: string;
    }
  | {
      status: 'skipped';
      reason: 'low_remaining_uses';
      thresholdSessionId: string;
      remainingUses: number;
    }
  | {
      status: 'skipped';
      reason: 'refill_not_scheduled';
      thresholdSessionId: string;
      remainingUses: number;
      schedule: RouterAbEcdsaDerivationClientPresignatureRefillScheduleResult;
    }
  | {
      status: 'skipped';
      reason: 'pool_disabled' | 'pool_already_warm';
      thresholdSessionId: string;
    }
  | {
      status: 'failed';
      reason: 'unexpected_error';
      thresholdSessionId: string | null;
      error: string;
    };

export type RouterAbEcdsaDerivationLoginPresignaturePrefillDeps = {
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  resolveActiveWalletAuthority: (args: {
    walletId: WalletId;
    authority: WalletAuthAuthorityRef;
  }) => Promise<{
    walletId: WalletId;
    authorityId: WalletAuthorityId;
    walletAuthMethodId: WalletAuthMethodId;
    authorityDigestB64u: DigestB64u;
    authorityRevocationEpoch: number;
  } | null>;
  readExactWalletSessionWithOperationCredential: (args: {
    walletId: WalletId;
    authorityId: WalletAuthorityId;
    authMethodId: WalletAuthMethodId;
  }) => Promise<WalletSessionAuthorizationExactOperationCredentialReadResult>;
  resolveClientSigningMaterialSource: (args: {
    manifest: ActiveEcdsaCapabilityManifest;
    runtime: ExactEcdsaSealedRuntime;
  }) => RouterAbEcdsaDerivationClientSigningMaterialSource;
  routerAbEcdsaDerivationPresignaturePoolPolicy?:
    | RouterAbEcdsaDerivationPresignaturePoolPolicyInput
    | RouterAbEcdsaDerivationPresignaturePoolPolicy;
};

function exactEcdsaSignCapabilityMatchesMaterial(args: {
  session: ActiveWalletSessionV1;
  runtime: ExactEcdsaSealedRuntime;
  manifest: ActiveEcdsaCapabilityManifest;
}): boolean {
  if (
    !mpcMaterialActivationRefsEqual(
      args.runtime.materialActivation,
      args.manifest.activation.materialActivation,
    )
  ) {
    return false;
  }
  const matches = args.session.capabilitySubjects.filter(
    (subject) =>
      subject.kind === 'sign' &&
      subject.keyFamily === 'ecdsa_secp256k1' &&
      mpcMaterialActivationRefsEqual(subject.materialActivation, args.runtime.materialActivation),
  );
  return matches.length === 1;
}

export async function scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill(
  deps: RouterAbEcdsaDerivationLoginPresignaturePrefillDeps,
  args: {
    walletId: WalletId;
    manifest: ActiveEcdsaCapabilityManifest;
    runtime: ExactEcdsaSealedRuntime;
    chainTarget: ThresholdEcdsaChainTarget;
    minRemainingUsesBeforePrefill?: number;
  },
): Promise<RouterAbEcdsaDerivationLoginPresignaturePrefillResult> {
  let thresholdSessionId: string | undefined;
  try {
    const walletId = args.walletId;
    // The runtime was already correlated against the active manifest, so its
    // transport and two-party facts are exact. The remaining guard is that the
    // participant ids still parse as a Router A/B 2-of-2 set.
    const runtime = args.runtime;
    const relayerUrl = runtime.relayerUrl;
    const clientVerifyingPublicKey33B64u = runtime.clientVerifyingPublicKey33B64u;
    const participantIds = parseThresholdSecp256k1Ecdsa2pParticipantIdsV1(runtime.participantIds);
    if (!participantIds.ok) {
      return {
        status: 'skipped',
        reason: 'invalid_session_record',
        thresholdSessionId: null,
        details: null,
      };
    }

    thresholdSessionId = runtime.sealedRecord.thresholdSessionId;

    const manifestAuthority = args.manifest.signer.authority;
    let activeAuthority: Awaited<
      ReturnType<
        RouterAbEcdsaDerivationLoginPresignaturePrefillDeps['resolveActiveWalletAuthority']
      >
    >;
    try {
      activeAuthority = await deps.resolveActiveWalletAuthority({
        walletId,
        authority: manifestAuthority,
      });
    } catch {
      return {
        status: 'skipped',
        reason: 'exact_wallet_session_unavailable',
        thresholdSessionId,
      };
    }
    if (
      !activeAuthority ||
      activeAuthority.walletId !== walletId ||
      manifestAuthority.walletId !== walletId ||
      activeAuthority.walletAuthMethodId !== manifestAuthority.walletAuthMethodId
    ) {
      return {
        status: 'skipped',
        reason: 'exact_wallet_session_unavailable',
        thresholdSessionId,
      };
    }

    let exactRead: WalletSessionAuthorizationExactOperationCredentialReadResult;
    try {
      exactRead = await deps.readExactWalletSessionWithOperationCredential({
        walletId,
        authorityId: activeAuthority.authorityId,
        authMethodId: activeAuthority.walletAuthMethodId,
      });
    } catch {
      return {
        status: 'skipped',
        reason: 'exact_wallet_session_unavailable',
        thresholdSessionId,
      };
    }
    if (exactRead.kind !== 'found') {
      return {
        status: 'skipped',
        reason: 'exact_wallet_session_unavailable',
        thresholdSessionId,
      };
    }
    const authorization = exactRead.record;
    const operationCredential = exactRead.operationCredential;
    const nowMs = Date.now();
    if (
      authorization.walletId !== walletId ||
      authorization.authorityId !== activeAuthority.authorityId ||
      authorization.authMethodId !== activeAuthority.walletAuthMethodId ||
      authorization.authorityDigestB64u !== activeAuthority.authorityDigestB64u ||
      authorization.authorityRevocationEpoch !== activeAuthority.authorityRevocationEpoch ||
      authorization.expiresAtMs <= nowMs ||
      operationCredential.walletSessionId.length === 0 ||
      operationCredential.token.trim().length === 0 ||
      !exactEcdsaSignCapabilityMatchesMaterial({
        session: authorization,
        runtime,
        manifest: args.manifest,
      })
    ) {
      return {
        status: 'skipped',
        reason: 'exact_wallet_session_unavailable',
        thresholdSessionId,
      };
    }

    const policy = resolveRouterAbEcdsaDerivationPresignaturePoolPolicy(
      deps.routerAbEcdsaDerivationPresignaturePoolPolicy,
    );
    if (!policy.enabled) {
      return {
        status: 'skipped',
        reason: 'pool_disabled',
        thresholdSessionId,
      };
    }

    if (runtime.expiresAtMs <= Date.now()) {
      return {
        status: 'skipped',
        reason: 'missing_router_ab_ecdsa_derivation_state',
        thresholdSessionId,
      };
    }

    const existingDepth = getRouterAbEcdsaDerivationClientPresignaturePoolDepth({
      relayerUrl,
      scope: runtime.normalSigning.scope,
      materialActivation: routerAbMpcMaterialActivationRefToWire(runtime.materialActivation),
    });
    if (existingDepth >= LOGIN_PREFILL_TARGET_DEPTH) {
      return {
        status: 'skipped',
        reason: 'pool_already_warm',
        thresholdSessionId,
      };
    }

    if (runtime.expiresAtMs <= nowMs) {
      return {
        status: 'skipped',
        reason: 'warm_session_not_active',
        thresholdSessionId,
      };
    }

    const routerAbPoolFillExpiresAtMs = Math.min(
      runtime.expiresAtMs,
      authorization.expiresAtMs,
      nowMs + 60_000,
    );
    if (routerAbPoolFillExpiresAtMs <= nowMs) {
      return {
        status: 'skipped',
        reason: 'warm_session_expiry_unavailable',
        thresholdSessionId,
      };
    }

    const minimumUses = Math.max(
      LOGIN_PREFILL_MIN_REMAINING_USES,
      Math.floor(Number(args.minRemainingUsesBeforePrefill ?? LOGIN_PREFILL_MIN_REMAINING_USES)),
    );
    const remainingUsesBefore = runtime.remainingUses;
    if (remainingUsesBefore < minimumUses) {
      return {
        status: 'skipped',
        reason: 'low_remaining_uses',
        thresholdSessionId,
        remainingUses: remainingUsesBefore,
      };
    }

    const routerAbEcdsaDerivationPoolFill = {
      kind: 'router_ab_ecdsa_derivation_signing_worker_pool' as const,
      scope: runtime.normalSigning.scope,
      expiresAtMs: routerAbPoolFillExpiresAtMs,
    };

    const remainingUsesAfterDispense = remainingUsesBefore;
    const clientSigningMaterial = deps.resolveClientSigningMaterialSource({
      manifest: args.manifest,
      runtime,
    });

    const schedule = scheduleRouterAbEcdsaDerivationClientPresignaturePoolRefill({
      relayerUrl,
      ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(runtime.ecdsaThresholdKeyId),
      clientVerifyingShareB64u: parseEcdsaClientVerifyingShareB64u(clientVerifyingPublicKey33B64u),
      clientSigningMaterial,
      thresholdEcdsaPublicKeyB64u: runtime.thresholdEcdsaPublicKeyB64u,
      relayerVerifyingShareB64u:
        runtime.normalSigning.scope.public_identity.server_public_key33_b64u,
      credential: {
        kind: 'wallet_session_opaque',
        walletSessionToken: operationCredential.token,
      },
      authorization: {
        kind: 'reusable_wallet_session',
        wallet_session_id: operationCredential.walletSessionId,
      },
      materialActivation: routerAbMpcMaterialActivationRefToWire(runtime.materialActivation),
      routerAbEcdsaDerivationPoolFill,
      workerCtx: deps.getSignerWorkerContext(),
      poolPolicy: policy,
      targetDepth: LOGIN_PREFILL_TARGET_DEPTH,
      triggerIfDepthAtOrBelow: LOGIN_PREFILL_TRIGGER_DEPTH,
    });

    if (!schedule.scheduled) {
      return {
        status: 'skipped',
        reason: 'refill_not_scheduled',
        thresholdSessionId,
        remainingUses: remainingUsesAfterDispense,
        schedule,
      };
    }

    return {
      status: 'scheduled',
      reason: 'scheduled',
      thresholdSessionId,
      remainingUsesBeforeDispense: remainingUsesBefore,
      remainingUsesAfterDispense,
      schedule,
    };
  } catch (error: unknown) {
    return {
      status: 'failed',
      reason: 'unexpected_error',
      thresholdSessionId: thresholdSessionId || null,
      error: String((error as { message?: unknown })?.message || error || 'unexpected error'),
    };
  }
}
