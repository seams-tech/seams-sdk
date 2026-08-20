import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { NearEd25519YaoOperationMaterial } from '@/core/signingEngine/interfaces/near';
import type { ExactEd25519ExportMaterialIdentity } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { SigningLaneAuthBinding } from '@/core/signingEngine/session/identity/signingLaneAuthBinding';
import type { EmailOtpEd25519YaoActiveCapabilityDescriptorV1 } from '@/core/signingEngine/workerManager/workerTypes';
import type {
  EmailOtpEd25519YaoRecoveryBootstrapV1,
  EmailOtpEd25519YaoWorkerActivationResult,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { LoadedWalletCustodyEd25519MaterialV1 } from '@/core/signingEngine/walletCustody/ed25519SeedMaterial';
import { parseEd25519YaoRecoveryCapabilityV1 } from '@/core/signingEngine/session/passkey/ed25519YaoRecoveryCapability';
import type { ReusableWalletSessionState } from '@/core/types/seams';
import type { AccountId } from '@/core/types/accountIds';
import {
  type ActiveWalletSessionAuthorizationProjection,
  type WalletSessionAuthorizationReadResult,
  walletSessionAuthorizationIdForCurve,
  walletSessionTokenForCurve,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  mpcMaterialActivationRefsEqual,
  parseThresholdEd25519SessionId,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1,
  parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { parseEmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { base64UrlEncode } from '@shared/utils/base64';

type EmailOtpEd25519LaneAuth = Extract<SigningLaneAuthBinding, { kind: 'email_otp' }>;

export type ResolvedWalletCustodyEd25519ExportV1 = {
  readonly kind: 'wallet_custody_ed25519_export_context_v1';
  readonly lane: ExactEd25519ExportMaterialIdentity<EmailOtpEd25519LaneAuth>;
  readonly authorization: ActiveWalletSessionAuthorizationProjection;
  readonly material:
    | {
        readonly kind: 'active_capability';
        readonly materialActivation: MpcMaterialActivationRef;
        readonly capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
      }
    | {
        readonly kind: 'sealed_custody';
        readonly materialActivation: MpcMaterialActivationRef;
        readonly capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
        readonly walletCustodyEd25519Material: LoadedWalletCustodyEd25519MaterialV1;
        readonly bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
        readonly activateRecoveredCapability: (
          result: EmailOtpEd25519YaoWorkerActivationResult,
        ) => Promise<void>;
      };
};

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireExactKeys(
  record: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(record).sort();
  const keys = [...expected].sort();
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    throw new Error(`${label} fields are invalid`);
  }
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.trim() !== value || value.length === 0) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function requirePositiveInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function requireParticipantIds(value: unknown): readonly [number, number] {
  if (
    !Array.isArray(value) ||
    value.length !== 2 ||
    !Number.isSafeInteger(value[0]) ||
    !Number.isSafeInteger(value[1]) ||
    Number(value[0]) < 1 ||
    Number(value[1]) < 1 ||
    value[0] === value[1]
  ) {
    throw new Error('Ed25519 export bootstrap participantIds are invalid');
  }
  return [Number(value[0]), Number(value[1])];
}

async function readColdExportBootstrap(input: {
  readonly subject: ExactEd25519ExportMaterialIdentity<EmailOtpEd25519LaneAuth>;
  readonly authorization: ActiveWalletSessionAuthorizationProjection;
  readonly material: LoadedWalletCustodyEd25519MaterialV1;
  readonly reusableSession: ReusableWalletSessionState;
  readonly expectedMaterialActivation: MpcMaterialActivationRef;
  readonly relayerUrl: string;
  readonly fetch: typeof fetch;
}): Promise<{
  readonly bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  readonly emailHashHex: string;
}> {
  if (
    input.reusableSession.kind !== 'active' ||
    input.reusableSession.walletSessionId !== input.authorization.walletSessionId ||
    input.reusableSession.authMethod !== 'email_otp'
  ) {
    throw new Error('[SigningEngine][ed25519-export] reusable Wallet Session is unavailable');
  }
  const walletSessionToken = walletSessionTokenForCurve(input.authorization, 'ed25519');
  const authorizationId = walletSessionAuthorizationIdForCurve(input.authorization, 'ed25519');
  const signer = input.subject.signer;
  const binding = input.material.binding;
  if (
    !walletSessionToken ||
    input.authorization.walletId !== signer.account.wallet.walletId ||
    input.authorization.authMethod !== 'email_otp' ||
    !authorizationId ||
    !input.authorization.walletSessionId ||
    !input.authorization.quotaId ||
    binding.walletId !== String(signer.account.wallet.walletId) ||
    binding.nearAccountId !== String(signer.account.nearAccountId) ||
    binding.nearEd25519SigningKeyId !== String(signer.nearEd25519SigningKeyId) ||
    binding.signerSlot !== signer.signerSlot
  ) {
    throw new Error('[SigningEngine][ed25519-export] sealed custody identity mismatch');
  }
  const request = parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1({
    kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_request_v1',
    walletId: String(signer.account.wallet.walletId),
    nearAccountId: String(signer.account.nearAccountId),
    nearEd25519SigningKeyId: String(signer.nearEd25519SigningKeyId),
    signerSlot: signer.signerSlot,
    thresholdSessionId: input.subject.thresholdSessionId,
    signingWorkerId: binding.signingWorkerId,
    participantIds: binding.participantIds,
  });
  if (!request.ok) throw new Error(request.message);
  const response = await input.fetch(
    `${new URL(input.relayerUrl).origin}${ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1}`,
    {
      method: 'POST',
      headers: { Authorization: `Bearer ${walletSessionToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(request.value),
    },
  );
  const raw = await response.json().catch(() => null);
  if (!response.ok) {
    const failure = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : null;
    throw new Error(
      `[SigningEngine][ed25519-export] capability bootstrap failed (HTTP ${response.status}): ${String(failure?.message || 'invalid response')}`,
    );
  }
  const record = requireRecord(raw, 'Ed25519 export bootstrap');
  requireExactKeys(
    record,
    [
      'kind',
      'walletId',
      'nearAccountId',
      'nearEd25519SigningKeyId',
      'signerSlot',
      'thresholdSessionId',
      'walletSessionId',
      'quotaId',
      'signingWorkerId',
      'thresholdExpiresAtMs',
      'participantIds',
      'authority',
      'authorityRef',
      'authorityScope',
      'runtimePolicyScope',
      'routerAbNormalSigning',
      'capability',
    ],
    'Ed25519 export bootstrap',
  );
  if (record.kind !== 'router_ab_ed25519_yao_warm_recovery_bootstrap_v1') {
    throw new Error('Ed25519 export bootstrap kind is invalid');
  }
  const walletId = requireString(record.walletId, 'bootstrap.walletId');
  const nearAccountId = requireString(record.nearAccountId, 'bootstrap.nearAccountId');
  const nearEd25519SigningKeyId = requireString(
    record.nearEd25519SigningKeyId,
    'bootstrap.nearEd25519SigningKeyId',
  );
  const thresholdSessionId = parseThresholdEd25519SessionId(record.thresholdSessionId);
  const walletSessionId = parseWalletSessionId(record.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(record.quotaId);
  const authority = parseEmailOtpWalletAuthAuthority(record.authority);
  const runtimePolicyScope = normalizeRuntimePolicyScope(record.runtimePolicyScope);
  const signingRoot = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
    record.routerAbNormalSigning,
  );
  const parsedCapability = parseEd25519YaoRecoveryCapabilityV1(record.capability);
  const capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1 = {
    kind: 'router_ab_ed25519_yao_active_capability_v1',
    ...parsedCapability,
  };
  const participantIds = requireParticipantIds(record.participantIds);
  const registeredPublicKeyB64u = base64UrlEncode(Uint8Array.from(capability.registeredPublicKey));
  if (
    !thresholdSessionId.ok ||
    !walletSessionId.ok ||
    !quotaId.ok ||
    !authority ||
    !signingRoot ||
    !routerAbNormalSigning ||
    walletId !== String(signer.account.wallet.walletId) ||
    nearAccountId !== String(signer.account.nearAccountId) ||
    nearEd25519SigningKeyId !== String(signer.nearEd25519SigningKeyId) ||
    thresholdSessionId.value !== input.subject.thresholdSessionId ||
    walletSessionId.value !== input.authorization.walletSessionId ||
    quotaId.value !== input.authorization.quotaId ||
    requirePositiveInteger(record.signerSlot, 'bootstrap.signerSlot') !== signer.signerSlot ||
    requireString(record.signingWorkerId, 'bootstrap.signingWorkerId') !==
      binding.signingWorkerId ||
    participantIds[0] !== binding.participantIds[0] ||
    participantIds[1] !== binding.participantIds[1] ||
    authority.factor.providerUserId !== input.subject.auth.providerSubjectId ||
    registeredPublicKeyB64u !== binding.registeredPublicKeyB64u ||
    !mpcMaterialActivationRefsEqual(capability.materialActivation, input.expectedMaterialActivation)
  ) {
    throw new Error('[SigningEngine][ed25519-export] capability bootstrap identity mismatch');
  }
  return {
    emailHashHex: authority.verifier.emailHashHex,
    bootstrap: {
      kind: 'router_ab_ed25519_yao_email_otp_recovery_v1',
      session: {
        sessionKind: 'opaque',
        walletSessionToken,
        walletId: signer.account.wallet.walletId,
        nearAccountId,
        nearEd25519SigningKeyId,
        authorityScope: {
          kind: 'email_otp',
          provider: authority.factor.provider,
          providerUserId: authority.factor.providerUserId,
        },
        thresholdSessionId: thresholdSessionId.value,
        authorizationId,
        walletSessionId: walletSessionId.value,
        quotaId: quotaId.value,
        expiresAtMs: Math.min(
          requirePositiveInteger(record.thresholdExpiresAtMs, 'bootstrap.thresholdExpiresAtMs'),
          input.reusableSession.expiresAtMs,
        ),
        participantIds,
        remainingUses: input.reusableSession.remainingUses,
        signingRootId: signingRoot.signingRootId,
        signingRootVersion: runtimePolicyScope.signingRootVersion,
        runtimePolicyScope,
        routerAbNormalSigning,
      },
      capability,
    },
  };
}

function resolveActiveEmailOtpAuthorization(args: {
  walletId: WalletId;
  result: WalletSessionAuthorizationReadResult<ActiveWalletSessionAuthorizationProjection>;
}): ActiveWalletSessionAuthorizationProjection {
  if (args.result.kind !== 'found') {
    throw new Error(
      '[SigningEngine][ed25519-export] active Wallet Session authorization is unavailable',
    );
  }
  const authorization = args.result.projection;
  if (
    authorization.status !== 'active' ||
    authorization.walletId !== args.walletId ||
    authorization.authority.walletId !== args.walletId ||
    authorization.authMethod !== 'email_otp' ||
    authorization.expiresAtMs <= Date.now()
  ) {
    throw new Error(
      '[SigningEngine][ed25519-export] Email OTP Wallet Session authorization is invalid',
    );
  }
  return authorization;
}

function capabilityFromActiveMaterial(args: {
  subject: ExactEd25519ExportMaterialIdentity<EmailOtpEd25519LaneAuth>;
  expectedMaterialActivation: MpcMaterialActivationRef;
  material: NearEd25519YaoOperationMaterial;
}): EmailOtpEd25519YaoActiveCapabilityDescriptorV1 {
  if (args.material.activeClient.status().kind !== 'active') {
    throw new Error('[SigningEngine][ed25519-export] wallet custody client is inactive');
  }
  const metadata = args.material.activeClient.metadata();
  const signer = args.subject.signer;
  if (
    !mpcMaterialActivationRefsEqual(metadata.materialActivation, args.expectedMaterialActivation) ||
    args.material.facts.signer.account.wallet.walletId !== signer.account.wallet.walletId ||
    String(args.material.facts.signer.account.nearAccountId) !==
      String(signer.account.nearAccountId) ||
    args.material.facts.signer.nearEd25519SigningKeyId !== signer.nearEd25519SigningKeyId ||
    args.material.facts.signer.signerSlot !== signer.signerSlot ||
    metadata.applicationBinding.wallet_id !== signer.account.wallet.walletId ||
    metadata.applicationBinding.near_ed25519_signing_key_id !== signer.nearEd25519SigningKeyId ||
    metadata.applicationBinding.key_creation_signer_slot !== signer.signerSlot
  ) {
    throw new Error('[SigningEngine][ed25519-export] wallet custody client changed the exact lane');
  }
  const thresholdSessionId = parseThresholdEd25519SessionId(metadata.scope.threshold_session_id);
  if (!thresholdSessionId.ok) {
    throw new Error(
      `[SigningEngine][ed25519-export] threshold session id is invalid: ${thresholdSessionId.error.message}`,
    );
  }
  return {
    kind: 'router_ab_ed25519_yao_active_capability_v1',
    materialActivation: metadata.materialActivation,
    activeCapabilityBinding: metadata.activeCapabilityBinding,
    registeredPublicKey: [...metadata.registeredPublicKey],
    nearAccountId: String(signer.account.nearAccountId),
    applicationBinding: metadata.applicationBinding,
    runtimePolicyScope: args.material.facts.runtimePolicyScope,
    participantIds: metadata.participantIds,
    lifecycle: {
      lifecycleId: metadata.scope.lifecycle_id,
      rootShareEpoch: metadata.scope.root_share_epoch,
      accountId: metadata.scope.account_id,
      thresholdSessionId: thresholdSessionId.value,
      signerSetId: metadata.scope.signer_set_id,
      signingWorkerId: metadata.scope.signing_worker_id,
    },
    stateEpoch: Number(metadata.stateEpoch),
    registrationContinuity: {
      kind: 'recovery',
      activationTranscript: [...metadata.transcript],
    },
  };
}

export async function resolveWalletCustodyEd25519ExportContextV1(input: {
  subject: ExactEd25519ExportMaterialIdentity<EmailOtpEd25519LaneAuth>;
  expectedMaterialActivation: MpcMaterialActivationRef;
  readActiveWalletSessionAuthorization: (
    walletId: WalletId,
  ) => Promise<WalletSessionAuthorizationReadResult<ActiveWalletSessionAuthorizationProjection>>;
  resolveActiveCapability: (
    walletId: WalletId,
    nearAccountId: AccountId,
    materialActivation: MpcMaterialActivationRef,
  ) => NearEd25519YaoOperationMaterial | null;
  loadWalletCustodyMaterial: () => Promise<
    | { readonly kind: 'found'; readonly material: LoadedWalletCustodyEd25519MaterialV1 }
    | { readonly kind: 'absent' }
  >;
  readReusableWalletSessionState: () => Promise<ReusableWalletSessionState>;
  relayerUrl: string;
  fetch: typeof fetch;
  activateRecoveredCapability: (
    result: EmailOtpEd25519YaoWorkerActivationResult & {
      readonly bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
      readonly emailHashHex: string;
    },
  ) => Promise<void>;
}): Promise<ResolvedWalletCustodyEd25519ExportV1> {
  const walletId = input.subject.signer.account.wallet.walletId;
  const authorization = resolveActiveEmailOtpAuthorization({
    walletId,
    result: await input.readActiveWalletSessionAuthorization(walletId),
  });
  const material = input.resolveActiveCapability(
    walletId,
    input.subject.signer.account.nearAccountId,
    input.expectedMaterialActivation,
  );
  if (material) {
    return {
      kind: 'wallet_custody_ed25519_export_context_v1',
      lane: input.subject,
      authorization,
      material: {
        kind: 'active_capability',
        materialActivation: input.expectedMaterialActivation,
        capability: capabilityFromActiveMaterial({
          subject: input.subject,
          expectedMaterialActivation: input.expectedMaterialActivation,
          material,
        }),
      },
    };
  }
  const loaded = await input.loadWalletCustodyMaterial();
  if (loaded.kind !== 'found') {
    throw new Error(
      '[SigningEngine][ed25519-export] sealed wallet custody material is unavailable',
    );
  }
  const cold = await readColdExportBootstrap({
    subject: input.subject,
    authorization,
    material: loaded.material,
    reusableSession: await input.readReusableWalletSessionState(),
    expectedMaterialActivation: input.expectedMaterialActivation,
    relayerUrl: input.relayerUrl,
    fetch: input.fetch,
  });
  return {
    kind: 'wallet_custody_ed25519_export_context_v1',
    lane: input.subject,
    authorization,
    material: {
      kind: 'sealed_custody',
      materialActivation: input.expectedMaterialActivation,
      capability: cold.bootstrap.capability,
      walletCustodyEd25519Material: loaded.material,
      bootstrap: cold.bootstrap,
      activateRecoveredCapability: (result) =>
        input.activateRecoveredCapability({
          ...result,
          bootstrap: cold.bootstrap,
          emailHashHex: cold.emailHashHex,
        }),
    },
  };
}
