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
import type { AccountId } from '@/core/types/accountIds';
import {
  type ActiveWalletSessionV1,
  type WalletSessionOperationCredentialV1,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { ExactWalletSessionStatus } from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';
import type { ActiveWalletAuthMethodV2 } from '@/core/signingEngine/session/identity/ownerLaneScope';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import { activeWalletSessionV1RecordsEqual } from '@shared/device-linking/activeWalletSession';
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
import {
  parseEmailOtpWalletAuthAuthority,
  walletAuthAuthoritiesMatch,
  type EmailOtpWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { base64UrlEncode } from '@shared/utils/base64';
import type {
  PasskeyCustodyEnvelopeRecord,
  PasskeyCustodySecretBinding,
} from '@shared/passkey-custody';
type EmailOtpEd25519LaneAuth = Extract<SigningLaneAuthBinding, { kind: 'email_otp' }>;
type ExactEmailOtpWalletSessionStatus = Extract<
  ExactWalletSessionStatus,
  { readonly status: 'active' }
>;

export type EmailOtpEd25519YaoRecoveredCapabilityActivationV1 =
  EmailOtpEd25519YaoWorkerActivationResult & {
    readonly emailHashHex: string;
  };

export type EmailOtpEd25519YaoRecoveredCapabilityActivationRequestV1 = {
  readonly activation: EmailOtpEd25519YaoRecoveredCapabilityActivationV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
};

type EmailOtpEd25519YaoWorkerActivationRequestV1 = {
  readonly activation: EmailOtpEd25519YaoWorkerActivationResult;
  readonly operationCredential: WalletSessionOperationCredentialV1;
};

export type ExactWalletSessionAuthorizationForEd25519ExportV1 = {
  readonly selectedAuthority: ActiveWalletAuthorityV1;
  readonly selectedAuthMethod: Extract<ActiveWalletAuthMethodV2, { readonly kind: 'email_otp' }>;
  readonly factorAuthority: EmailOtpWalletAuthAuthority;
  readonly record: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
  readonly status: ExactEmailOtpWalletSessionStatus;
};

export type EmailOtpEd25519ExportAuthorizationReadResultV1 =
  | {
      readonly kind: 'found';
      readonly authorization: ExactWalletSessionAuthorizationForEd25519ExportV1;
    }
  | {
      readonly kind:
        | 'missing'
        | 'upgrade_required'
        | 'corrupt'
        | 'persistence_unavailable'
        | 'exhausted'
        | 'expired'
        | 'superseded'
        | 'authority_unavailable'
        | 'method_unavailable'
        | 'capability_unavailable';
      readonly authorization?: never;
    };

type Ed25519YaoClientRootEnvelopeRecordV1 = PasskeyCustodyEnvelopeRecord & {
  readonly binding: Extract<
    PasskeyCustodySecretBinding,
    { readonly kind: 'ed25519_yao_client_root_v1' }
  >;
};

function isEd25519YaoClientRootEnvelopeV1(
  envelope: PasskeyCustodyEnvelopeRecord,
): envelope is Ed25519YaoClientRootEnvelopeRecordV1 {
  return envelope.binding.kind === 'ed25519_yao_client_root_v1';
}

function requireEd25519YaoClientRootEnvelopeV1(
  envelope: PasskeyCustodyEnvelopeRecord,
): Ed25519YaoClientRootEnvelopeRecordV1 {
  if (!isEd25519YaoClientRootEnvelopeV1(envelope)) {
    throw new Error('[SigningEngine][ed25519-export] export envelope has the wrong secret kind');
  }
  return envelope;
}

export type ResolvedWalletCustodyEd25519ExportV1 = {
  readonly kind: 'wallet_custody_ed25519_export_context_v1';
  readonly lane: ExactEd25519ExportMaterialIdentity<EmailOtpEd25519LaneAuth>;
  readonly selectedLaneMaterialActivation: MpcMaterialActivationRef;
  readonly authorization: ExactWalletSessionAuthorizationForEd25519ExportV1;
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
          request: EmailOtpEd25519YaoWorkerActivationRequestV1,
        ) => Promise<void>;
      }
    | {
        readonly kind: 'sealed_export_root';
        readonly materialActivation: MpcMaterialActivationRef;
        readonly capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
        readonly exportRootEnvelope: Ed25519YaoClientRootEnvelopeRecordV1;
      };
};

export type EmailOtpEd25519YaoExportRootResolutionV1 = {
  readonly envelope: PasskeyCustodyEnvelopeRecord;
  readonly source: {
    readonly materialActivation: MpcMaterialActivationRef;
    readonly signingWorkerId: string;
    readonly participantIds: readonly [number, number];
    readonly registeredPublicKeyB64u: string;
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
  readonly authorization: ExactWalletSessionAuthorizationForEd25519ExportV1;
  readonly source: {
    readonly signingWorkerId: string;
    readonly participantIds: readonly [number, number];
    readonly registeredPublicKeyB64u: string;
  };
  readonly expectedMaterialActivation: MpcMaterialActivationRef;
  readonly relayerUrl: string;
  readonly fetch: typeof fetch;
}): Promise<{
  readonly bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  readonly emailHashHex: string;
}> {
  const operationCredential = input.authorization.operationCredential;
  const status = input.authorization.status;
  const authorizationId = input.authorization.record.authorizationId;
  const signer = input.subject.signer;
  const binding = input.source;
  if (
    input.authorization.record.walletId !== signer.account.wallet.walletId ||
    input.authorization.record.authMethodId !==
      input.authorization.selectedAuthMethod.walletAuthMethodId ||
    input.authorization.factorAuthority.factor.providerUserId !==
      input.subject.auth.providerSubjectId ||
    !binding.signingWorkerId ||
    binding.participantIds.length !== 2 ||
    !binding.registeredPublicKeyB64u
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
      headers: {
        Authorization: `Bearer ${operationCredential.token}`,
        'Content-Type': 'application/json',
      },
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
    !walletAuthAuthoritiesMatch(authority, input.authorization.factorAuthority) ||
    walletId !== String(signer.account.wallet.walletId) ||
    nearAccountId !== String(signer.account.nearAccountId) ||
    nearEd25519SigningKeyId !== String(signer.nearEd25519SigningKeyId) ||
    thresholdSessionId.value !== capability.lifecycle.thresholdSessionId ||
    walletSessionId.value !== operationCredential.walletSessionId ||
    quotaId.value !== input.authorization.record.quotaId ||
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
          status.expiresAtMs,
        ),
        participantIds,
        remainingUses: status.remainingUses,
        signingRootId: signingRoot.signingRootId,
        signingRootVersion: runtimePolicyScope.signingRootVersion,
        runtimePolicyScope,
        routerAbNormalSigning,
      },
      capability,
    },
  };
}

async function readLinkedExportCapability(input: {
  readonly subject: ExactEd25519ExportMaterialIdentity<EmailOtpEd25519LaneAuth>;
  readonly authorization: ExactWalletSessionAuthorizationForEd25519ExportV1;
  readonly source: {
    readonly signingWorkerId: string;
    readonly participantIds: readonly [number, number];
    readonly registeredPublicKeyB64u: string;
  };
  readonly expectedMaterialActivation: MpcMaterialActivationRef;
  readonly relayerUrl: string;
  readonly fetch: typeof fetch;
}): Promise<EmailOtpEd25519YaoActiveCapabilityDescriptorV1> {
  const operationCredential = input.authorization.operationCredential;
  const signer = input.subject.signer;
  if (
    input.authorization.record.walletId !== signer.account.wallet.walletId ||
    input.authorization.record.authMethodId !==
      input.authorization.selectedAuthMethod.walletAuthMethodId ||
    input.authorization.factorAuthority.factor.providerUserId !==
      input.subject.auth.providerSubjectId
  ) {
    throw new Error('[SigningEngine][ed25519-export] linked Wallet Session is unavailable');
  }
  const request = parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1({
    kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_request_v1',
    walletId: String(signer.account.wallet.walletId),
    nearAccountId: String(signer.account.nearAccountId),
    nearEd25519SigningKeyId: String(signer.nearEd25519SigningKeyId),
    signerSlot: signer.signerSlot,
    thresholdSessionId: input.subject.thresholdSessionId,
    signingWorkerId: input.source.signingWorkerId,
    participantIds: input.source.participantIds,
  });
  if (!request.ok) throw new Error(request.message);
  const response = await input.fetch(
    `${new URL(input.relayerUrl).origin}${ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1}`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${operationCredential.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request.value),
    },
  );
  const raw = await response.json().catch(() => null);
  if (!response.ok) {
    const failure = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : null;
    throw new Error(
      `[SigningEngine][ed25519-export] linked capability bootstrap failed (HTTP ${response.status}): ${String(failure?.message || 'invalid response')}`,
    );
  }
  const record = requireRecord(raw, 'linked Ed25519 export bootstrap');
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
      'runtimePolicyScope',
      'routerAbNormalSigning',
      'capability',
    ],
    'linked Ed25519 export bootstrap',
  );
  if (record.kind !== 'router_ab_ed25519_yao_warm_recovery_bootstrap_v1') {
    throw new Error('linked Ed25519 export bootstrap kind is invalid');
  }
  const thresholdSessionId = parseThresholdEd25519SessionId(record.thresholdSessionId);
  const walletSessionId = parseWalletSessionId(record.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(record.quotaId);
  const runtimePolicyScope = normalizeRuntimePolicyScope(record.runtimePolicyScope);
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
    !runtimePolicyScope ||
    !routerAbNormalSigning ||
    requireString(record.walletId, 'bootstrap.walletId') !==
      String(signer.account.wallet.walletId) ||
    requireString(record.nearAccountId, 'bootstrap.nearAccountId') !==
      String(signer.account.nearAccountId) ||
    requireString(record.nearEd25519SigningKeyId, 'bootstrap.nearEd25519SigningKeyId') !==
      String(signer.nearEd25519SigningKeyId) ||
    requirePositiveInteger(record.signerSlot, 'bootstrap.signerSlot') !== signer.signerSlot ||
    thresholdSessionId.value !== capability.lifecycle.thresholdSessionId ||
    walletSessionId.value !== operationCredential.walletSessionId ||
    quotaId.value !== input.authorization.record.quotaId ||
    requireString(record.signingWorkerId, 'bootstrap.signingWorkerId') !==
      input.source.signingWorkerId ||
    participantIds[0] !== input.source.participantIds[0] ||
    participantIds[1] !== input.source.participantIds[1] ||
    registeredPublicKeyB64u !== input.source.registeredPublicKeyB64u ||
    !mpcMaterialActivationRefsEqual(capability.materialActivation, input.expectedMaterialActivation)
  ) {
    throw new Error('[SigningEngine][ed25519-export] linked capability identity mismatch');
  }
  return capability;
}

function countExactEd25519ExportSubjects(
  subjects: ActiveWalletSessionV1['capabilitySubjects'],
  expectedMaterialActivation: MpcMaterialActivationRef,
): number {
  let matchCount = 0;
  for (const subject of subjects) {
    switch (subject.kind) {
      case 'export_keys':
        if (
          subject.keyFamily === 'ed25519' &&
          mpcMaterialActivationRefsEqual(subject.materialActivation, expectedMaterialActivation)
        ) {
          matchCount += 1;
        }
        break;
      case 'sign':
      case 'link_devices':
      case 'revoke_devices':
        break;
      default:
        subject satisfies never;
        break;
    }
  }
  return matchCount;
}

function assertExactEmailOtpExportAuthorization(args: {
  readonly subject: ExactEd25519ExportMaterialIdentity<EmailOtpEd25519LaneAuth>;
  readonly expectedMaterialActivation: MpcMaterialActivationRef;
  readonly authorization: ExactWalletSessionAuthorizationForEd25519ExportV1;
}): void {
  const { authorization } = args;
  const selectedAuthority = authorization.selectedAuthority;
  const selectedAuthMethod = authorization.selectedAuthMethod;
  const factorAuthority = authorization.factorAuthority;
  const record = authorization.record;
  const operationCredential = authorization.operationCredential;
  const status = authorization.status;
  if (
    selectedAuthority.state !== 'active' ||
    selectedAuthority.walletId !== args.subject.signer.account.wallet.walletId ||
    selectedAuthMethod.status !== 'active' ||
    selectedAuthMethod.walletId !== args.subject.signer.account.wallet.walletId ||
    selectedAuthMethod.walletAuthorityId !== selectedAuthority.authorityId ||
    factorAuthority.walletId !== args.subject.signer.account.wallet.walletId ||
    factorAuthority.bindingId !== selectedAuthMethod.walletAuthMethodId ||
    factorAuthority.verifier.emailHashHex !== selectedAuthMethod.emailHashHex ||
    factorAuthority.factor.providerUserId !== args.subject.auth.providerSubjectId ||
    record.walletId !== args.subject.signer.account.wallet.walletId ||
    record.authorityId !== selectedAuthority.authorityId ||
    record.authMethodId !== selectedAuthMethod.walletAuthMethodId ||
    String(record.authorityDigestB64u) !== String(selectedAuthority.authorityDigestB64u) ||
    record.authorityRevocationEpoch !== selectedAuthority.revocationEpoch ||
    status.quotaLifecycle !== 'active' ||
    status.remainingUses <= 0 ||
    status.walletSessionId !== operationCredential.walletSessionId ||
    status.quotaId !== record.quotaId ||
    !activeWalletSessionV1RecordsEqual(status.authorization, record) ||
    operationCredential.walletSessionId.trim().length === 0 ||
    operationCredential.token.trim().length === 0 ||
    status.expiresAtMs <= Date.now() ||
    countExactEd25519ExportSubjects(record.capabilitySubjects, args.expectedMaterialActivation) !==
      1
  ) {
    throw new Error(
      '[SigningEngine][ed25519-export] exact Email OTP authorization identity mismatch',
    );
  }
}

function resolveExactEmailOtpExportAuthorization(args: {
  readonly subject: ExactEd25519ExportMaterialIdentity<EmailOtpEd25519LaneAuth>;
  readonly expectedMaterialActivation: MpcMaterialActivationRef;
  readonly result: EmailOtpEd25519ExportAuthorizationReadResultV1;
}): ExactWalletSessionAuthorizationForEd25519ExportV1 {
  switch (args.result.kind) {
    case 'found':
      assertExactEmailOtpExportAuthorization({
        subject: args.subject,
        expectedMaterialActivation: args.expectedMaterialActivation,
        authorization: args.result.authorization,
      });
      return args.result.authorization;
    case 'missing':
      throw new Error('[SigningEngine][ed25519-export] exact Email OTP authorization is missing');
    case 'upgrade_required':
      throw new Error(
        '[SigningEngine][ed25519-export] exact Email OTP authorization requires an upgrade',
      );
    case 'corrupt':
      throw new Error('[SigningEngine][ed25519-export] exact Email OTP authorization is corrupt');
    case 'persistence_unavailable':
      throw new Error(
        '[SigningEngine][ed25519-export] exact Email OTP authorization persistence is unavailable',
      );
    case 'exhausted':
      throw new Error(
        '[SigningEngine][ed25519-export] exact Email OTP authorization is exhausted',
      );
    case 'expired':
      throw new Error('[SigningEngine][ed25519-export] exact Email OTP authorization is expired');
    case 'superseded':
      throw new Error(
        '[SigningEngine][ed25519-export] exact Email OTP authorization is superseded',
      );
    case 'authority_unavailable':
      throw new Error(
        '[SigningEngine][ed25519-export] exact Email OTP authority is unavailable',
      );
    case 'method_unavailable':
      throw new Error(
        '[SigningEngine][ed25519-export] exact Email OTP method is unavailable',
      );
    case 'capability_unavailable':
      throw new Error(
        '[SigningEngine][ed25519-export] exact Email OTP export capability is unavailable',
      );
    default: {
      const exhaustive: never = args.result;
      return exhaustive;
    }
  }
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
  readExactWalletSessionAuthorization: (args: {
    readonly subject: ExactEd25519ExportMaterialIdentity<EmailOtpEd25519LaneAuth>;
    readonly expectedMaterialActivation: MpcMaterialActivationRef;
  }) => Promise<EmailOtpEd25519ExportAuthorizationReadResultV1>;
  resolveActiveCapability: (
    walletId: WalletId,
    nearAccountId: AccountId,
    materialActivation: MpcMaterialActivationRef,
  ) => NearEd25519YaoOperationMaterial | null;
  resolveEd25519YaoClientRootEnvelope?: (args: {
    readonly subject: ExactEd25519ExportMaterialIdentity<EmailOtpEd25519LaneAuth>;
    readonly capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1 | null;
    readonly selectedMaterialActivation: MpcMaterialActivationRef;
  }) => Promise<PasskeyCustodyEnvelopeRecord | EmailOtpEd25519YaoExportRootResolutionV1 | null>;
  loadWalletCustodyMaterial: () => Promise<
    | { readonly kind: 'found'; readonly material: LoadedWalletCustodyEd25519MaterialV1 }
    | { readonly kind: 'absent' }
  >;
  relayerUrl: string;
  fetch: typeof fetch;
  activateRecoveredCapability: (
    request: EmailOtpEd25519YaoRecoveredCapabilityActivationRequestV1,
  ) => Promise<void>;
}): Promise<ResolvedWalletCustodyEd25519ExportV1> {
  const walletId = input.subject.signer.account.wallet.walletId;
  const exactAuthorization = resolveExactEmailOtpExportAuthorization({
    subject: input.subject,
    expectedMaterialActivation: input.expectedMaterialActivation,
    result: await input.readExactWalletSessionAuthorization({
      subject: input.subject,
      expectedMaterialActivation: input.expectedMaterialActivation,
    }),
  });
  const material = input.resolveActiveCapability(
    walletId,
    input.subject.signer.account.nearAccountId,
    input.expectedMaterialActivation,
  );
  const activeCapability = material
    ? capabilityFromActiveMaterial({
        subject: input.subject,
        expectedMaterialActivation: input.expectedMaterialActivation,
        material,
      })
    : null;
  const rootResolution = input.resolveEd25519YaoClientRootEnvelope
    ? await input.resolveEd25519YaoClientRootEnvelope({
        subject: input.subject,
        capability: activeCapability,
        selectedMaterialActivation: input.expectedMaterialActivation,
      })
    : null;
  const rootEnvelope =
    rootResolution && 'envelope' in rootResolution ? rootResolution.envelope : rootResolution;
  let rootCapability = activeCapability;
  if (rootResolution && 'envelope' in rootResolution) {
    rootCapability = await readLinkedExportCapability({
      subject: input.subject,
      authorization: exactAuthorization,
      source: rootResolution.source,
      expectedMaterialActivation: rootResolution.source.materialActivation,
      relayerUrl: input.relayerUrl,
      fetch: input.fetch,
    });
  }
  if (rootEnvelope) {
    if (!rootCapability) {
      throw new Error(
        '[SigningEngine][ed25519-export] Ed25519 export-root capability is unavailable',
      );
    }
    return {
      kind: 'wallet_custody_ed25519_export_context_v1',
      lane: input.subject,
      selectedLaneMaterialActivation: input.expectedMaterialActivation,
      authorization: exactAuthorization,
      material: {
        kind: 'sealed_export_root',
        materialActivation: rootCapability.materialActivation,
        capability: rootCapability,
        exportRootEnvelope: requireEd25519YaoClientRootEnvelopeV1(rootEnvelope),
      },
    };
  }
  if (material) {
    if (!activeCapability) {
      throw new Error('[SigningEngine][ed25519-export] active Email OTP capability is unavailable');
    }
    return {
      kind: 'wallet_custody_ed25519_export_context_v1',
      lane: input.subject,
      selectedLaneMaterialActivation: input.expectedMaterialActivation,
      authorization: exactAuthorization,
      material: {
        kind: 'active_capability',
        materialActivation: input.expectedMaterialActivation,
        capability: activeCapability,
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
    authorization: exactAuthorization,
    source: loaded.material.binding,
    expectedMaterialActivation: input.expectedMaterialActivation,
    relayerUrl: input.relayerUrl,
    fetch: input.fetch,
  });
  return {
    kind: 'wallet_custody_ed25519_export_context_v1',
    lane: input.subject,
    selectedLaneMaterialActivation: input.expectedMaterialActivation,
    authorization: exactAuthorization,
    material: {
      kind: 'sealed_custody',
      materialActivation: input.expectedMaterialActivation,
      capability: cold.bootstrap.capability,
      walletCustodyEd25519Material: loaded.material,
      bootstrap: cold.bootstrap,
      activateRecoveredCapability: (request) => {
        if (
          request.operationCredential.walletSessionId !==
            exactAuthorization.operationCredential.walletSessionId ||
          request.operationCredential.token !== exactAuthorization.operationCredential.token
        ) {
          throw new Error(
            '[SigningEngine][ed25519-export] recovered capability credential does not match authorization',
          );
        }
        return input.activateRecoveredCapability({
          activation: {
            ...request.activation,
            bootstrap: cold.bootstrap,
            emailHashHex: cold.emailHashHex,
          },
          operationCredential: request.operationCredential,
        });
      },
    },
  };
}
