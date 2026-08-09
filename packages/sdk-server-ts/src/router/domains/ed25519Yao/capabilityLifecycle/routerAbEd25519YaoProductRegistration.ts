import {
  computeAddSignerNearEd25519SigningKeyId,
  computeRegistrationNearEd25519SigningKeyId,
  registrationEd25519AuthorityScopeFromAuthority,
  registrationNearEd25519BranchKey,
  type AddSignerIntentV1,
  type RegistrationAuthority,
  type RegistrationNearEd25519SignerPlan,
  type WalletId,
  type RegistrationEd25519AuthorityScope,
} from '@shared/utils/registrationIntent';
import {
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  routerAbMpcMaterialActivationRefToWire,
  type RouterAbMpcMaterialActivationRefWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import type {
  RouterAbEd25519YaoActivationConsumerV1,
  RouterAbEd25519YaoActivationConsumptionRequestV1,
  RouterAbEd25519YaoActivationConsumptionResultV1,
  RouterAbEd25519YaoRegistrationAdmissionClaimV1,
  RouterAbEd25519YaoRegistrationExecuteRequestV1,
  RouterAbEd25519YaoRegistrationResultV1,
  RouterAbEd25519YaoRegistrationServiceResult,
} from '../registration/routerAbEd25519YaoRegistration';
import {
  createRouterAbEd25519YaoRegistrationModule,
  InMemoryRouterAbEd25519YaoRegistrationStateV1,
  type RouterAbEd25519YaoRegistrationBackend,
  type RouterAbEd25519YaoRegistrationAuthorizationAdapter,
  type RouterAbEd25519YaoRegistrationService,
} from '../registration/routerAbEd25519YaoRegistration';
import {
  InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationStateV1,
  type RouterAbEd25519YaoVerifiedActivationIntentV1,
  type RouterAbEd25519YaoRegistrationIntentBindingResult,
} from '../registration/routerAbEd25519YaoRegistrationIntentAuthorization';
import type { SessionAdapter } from '../../../framework/routerApi';
import { createRouterApiModule, type RouterApiModule } from '../../../framework/modules';
import { signRouterAbEd25519WalletSessionJwt } from '../../../auth/commonRouterUtils';
import type {
  MpcWalletSigningQuotaId,
  SeamsSessionId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { ThresholdEd25519SessionId } from '@shared/utils/domainIds';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { deriveSigningRootId, type RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { WalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { WalletRegistrationEd25519YaoBootstrapSession } from '../../../../core/registrationContracts';
import { thresholdEd25519AuthorityScopeFromWalletAuthAuthority } from '../../../../core/ThresholdService/validation';
import {
  createRouterAbEd25519YaoRecoveryModule,
  InMemoryRouterAbEd25519YaoRecoveryStateV1,
  type RouterAbEd25519YaoActiveCapabilityLookupResultV1,
  type RouterAbEd25519YaoActiveCapabilityLookupV1,
  type RouterAbEd25519YaoActiveCapabilityResolverV1,
  type RouterAbEd25519YaoPersistedActiveCapabilityInstallerV1,
  type RouterAbEd25519YaoRecoveryBackend,
  type RouterAbEd25519YaoRecoveryAuthorizationAdapter,
  type RouterAbEd25519YaoRecoveryService,
  type RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1,
  type RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1,
  type RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallerV1,
} from '../recovery/routerAbEd25519YaoRecovery';
import type { WalletEd25519YaoActiveCapabilityRecord } from '../../../../core/WalletStore';
import {
  createRouterAbEd25519YaoExportModule,
  InMemoryRouterAbEd25519YaoExportStateV1,
  type RouterAbEd25519YaoExportBackend,
  type RouterAbEd25519YaoExportAuthorizationAdapter,
  type RouterAbEd25519YaoExportService,
} from '../export/routerAbEd25519YaoExport';
import { isPlainObject } from '@shared/utils/validation';
import {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';

export type RouterAbEd25519YaoWalletSessionMintResultV1 =
  | { readonly ok: true; readonly session: WalletRegistrationEd25519YaoBootstrapSession }
  | { readonly ok: false; readonly code: string; readonly message: string };

type RouterAbEd25519YaoWalletSessionMintIdentityV1 = {
  readonly walletId: WalletId;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly authority: WalletAuthAuthority;
  readonly thresholdSessionId: ThresholdEd25519SessionId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly participantIds: readonly [number, number];
  readonly runtimePolicyScope: RuntimePolicyScope;
};

export type RouterAbEd25519YaoWalletSessionMintInputV1 =
  | (RouterAbEd25519YaoWalletSessionMintIdentityV1 & {
      readonly kind: 'verified_wallet_unlock_v1';
      readonly ttlMs?: never;
      readonly expiresAtMs: number;
      readonly remainingUses: number;
      readonly seamsSessionId?: never;
    })
  | (RouterAbEd25519YaoWalletSessionMintIdentityV1 & {
      readonly kind: 'verified_app_session_wallet_unlock_v1';
      readonly ttlMs?: never;
      readonly expiresAtMs: number;
      readonly remainingUses: number;
      readonly seamsSessionId: SeamsSessionId;
    })
  | (RouterAbEd25519YaoWalletSessionMintIdentityV1 & {
      readonly kind: 'same_identity_budget_refresh_v1';
      readonly expiresAtMs?: never;
      readonly remainingUses: number;
      readonly seamsSessionId?: SeamsSessionId;
    });

export type RouterAbEd25519YaoProductRegistrationRuntimeV1 =
  RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallerV1 &
    RouterAbEd25519YaoPersistedActiveCapabilityInstallerV1 &
    RouterAbEd25519YaoActiveCapabilityResolverV1 & {
      readonly kind: 'router_ab_ed25519_yao_product_registration_runtime_v1';
      readonly signingWorkerId: string;
      bindAndAdmitVerifiedRegistration(
        input: RouterAbEd25519YaoVerifiedActivationIntentV1,
      ): Promise<RouterAbEd25519YaoVerifiedRegistrationAdmissionResultV1>;
      bindVerifiedIntent(
        input: RouterAbEd25519YaoVerifiedActivationIntentV1,
      ): Promise<RouterAbEd25519YaoRegistrationIntentBindingResult>;
      consumeActivated(
        request: RouterAbEd25519YaoActivationConsumptionRequestV1,
      ): Promise<RouterAbEd25519YaoActivationConsumptionResultV1>;
      replayActivatedRegistration(
        request: RouterAbEd25519YaoRegistrationExecuteRequestV1,
      ): Promise<
        RouterAbEd25519YaoRegistrationServiceResult<RouterAbEd25519YaoRegistrationResultV1>
      >;
      mintWalletSession(
        input: RouterAbEd25519YaoWalletSessionMintInputV1,
      ): Promise<RouterAbEd25519YaoWalletSessionMintResultV1>;
    };

export type RouterAbEd25519YaoVerifiedRegistrationAdmissionResultV1 =
  | Extract<RouterAbEd25519YaoRegistrationIntentBindingResult, { readonly ok: false }>
  | RouterAbEd25519YaoRegistrationServiceResult<
      RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>
    >;

export type RouterAbEd25519YaoProductRegistrationCompositionV1 = {
  readonly kind: 'router_ab_ed25519_yao_product_registration_composition_v1';
  readonly registrationService: RouterAbEd25519YaoProductRegistrationServicePortV1;
  readonly authorization: RouterAbEd25519YaoProductRegistrationAuthorizationPortV1;
  readonly recoveryService: RouterAbEd25519YaoProductRecoveryServicePortV1;
  readonly recoveryAuthorization: RouterAbEd25519YaoRecoveryAuthorizationAdapter;
  readonly exportService: RouterAbEd25519YaoExportService;
  readonly exportAuthorization: RouterAbEd25519YaoExportAuthorizationAdapter;
  readonly runtime: RouterAbEd25519YaoProductRegistrationRuntimeV1;
  readonly module: RouterApiModule;
};

export interface RouterAbEd25519YaoProductRegistrationServicePortV1
  extends RouterAbEd25519YaoRegistrationService, RouterAbEd25519YaoActivationConsumerV1 {}

export interface RouterAbEd25519YaoProductRegistrationAuthorizationPortV1 extends RouterAbEd25519YaoRegistrationAuthorizationAdapter {
  bindVerifiedIntent(
    input: RouterAbEd25519YaoVerifiedActivationIntentV1,
  ): Promise<RouterAbEd25519YaoRegistrationIntentBindingResult>;
}

export interface RouterAbEd25519YaoProductRecoveryServicePortV1
  extends
    RouterAbEd25519YaoRecoveryService,
    RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallerV1,
    RouterAbEd25519YaoPersistedActiveCapabilityInstallerV1,
    RouterAbEd25519YaoActiveCapabilityResolverV1 {}

export type RouterAbEd25519YaoProductRegistrationPortsV1 = {
  readonly signingWorkerId: string;
  readonly registrationService: RouterAbEd25519YaoProductRegistrationServicePortV1;
  readonly authorization: RouterAbEd25519YaoProductRegistrationAuthorizationPortV1;
  readonly recoveryService: RouterAbEd25519YaoProductRecoveryServicePortV1;
  readonly capabilities: RouterAbEd25519YaoActiveCapabilityResolverV1;
  readonly recoveryAuthorization: RouterAbEd25519YaoRecoveryAuthorizationAdapter;
  readonly exportService: RouterAbEd25519YaoExportService;
  readonly exportAuthorization: RouterAbEd25519YaoExportAuthorizationAdapter;
  readonly session: SessionAdapter;
};

export type RouterAbEd25519YaoProductRegistrationStateV1 = {
  readonly kind: 'router_ab_ed25519_yao_product_registration_state_v1';
  readonly registration: InMemoryRouterAbEd25519YaoRegistrationStateV1;
  readonly authorization: InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationStateV1;
  readonly recovery: InMemoryRouterAbEd25519YaoRecoveryStateV1;
  readonly export: InMemoryRouterAbEd25519YaoExportStateV1;
};

export function createRouterAbEd25519YaoProductRegistrationStateV1(): RouterAbEd25519YaoProductRegistrationStateV1 {
  return {
    kind: 'router_ab_ed25519_yao_product_registration_state_v1',
    registration: new InMemoryRouterAbEd25519YaoRegistrationStateV1(),
    authorization: new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationStateV1(),
    recovery: new InMemoryRouterAbEd25519YaoRecoveryStateV1(),
    export: new InMemoryRouterAbEd25519YaoExportStateV1(),
  };
}

const REGISTRATION_STATE_KINDS = new Set(['admitted', 'executing', 'activated', 'failed']);
const REGISTRATION_ADMISSION_CLAIM_KINDS = new Set([
  'router_ab_ed25519_yao_registration_admission_claim_v1',
]);
const INTENT_AUTHORITY_KINDS = new Set(['available', 'admitted']);
const CAPABILITY_STATE_KINDS = new Set(['active', 'suspended', 'retired']);
const RECOVERY_STATE_KINDS = new Set([
  'admitting',
  'admission_failed',
  'admitted',
  'executing',
  'execution_failed',
  'staged',
  'activating',
  'activation_failed',
  'promoted',
]);
const EXPORT_STATE_KINDS = new Set([
  'authorizing',
  'authorization_failed',
  'authorized',
  'admitting',
  'admission_failed',
  'admitted',
  'executing',
  'execution_failed',
  'completed',
]);

function isStringMapWithStateKinds(input: unknown, kinds: ReadonlySet<string>): boolean {
  if (!(input instanceof Map)) return false;
  for (const [key, value] of input) {
    if (typeof key !== 'string' || !isPlainObject(value) || !kinds.has(String(value.kind))) {
      return false;
    }
  }
  return true;
}

function isStringMap(input: unknown): input is Map<string, string> {
  if (!(input instanceof Map)) return false;
  for (const [key, value] of input) {
    if (typeof key !== 'string' || typeof value !== 'string') return false;
  }
  return true;
}

function isStringSet(input: unknown): input is Set<string> {
  if (!(input instanceof Set)) return false;
  for (const value of input) {
    if (typeof value !== 'string') return false;
  }
  return true;
}

function hasProductStateCollections(
  input: unknown,
): input is RouterAbEd25519YaoProductRegistrationStateV1 {
  if (!isPlainObject(input)) return false;
  if (input.kind !== 'router_ab_ed25519_yao_product_registration_state_v1') return false;
  const registration = input.registration;
  const authorization = input.authorization;
  const recovery = input.recovery;
  const exportState = input.export;
  if (
    !isPlainObject(registration) ||
    !isPlainObject(authorization) ||
    !isPlainObject(recovery) ||
    !isPlainObject(exportState)
  ) {
    return false;
  }
  return (
    isStringMapWithStateKinds(registration.states, REGISTRATION_STATE_KINDS) &&
    isStringMap(registration.lifecycleSessions) &&
    (registration.admissionClaims === undefined ||
      isStringMapWithStateKinds(
        registration.admissionClaims,
        REGISTRATION_ADMISSION_CLAIM_KINDS,
      )) &&
    Array.isArray(authorization.authorities) &&
    authorization.authorities.every(
      (authority) => isPlainObject(authority) && INTENT_AUTHORITY_KINDS.has(String(authority.kind)),
    ) &&
    isStringMapWithStateKinds(recovery.capabilities, CAPABILITY_STATE_KINDS) &&
    isStringMap(recovery.identityCapabilities) &&
    isStringMapWithStateKinds(recovery.recoveries, RECOVERY_STATE_KINDS) &&
    isStringMap(recovery.recoverySessions) &&
    isStringMapWithStateKinds(exportState.exports, EXPORT_STATE_KINDS) &&
    isStringSet(exportState.authorizationNonces) &&
    (exportState.authorizationUncertain === undefined ||
      isStringSet(exportState.authorizationUncertain))
  );
}

export type RouterAbEd25519YaoProductRegistrationStateParseResultV1 =
  | { readonly ok: true; readonly value: RouterAbEd25519YaoProductRegistrationStateV1 }
  | { readonly ok: false; readonly message: string };

export function parseRouterAbEd25519YaoProductRegistrationStateV1(
  input: unknown,
): RouterAbEd25519YaoProductRegistrationStateParseResultV1 {
  if (!hasProductStateCollections(input)) {
    return {
      ok: false,
      message: 'persisted Ed25519 Yao product state has invalid lifecycle collections',
    };
  }
  const registration = input.registration;
  const admissionClaims =
    registration.admissionClaims === undefined
      ? new Map<string, RouterAbEd25519YaoRegistrationAdmissionClaimV1>()
      : registration.admissionClaims;
  const authorizationUncertain =
    input.export.authorizationUncertain === undefined
      ? new Set<string>()
      : input.export.authorizationUncertain;
  return {
    ok: true,
    value: {
      kind: 'router_ab_ed25519_yao_product_registration_state_v1',
      registration: {
        states: registration.states,
        lifecycleSessions: registration.lifecycleSessions,
        admissionClaims,
      },
      authorization: input.authorization,
      recovery: input.recovery,
      export: {
        exports: input.export.exports,
        authorizationNonces: input.export.authorizationNonces,
        authorizationUncertain,
      },
    },
  };
}

export function createRouterAbEd25519YaoProductRegistrationCompositionFromPortsV1(
  input: RouterAbEd25519YaoProductRegistrationPortsV1,
): RouterAbEd25519YaoProductRegistrationCompositionV1 {
  const runtime = createRouterAbEd25519YaoProductRegistrationRuntimeV1({
    signingWorkerId: input.signingWorkerId,
    registrationService: input.registrationService,
    authorization: input.authorization,
    capabilityInstaller: input.recoveryService,
    capabilityResolver: input.capabilities,
    session: input.session,
  });
  const registrationModule = createRouterAbEd25519YaoRegistrationModule({
    service: input.registrationService,
    authorization: input.authorization,
  });
  const recoveryModule = createRouterAbEd25519YaoRecoveryModule({
    service: input.recoveryService,
    capabilities: input.capabilities,
    authorization: input.recoveryAuthorization,
  });
  const exportModule = createRouterAbEd25519YaoExportModule({
    service: input.exportService,
    authorization: input.exportAuthorization,
  });
  const module = createRouterApiModule({
    id: 'router_ab_ed25519_yao_product',
    routeExtensions: [
      ...registrationModule.routeExtensions,
      ...recoveryModule.routeExtensions,
      ...exportModule.routeExtensions,
    ],
  });
  return {
    kind: 'router_ab_ed25519_yao_product_registration_composition_v1',
    registrationService: input.registrationService,
    authorization: input.authorization,
    recoveryService: input.recoveryService,
    recoveryAuthorization: input.recoveryAuthorization,
    exportService: input.exportService,
    exportAuthorization: input.exportAuthorization,
    runtime,
    module,
  };
}

type RouterAbEd25519YaoWalletSessionTermsV1 = {
  readonly expiresAtMs: number;
  readonly remainingUses: number;
};

function assertNeverWalletSessionMintInput(value: never): never {
  throw new Error(`Unexpected Ed25519 Yao Wallet Session mint kind: ${String(value)}`);
}

async function resolveRouterAbEd25519YaoWalletSessionTermsV1(
  input: RouterAbEd25519YaoWalletSessionMintInputV1,
): Promise<RouterAbEd25519YaoWalletSessionTermsV1> {
  const nowMs = Date.now();
  switch (input.kind) {
    case 'verified_wallet_unlock_v1':
    case 'verified_app_session_wallet_unlock_v1':
      if (!Number.isSafeInteger(input.expiresAtMs) || input.expiresAtMs <= nowMs) {
        throw new Error('Verified wallet unlock expiry must follow issuance');
      }
      return {
        expiresAtMs: input.expiresAtMs,
        remainingUses: Math.min(
          DEFAULT_WALLET_SESSION_REMAINING_USES,
          Math.max(1, Math.floor(input.remainingUses)),
        ),
      };
    case 'same_identity_budget_refresh_v1':
      return {
        expiresAtMs: nowMs + DEFAULT_WALLET_SESSION_TTL_MS,
        remainingUses: Math.min(
          DEFAULT_WALLET_SESSION_REMAINING_USES,
          Math.max(1, Math.floor(input.remainingUses)),
        ),
      };
    default:
      return assertNeverWalletSessionMintInput(input);
  }
}

class RouterAbEd25519YaoProductRegistrationRuntime implements RouterAbEd25519YaoProductRegistrationRuntimeV1 {
  readonly kind = 'router_ab_ed25519_yao_product_registration_runtime_v1' as const;
  readonly signingWorkerId: string;

  constructor(
    private readonly input: {
      readonly signingWorkerId: string;
      readonly registrationService: RouterAbEd25519YaoProductRegistrationServicePortV1;
      readonly authorization: RouterAbEd25519YaoProductRegistrationAuthorizationPortV1;
      readonly capabilityInstaller: RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallerV1 &
        RouterAbEd25519YaoPersistedActiveCapabilityInstallerV1;
      readonly capabilityResolver: RouterAbEd25519YaoActiveCapabilityResolverV1;
      readonly session: SessionAdapter;
    },
  ) {
    this.signingWorkerId = input.signingWorkerId.trim();
    if (!this.signingWorkerId) throw new Error('Ed25519 Yao SigningWorker ID is required');
  }

  async bindVerifiedIntent(
    input: RouterAbEd25519YaoVerifiedActivationIntentV1,
  ): Promise<RouterAbEd25519YaoRegistrationIntentBindingResult> {
    return await this.input.authorization.bindVerifiedIntent(input);
  }

  async bindAndAdmitVerifiedRegistration(
    input: RouterAbEd25519YaoVerifiedActivationIntentV1,
  ): Promise<RouterAbEd25519YaoVerifiedRegistrationAdmissionResultV1> {
    const bound = await this.input.authorization.bindVerifiedIntent(input);
    if (!bound.ok) return bound;
    return await this.input.registrationService.admit(input.admissionRequest);
  }

  async consumeActivated(
    request: RouterAbEd25519YaoActivationConsumptionRequestV1,
  ): Promise<RouterAbEd25519YaoActivationConsumptionResultV1> {
    const activationConsumer: RouterAbEd25519YaoActivationConsumerV1 =
      this.input.registrationService;
    return await activationConsumer.consumeActivated(request);
  }

  async replayActivatedRegistration(
    request: RouterAbEd25519YaoRegistrationExecuteRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationServiceResult<RouterAbEd25519YaoRegistrationResultV1>> {
    return this.input.registrationService.replayActivated(request);
  }

  async installRegistrationFinalizeCapability(
    input: RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1,
  ): Promise<RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1> {
    return await this.input.capabilityInstaller.installRegistrationFinalizeCapability(input);
  }

  async installPersistedActiveCapability(
    input: WalletEd25519YaoActiveCapabilityRecord,
  ): Promise<RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1> {
    return await this.input.capabilityInstaller.installPersistedActiveCapability(input);
  }

  async resolveActiveCapability(
    input: RouterAbEd25519YaoActiveCapabilityLookupV1,
  ): Promise<RouterAbEd25519YaoActiveCapabilityLookupResultV1> {
    return await this.input.capabilityResolver.resolveActiveCapability(input);
  }

  async mintWalletSession(
    sessionInput: RouterAbEd25519YaoWalletSessionMintInputV1,
  ): Promise<RouterAbEd25519YaoWalletSessionMintResultV1> {
    return await mintRouterAbEd25519YaoWalletSessionV1({
      session: this.input.session,
      signingWorkerId: this.signingWorkerId,
      sessionInput,
    });
  }
}

export async function mintRouterAbEd25519YaoWalletSessionV1(input: {
  readonly session: SessionAdapter;
  readonly signingWorkerId: string;
  readonly sessionInput: RouterAbEd25519YaoWalletSessionMintInputV1;
}): Promise<RouterAbEd25519YaoWalletSessionMintResultV1> {
  const signingWorkerId = input.signingWorkerId.trim();
  if (!signingWorkerId) throw new Error('Ed25519 Yao SigningWorker ID is required');
  const sessionInput = input.sessionInput;
  const terms = await resolveRouterAbEd25519YaoWalletSessionTermsV1(sessionInput);
  const signingRootId = deriveSigningRootId(sessionInput.runtimePolicyScope);
  const signingRootVersion = sessionInput.runtimePolicyScope.signingRootVersion;
  const routerAbNormalSigning = {
    kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
    signingWorkerId,
  } as const;
  const signed = await signRouterAbEd25519WalletSessionJwt({
    session: input.session,
    userId: sessionInput.walletId,
    relayerKeyId: signingWorkerId,
    authority: sessionInput.authority,
    sessionInfo: {
      sessionKind: 'jwt',
      ...(sessionInput.seamsSessionId ? { seamsSessionId: sessionInput.seamsSessionId } : {}),
      walletId: sessionInput.walletId,
      nearAccountId: sessionInput.nearAccountId,
      nearEd25519SigningKeyId: sessionInput.nearEd25519SigningKeyId,
      thresholdSessionId: sessionInput.thresholdSessionId,
      authorizationId: sessionInput.authorizationId,
      walletSessionId: sessionInput.walletSessionId,
      quotaId: sessionInput.quotaId,
      expiresAtMs: terms.expiresAtMs,
      participantIds: [sessionInput.participantIds[0], sessionInput.participantIds[1]],
      runtimePolicyScope: sessionInput.runtimePolicyScope,
      routerAbNormalSigning,
    },
    fallbackParticipantIds: [sessionInput.participantIds[0], sessionInput.participantIds[1]],
    requireJwtErrorMessage: 'Ed25519 Wallet Session must use jwt sessionKind',
    invalidPayloadErrorMessage: 'invalid Ed25519 Yao Wallet Session payload for jwt signing',
  });
  if (!signed.ok) return { ok: false, code: signed.code, message: signed.message };
  return {
    ok: true,
    session: {
      sessionKind: 'jwt',
      walletSessionJwt: signed.jwt,
      walletId: sessionInput.walletId,
      nearAccountId: sessionInput.nearAccountId,
      nearEd25519SigningKeyId: sessionInput.nearEd25519SigningKeyId,
      authorityScope: thresholdEd25519AuthorityScopeFromWalletAuthAuthority(sessionInput.authority),
      thresholdSessionId: signed.thresholdSessionId,
      walletSessionId: sessionInput.walletSessionId,
      quotaId: sessionInput.quotaId,
      expiresAtMs: signed.thresholdExpiresAtMs,
      participantIds: [sessionInput.participantIds[0], sessionInput.participantIds[1]],
      remainingUses: terms.remainingUses,
      signingRootId,
      signingRootVersion,
      runtimePolicyScope: sessionInput.runtimePolicyScope,
      routerAbNormalSigning,
    },
  };
}

export function createRouterAbEd25519YaoProductRegistrationRuntimeV1(input: {
  readonly signingWorkerId: string;
  readonly registrationService: RouterAbEd25519YaoProductRegistrationServicePortV1;
  readonly authorization: RouterAbEd25519YaoProductRegistrationAuthorizationPortV1;
  readonly capabilityInstaller: RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallerV1 &
    RouterAbEd25519YaoPersistedActiveCapabilityInstallerV1;
  readonly capabilityResolver: RouterAbEd25519YaoActiveCapabilityResolverV1;
  readonly session: SessionAdapter;
}): RouterAbEd25519YaoProductRegistrationRuntimeV1 {
  return new RouterAbEd25519YaoProductRegistrationRuntime(input);
}

export function routerAbEd25519YaoPersistedCapabilityMatchesLookupV1(
  capability: WalletEd25519YaoActiveCapabilityRecord,
  lookup: RouterAbEd25519YaoActiveCapabilityLookupV1,
): boolean {
  const application = capability.admissionRequest.application_binding;
  const participants = capability.admissionRequest.participant_ids;
  return (
    application.wallet_id === lookup.walletId &&
    application.near_ed25519_signing_key_id === lookup.nearEd25519SigningKeyId &&
    application.key_creation_signer_slot === lookup.signerSlot &&
    capability.admissionRequest.scope.signing_worker_id === lookup.signingWorkerId &&
    participants[0] === lookup.participantIds[0] &&
    participants[1] === lookup.participantIds[1]
  );
}

/**
 * Mints the explicit material identity at the registration boundary. None of
 * its fields are derived from a wallet-session or ceremony identifier.
 */
export function createRouterAbEd25519YaoMaterialActivationRefV1(input: {
  readonly walletId: WalletId;
  readonly signingWorkerId: string;
}): RouterAbMpcMaterialActivationRefWire {
  const signingWorkerId = input.signingWorkerId.trim();
  if (!signingWorkerId) throw new Error('Ed25519 Yao signing worker is required');
  return routerAbMpcMaterialActivationRefToWire({
    kind: 'mpc_material_activation_ref',
    activationId: `mact_${secureRandomBase64Url(24)}`,
    capability: `cap_${secureRandomBase64Url(24)}`,
    materialOwner: String(input.walletId),
    keyBinding: `key_${secureRandomBase64Url(24)}`,
    lifecycleBinding: `life_${secureRandomBase64Url(24)}`,
    signingWorker: signingWorkerId,
  });
}

/**
 * Takes the authority *scope* rather than the authority because setup admits
 * before the proof exists (Refactor 94C). Callers holding a verified authority
 * pass `registrationEd25519AuthorityScopeFromAuthority(authority)`; setup
 * passes the scope derived from the requested auth method, and only when that
 * derivation is complete without a proof.
 */
export async function buildRouterAbEd25519YaoProductAdmissionRequestV1(input: {
  readonly registrationCeremonyId: string;
  readonly walletId: WalletId;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly authorityScope: RegistrationEd25519AuthorityScope;
  readonly branch: RegistrationNearEd25519SignerPlan;
  readonly signingWorkerId: string;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
}): Promise<RouterAbEd25519YaoRegistrationAdmissionRequestV1> {
  if (input.branch.participantIds.length !== 2) {
    throw new Error('Ed25519 Yao registration requires exactly two participant IDs');
  }
  const firstParticipantId = input.branch.participantIds[0];
  const secondParticipantId = input.branch.participantIds[1];
  if (firstParticipantId === undefined || secondParticipantId === undefined) {
    throw new Error('Ed25519 Yao participant IDs are incomplete');
  }
  const nearEd25519SigningKeyId = await computeRegistrationNearEd25519SigningKeyId({
    walletId: input.walletId,
    authorityScope: input.authorityScope,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    ed25519: {
      accountProvisioning: input.branch.accountProvisioning,
      signerSlot: input.branch.signerSlot,
      participantIds: [firstParticipantId, secondParticipantId],
      keyPurpose: input.branch.keyPurpose,
      keyVersion: input.branch.keyVersion,
      derivationVersion: input.branch.derivationVersion,
    },
  });
  const parsed = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1({
    scope: {
      lifecycle_id: input.registrationCeremonyId,
      root_share_epoch: input.signingRootVersion,
      account_id: String(input.walletId),
      threshold_session_id: input.registrationCeremonyId,
      signer_set_id: input.branch.branchKey,
      signing_worker_id: input.signingWorkerId,
      material_activation: input.materialActivation,
    },
    application_binding: {
      wallet_id: String(input.walletId),
      near_ed25519_signing_key_id: nearEd25519SigningKeyId,
      signing_root_id: input.signingRootId,
      key_creation_signer_slot: input.branch.signerSlot,
    },
    participant_ids: [firstParticipantId, secondParticipantId],
  });
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

export async function buildRouterAbEd25519YaoAddSignerAdmissionRequestV1(input: {
  readonly addSignerCeremonyId: string;
  readonly walletId: WalletId;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly selection: Extract<AddSignerIntentV1['signerSelection'], { mode: 'ed25519' }>;
  readonly signingWorkerId: string;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
}): Promise<RouterAbEd25519YaoRegistrationAdmissionRequestV1> {
  const branch = input.selection.ed25519;
  if (branch.mode !== 'create_implicit_near_account') {
    throw new Error('Ed25519 Yao add-signer requires implicit NEAR account creation');
  }
  const firstParticipantId = branch.participantIds[0];
  const secondParticipantId = branch.participantIds[1];
  if (
    branch.participantIds.length !== 2 ||
    firstParticipantId === undefined ||
    secondParticipantId === undefined ||
    !Number.isSafeInteger(firstParticipantId) ||
    !Number.isSafeInteger(secondParticipantId) ||
    firstParticipantId <= 0 ||
    secondParticipantId <= 0 ||
    firstParticipantId === secondParticipantId
  ) {
    throw new Error('Ed25519 Yao add-signer requires two distinct positive participant IDs');
  }
  const participantIds: readonly [number, number] = [firstParticipantId, secondParticipantId];
  const nearEd25519SigningKeyId = await computeAddSignerNearEd25519SigningKeyId({
    kind: 'wallet_add_signer_implicit_near_ed25519_key_v1',
    walletId: input.walletId,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    signerSlot: branch.signerSlot,
    participantIds,
    keyPurpose: branch.keyPurpose,
    keyVersion: branch.keyVersion,
    derivationVersion: branch.derivationVersion,
  });
  const parsed = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1({
    scope: {
      lifecycle_id: input.addSignerCeremonyId,
      root_share_epoch: input.signingRootVersion,
      account_id: String(input.walletId),
      threshold_session_id: input.addSignerCeremonyId,
      signer_set_id: registrationNearEd25519BranchKey(branch.signerSlot),
      signing_worker_id: input.signingWorkerId,
      material_activation: input.materialActivation,
    },
    application_binding: {
      wallet_id: String(input.walletId),
      near_ed25519_signing_key_id: nearEd25519SigningKeyId,
      signing_root_id: input.signingRootId,
      key_creation_signer_slot: branch.signerSlot,
    },
    participant_ids: participantIds,
  });
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}
