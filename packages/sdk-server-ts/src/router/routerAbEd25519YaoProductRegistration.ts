import {
  computeAddSignerNearEd25519SigningKeyId,
  computeRegistrationNearEd25519SigningKeyId,
  registrationEd25519AuthorityScopeFromAuthority,
  registrationNearEd25519BranchKey,
  type AddSignerIntentV1,
  type RegistrationAuthority,
  type RegistrationNearEd25519SignerPlan,
  type WalletId,
} from '@shared/utils/registrationIntent';
import {
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import type {
  RouterAbEd25519YaoActivationConsumerV1,
  RouterAbEd25519YaoActivationConsumptionRequestV1,
  RouterAbEd25519YaoActivationConsumptionResultV1,
} from './routerAbEd25519YaoRegistration';
import {
  createRouterAbEd25519YaoRegistrationModule,
  InMemoryRouterAbEd25519YaoRegistrationService,
  InMemoryRouterAbEd25519YaoRegistrationStateV1,
  type RouterAbEd25519YaoRegistrationBackend,
  type RouterAbEd25519YaoRegistrationAuthorizationAdapter,
  type RouterAbEd25519YaoRegistrationService,
} from './routerAbEd25519YaoRegistration';
import {
  InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter,
  InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationStateV1,
  type RouterAbEd25519YaoVerifiedActivationIntentV1,
  type RouterAbEd25519YaoRegistrationIntentBindingResult,
} from './routerAbEd25519YaoRegistrationIntentAuthorization';
import type { SessionAdapter } from './routerApi';
import { createRouterApiModule, type RouterApiModule } from './modules';
import { signRouterAbEd25519WalletSessionJwt } from './commonRouterUtils';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { deriveSigningRootId, type RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { WalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { WalletRegistrationEd25519YaoBootstrapSession } from '../core/registrationContracts';
import { thresholdEd25519AuthorityScopeFromWalletAuthAuthority } from '../core/ThresholdService/validation';
import {
  createRouterAbEd25519YaoRecoveryModule,
  InMemoryRouterAbEd25519YaoRecoveryService,
  InMemoryRouterAbEd25519YaoRecoveryStateV1,
  type RouterAbEd25519YaoActiveCapabilityLookupResultV1,
  type RouterAbEd25519YaoActiveCapabilityLookupV1,
  type RouterAbEd25519YaoActiveCapabilityResolverV1,
  type RouterAbEd25519YaoPersistedActiveCapabilityInstallerV1,
  type RouterAbEd25519YaoCapabilityPersistenceV1,
  type RouterAbEd25519YaoRecoveryBackend,
  type RouterAbEd25519YaoRecoveryAuthorizationAdapter,
  type RouterAbEd25519YaoRecoveryService,
  type RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1,
  type RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1,
  type RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallerV1,
} from './routerAbEd25519YaoRecovery';
import type { WalletEd25519YaoActiveCapabilityRecord } from '../core/WalletStore';
import { RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter } from './routerAbEd25519YaoRecoveryWalletSessionAuthorization';
import {
  createRouterAbEd25519YaoExportModule,
  InMemoryRouterAbEd25519YaoExportService,
  InMemoryRouterAbEd25519YaoExportStateV1,
  RouterAbEd25519YaoExportWalletSessionAuthorizationAdapter,
  type RouterAbEd25519YaoExportBackend,
  type RouterAbEd25519YaoExportAuthorizationAdapter,
  type RouterAbEd25519YaoExportService,
} from './routerAbEd25519YaoExport';
import type { RouterApiWebAuthnService } from './authServicePort';
import { isPlainObject } from '@shared/utils/validation';

const PRODUCT_WALLET_SESSION_TTL_MS = 10 * 60_000;
const PRODUCT_WALLET_SESSION_REMAINING_USES = 3;

export type RouterAbEd25519YaoWalletSessionMintResultV1 =
  | { readonly ok: true; readonly session: WalletRegistrationEd25519YaoBootstrapSession }
  | { readonly ok: false; readonly code: string; readonly message: string };

type RouterAbEd25519YaoWalletSessionMintIdentityV1 = {
  readonly walletId: WalletId;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly authority: WalletAuthAuthority;
  readonly thresholdSessionId: string;
  readonly participantIds: readonly [number, number];
  readonly runtimePolicyScope: RuntimePolicyScope;
};

export type RouterAbEd25519YaoWalletSessionMintInputV1 =
  | (RouterAbEd25519YaoWalletSessionMintIdentityV1 & {
      readonly kind: 'registration_wallet_session_v1';
      readonly signingGrantId?: never;
      readonly expiresAtMs?: never;
      readonly remainingUses?: never;
    })
  | (RouterAbEd25519YaoWalletSessionMintIdentityV1 & {
      readonly kind: 'shared_registration_wallet_session_v1';
      readonly signingGrantId: string;
      readonly expiresAtMs: number;
      readonly remainingUses: number;
    })
  | (RouterAbEd25519YaoWalletSessionMintIdentityV1 & {
      readonly kind: 'add_signer_wallet_session_v1';
      readonly signingGrantId?: never;
      readonly expiresAtMs?: never;
      readonly remainingUses?: never;
    })
  | (RouterAbEd25519YaoWalletSessionMintIdentityV1 & {
      readonly kind: 'shared_email_otp_recovery_wallet_session_v1';
      readonly signingGrantId?: never;
      readonly ttlMs?: never;
      readonly expiresAtMs?: never;
      readonly remainingUses: number;
    })
  | (RouterAbEd25519YaoWalletSessionMintIdentityV1 & {
      readonly kind: 'same_identity_budget_refresh_v1';
      readonly signingGrantId: string;
      readonly expiresAtMs: number;
      readonly remainingUses: number;
    });

export type RouterAbEd25519YaoProductRegistrationRuntimeV1 =
  RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallerV1 &
    RouterAbEd25519YaoPersistedActiveCapabilityInstallerV1 &
    RouterAbEd25519YaoActiveCapabilityResolverV1 & {
      readonly kind: 'router_ab_ed25519_yao_product_registration_runtime_v1';
      readonly signingWorkerId: string;
      bindVerifiedIntent(
        input: RouterAbEd25519YaoVerifiedActivationIntentV1,
      ): Promise<RouterAbEd25519YaoRegistrationIntentBindingResult>;
      consumeActivated(
        request: RouterAbEd25519YaoActivationConsumptionRequestV1,
      ): Promise<RouterAbEd25519YaoActivationConsumptionResultV1>;
      mintWalletSession(
        input: RouterAbEd25519YaoWalletSessionMintInputV1,
      ): Promise<RouterAbEd25519YaoWalletSessionMintResultV1>;
    };

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
  extends RouterAbEd25519YaoRegistrationService,
    RouterAbEd25519YaoActivationConsumerV1 {}

export interface RouterAbEd25519YaoProductRegistrationAuthorizationPortV1
  extends RouterAbEd25519YaoRegistrationAuthorizationAdapter {
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

const REGISTRATION_STATE_KINDS = new Set([
  'admitted',
  'executing',
  'activated',
  'failed',
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
const EXPORT_STATE_KINDS = new Set(['admitted', 'executing', 'completed', 'burned']);

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

function hasProductStateCollections(input: unknown): input is RouterAbEd25519YaoProductRegistrationStateV1 {
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
    Array.isArray(authorization.authorities) &&
    authorization.authorities.every(
      (authority) =>
        isPlainObject(authority) && INTENT_AUTHORITY_KINDS.has(String(authority.kind)),
    ) &&
    isStringMapWithStateKinds(recovery.capabilities, CAPABILITY_STATE_KINDS) &&
    isStringMap(recovery.identityCapabilities) &&
    isStringMapWithStateKinds(recovery.recoveries, RECOVERY_STATE_KINDS) &&
    isStringMap(recovery.recoverySessions) &&
    isStringMapWithStateKinds(exportState.exports, EXPORT_STATE_KINDS) &&
    isStringSet(exportState.authorizationNonces)
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
  return { ok: true, value: input };
}

export function createRouterAbEd25519YaoProductRegistrationStatefulCompositionV1(input: {
  readonly signingWorkerId: string;
  readonly backend: RouterAbEd25519YaoRegistrationBackend &
    RouterAbEd25519YaoRecoveryBackend &
    RouterAbEd25519YaoExportBackend;
  readonly session: SessionAdapter;
  readonly webAuthn: Pick<RouterApiWebAuthnService, 'verifyWebAuthnAuthenticationLite'>;
  readonly state: RouterAbEd25519YaoProductRegistrationStateV1;
  readonly capabilityPersistence: RouterAbEd25519YaoCapabilityPersistenceV1;
}): RouterAbEd25519YaoProductRegistrationCompositionV1 {
  const registrationService = new InMemoryRouterAbEd25519YaoRegistrationService(
    input.backend,
    input.state.registration,
  );
  const authorization = new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter(
    input.state.authorization,
  );
  const recoveryService = new InMemoryRouterAbEd25519YaoRecoveryService(
    input.backend,
    input.state.recovery,
    input.capabilityPersistence,
  );
  const recoveryAuthorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(
    input.session,
  );
  const exportService = new InMemoryRouterAbEd25519YaoExportService(
    input.backend,
    recoveryService,
    input.state.export,
  );
  const exportAuthorization = new RouterAbEd25519YaoExportWalletSessionAuthorizationAdapter(
    input.session,
    input.webAuthn,
  );
  return createRouterAbEd25519YaoProductRegistrationCompositionFromPortsV1({
    signingWorkerId: input.signingWorkerId,
    registrationService,
    authorization,
    recoveryService,
    recoveryAuthorization,
    exportService,
    exportAuthorization,
    session: input.session,
  });
}

export function createRouterAbEd25519YaoProductRegistrationCompositionFromPortsV1(
  input: RouterAbEd25519YaoProductRegistrationPortsV1,
): RouterAbEd25519YaoProductRegistrationCompositionV1 {
  const runtime = createRouterAbEd25519YaoProductRegistrationRuntimeV1({
    signingWorkerId: input.signingWorkerId,
    registrationService: input.registrationService,
    authorization: input.authorization,
    capabilityInstaller: input.recoveryService,
    session: input.session,
  });
  const registrationModule = createRouterAbEd25519YaoRegistrationModule({
    service: input.registrationService,
    authorization: input.authorization,
  });
  const recoveryModule = createRouterAbEd25519YaoRecoveryModule({
    service: input.recoveryService,
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
  readonly signingGrantId: string;
  readonly expiresAtMs: number;
  readonly remainingUses: number;
};

function assertNeverWalletSessionMintInput(value: never): never {
  throw new Error(`Unexpected Ed25519 Yao Wallet Session mint kind: ${String(value)}`);
}

function resolveRouterAbEd25519YaoWalletSessionTermsV1(
  input: RouterAbEd25519YaoWalletSessionMintInputV1,
): RouterAbEd25519YaoWalletSessionTermsV1 {
  switch (input.kind) {
    case 'registration_wallet_session_v1':
    case 'add_signer_wallet_session_v1':
      return {
        signingGrantId: `wss_${secureRandomBase64Url(24)}`,
        expiresAtMs: Date.now() + PRODUCT_WALLET_SESSION_TTL_MS,
        remainingUses: PRODUCT_WALLET_SESSION_REMAINING_USES,
      };
    case 'shared_email_otp_recovery_wallet_session_v1':
      return {
        signingGrantId: `wss_${secureRandomBase64Url(24)}`,
        expiresAtMs: Date.now() + PRODUCT_WALLET_SESSION_TTL_MS,
        remainingUses: Math.min(
          PRODUCT_WALLET_SESSION_REMAINING_USES,
          Math.max(1, Math.floor(input.remainingUses)),
        ),
      };
    case 'shared_registration_wallet_session_v1':
    case 'same_identity_budget_refresh_v1':
      return {
        signingGrantId: input.signingGrantId,
        expiresAtMs: input.expiresAtMs,
        remainingUses: input.remainingUses,
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
        RouterAbEd25519YaoPersistedActiveCapabilityInstallerV1 &
        RouterAbEd25519YaoActiveCapabilityResolverV1;
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

  async consumeActivated(
    request: RouterAbEd25519YaoActivationConsumptionRequestV1,
  ): Promise<RouterAbEd25519YaoActivationConsumptionResultV1> {
    const activationConsumer: RouterAbEd25519YaoActivationConsumerV1 =
      this.input.registrationService;
    return await activationConsumer.consumeActivated(request);
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
    return await this.input.capabilityInstaller.resolveActiveCapability(input);
  }

  async mintWalletSession(
    sessionInput: RouterAbEd25519YaoWalletSessionMintInputV1,
  ): Promise<RouterAbEd25519YaoWalletSessionMintResultV1> {
    const terms = resolveRouterAbEd25519YaoWalletSessionTermsV1(sessionInput);
    const signingRootId = deriveSigningRootId(sessionInput.runtimePolicyScope);
    const signingRootVersion = sessionInput.runtimePolicyScope.signingRootVersion;
    const routerAbNormalSigning = {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: this.signingWorkerId,
    } as const;
    const signed = await signRouterAbEd25519WalletSessionJwt({
      session: this.input.session,
      userId: sessionInput.walletId,
      relayerKeyId: this.signingWorkerId,
      authority: sessionInput.authority,
      sessionInfo: {
        sessionKind: 'jwt',
        walletId: sessionInput.walletId,
        nearAccountId: sessionInput.nearAccountId,
        nearEd25519SigningKeyId: sessionInput.nearEd25519SigningKeyId,
        thresholdSessionId: sessionInput.thresholdSessionId,
        signingGrantId: terms.signingGrantId,
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
        authorityScope: thresholdEd25519AuthorityScopeFromWalletAuthAuthority(
          sessionInput.authority,
        ),
        thresholdSessionId: signed.thresholdSessionId,
        signingGrantId: terms.signingGrantId,
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
}

export function createRouterAbEd25519YaoProductRegistrationRuntimeV1(input: {
  readonly signingWorkerId: string;
  readonly registrationService: RouterAbEd25519YaoProductRegistrationServicePortV1;
  readonly authorization: RouterAbEd25519YaoProductRegistrationAuthorizationPortV1;
  readonly capabilityInstaller: RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallerV1 &
    RouterAbEd25519YaoPersistedActiveCapabilityInstallerV1 &
    RouterAbEd25519YaoActiveCapabilityResolverV1;
  readonly session: SessionAdapter;
}): RouterAbEd25519YaoProductRegistrationRuntimeV1 {
  return new RouterAbEd25519YaoProductRegistrationRuntime(input);
}

export async function buildRouterAbEd25519YaoProductAdmissionRequestV1(input: {
  readonly registrationCeremonyId: string;
  readonly walletId: WalletId;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly authority: RegistrationAuthority;
  readonly branch: RegistrationNearEd25519SignerPlan;
  readonly signingWorkerId: string;
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
    authorityScope: registrationEd25519AuthorityScopeFromAuthority(input.authority),
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
      wallet_session_id: input.registrationCeremonyId,
      signer_set_id: input.branch.branchKey,
      signing_worker_id: input.signingWorkerId,
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
      wallet_session_id: input.addSignerCeremonyId,
      signer_set_id: registrationNearEd25519BranchKey(branch.signerSlot),
      signing_worker_id: input.signingWorkerId,
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
