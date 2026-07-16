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
} from './routerAbEd25519YaoExport';
import type { RouterApiWebAuthnService } from './authServicePort';

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
      ): RouterAbEd25519YaoActivationConsumptionResultV1;
      mintWalletSession(
        input: RouterAbEd25519YaoWalletSessionMintInputV1,
      ): Promise<RouterAbEd25519YaoWalletSessionMintResultV1>;
    };

export type RouterAbEd25519YaoProductRegistrationCompositionV1 = {
  readonly kind: 'router_ab_ed25519_yao_product_registration_composition_v1';
  readonly registrationService: InMemoryRouterAbEd25519YaoRegistrationService;
  readonly authorization: InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter;
  readonly recoveryService: InMemoryRouterAbEd25519YaoRecoveryService;
  readonly recoveryAuthorization: RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter;
  readonly exportService: InMemoryRouterAbEd25519YaoExportService;
  readonly exportAuthorization: RouterAbEd25519YaoExportWalletSessionAuthorizationAdapter;
  readonly runtime: RouterAbEd25519YaoProductRegistrationRuntimeV1;
  readonly module: RouterApiModule;
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

export function createRouterAbEd25519YaoProductRegistrationCompositionV1(input: {
  readonly signingWorkerId: string;
  readonly backend: RouterAbEd25519YaoRegistrationBackend &
    RouterAbEd25519YaoRecoveryBackend &
    RouterAbEd25519YaoExportBackend;
  readonly session: SessionAdapter;
  readonly webAuthn: Pick<RouterApiWebAuthnService, 'verifyWebAuthnAuthenticationLite'>;
  readonly state?: RouterAbEd25519YaoProductRegistrationStateV1;
  readonly capabilityPersistence?: RouterAbEd25519YaoCapabilityPersistenceV1;
}): RouterAbEd25519YaoProductRegistrationCompositionV1 {
  const state = input.state ?? createRouterAbEd25519YaoProductRegistrationStateV1();
  const registrationService = new InMemoryRouterAbEd25519YaoRegistrationService(
    input.backend,
    state.registration,
  );
  const authorization = new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter(
    state.authorization,
  );
  const recoveryService = new InMemoryRouterAbEd25519YaoRecoveryService(
    input.backend,
    state.recovery,
    input.capabilityPersistence,
  );
  const recoveryAuthorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(
    input.session,
  );
  const exportService = new InMemoryRouterAbEd25519YaoExportService(
    input.backend,
    recoveryService,
    state.export,
  );
  const exportAuthorization = new RouterAbEd25519YaoExportWalletSessionAuthorizationAdapter(
    input.session,
    input.webAuthn,
  );
  const runtime = createRouterAbEd25519YaoProductRegistrationRuntimeV1({
    signingWorkerId: input.signingWorkerId,
    registrationService,
    authorization,
    capabilityInstaller: recoveryService,
    session: input.session,
  });
  const registrationModule = createRouterAbEd25519YaoRegistrationModule({
    service: registrationService,
    authorization,
  });
  const recoveryModule = createRouterAbEd25519YaoRecoveryModule({
    service: recoveryService,
    authorization: recoveryAuthorization,
  });
  const exportModule = createRouterAbEd25519YaoExportModule({
    service: exportService,
    authorization: exportAuthorization,
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
    registrationService,
    authorization,
    recoveryService,
    recoveryAuthorization,
    exportService,
    exportAuthorization,
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
      readonly registrationService: InMemoryRouterAbEd25519YaoRegistrationService;
      readonly authorization: InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter;
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

  consumeActivated(
    request: RouterAbEd25519YaoActivationConsumptionRequestV1,
  ): RouterAbEd25519YaoActivationConsumptionResultV1 {
    const activationConsumer: RouterAbEd25519YaoActivationConsumerV1 =
      this.input.registrationService;
    return activationConsumer.consumeActivated(request);
  }

  installRegistrationFinalizeCapability(
    input: RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1,
  ): RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1 {
    return this.input.capabilityInstaller.installRegistrationFinalizeCapability(input);
  }

  installPersistedActiveCapability(
    input: WalletEd25519YaoActiveCapabilityRecord,
  ): RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1 {
    return this.input.capabilityInstaller.installPersistedActiveCapability(input);
  }

  resolveActiveCapability(
    input: RouterAbEd25519YaoActiveCapabilityLookupV1,
  ): RouterAbEd25519YaoActiveCapabilityLookupResultV1 {
    return this.input.capabilityInstaller.resolveActiveCapability(input);
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
  readonly registrationService: InMemoryRouterAbEd25519YaoRegistrationService;
  readonly authorization: InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter;
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
