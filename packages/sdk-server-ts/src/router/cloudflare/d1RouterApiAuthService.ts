import {
  D1WalletAuthMethodStore,
  type WalletAuthMethodStore,
} from '../../core/d1WalletAuthMethodStore';
import { D1WalletStore } from '../../core/d1WalletStore';
import { D1IdentityStore } from '../../core/d1IdentityStore';
import { D1EmailRecoveryPreparationStore } from '../../core/EmailRecoveryPreparationStore';
import { D1RecoverySessionStore } from '../../core/RecoverySessionStore';
import { D1WebAuthnAuthenticatorStore } from '../../core/WebAuthnAuthenticatorStore';
import { D1WebAuthnCredentialBindingStore } from '../../core/WebAuthnCredentialBindingStore';
import type { IdentityStore, LinkIdentityResult } from '../../core/IdentityStore';
import type { D1PreparedStatementLike } from '../../storage/tenantRoute';
import type {
  AccountCreationResult,
  FundImplicitNearAccountRequest,
  FundImplicitNearAccountResult,
} from '../../core/types';
import { EmailRecoveryAuthOperations } from '../../core/authService/emailRecoveryAuthOperations';
import type { RouterApiServiceBag } from '../authServicePort';
import type { RouterApiEmailRecoveryAuthService } from '../routerApi';
import { resolveRegistrationCeremonyDoConfig } from './d1RegistrationCeremonyDo';
import { CloudflareD1RegistrationCeremonyIntentStore } from './d1RegistrationCeremonyStore';
import { sha256BytesPortable } from './d1RouterApiAuthBoundary';
import { CloudflareD1NearPublicKeyStore } from './d1NearPublicKeyStore';
import { CloudflareD1WebAuthnStore } from './d1WebAuthnStore';
import { CloudflareD1EmailOtpChallengeStore } from './d1EmailOtpChallengeStore';
import { CloudflareD1EmailOtpDeliveryRuntime } from './d1EmailOtpDeliveryRuntime';
import { CloudflareD1EmailOtpEnrollmentStore } from './d1EmailOtpEnrollmentStore';
import { CloudflareD1EmailOtpGrantStore } from './d1EmailOtpGrantStore';
import { CloudflareD1EmailOtpRateLimitStore } from './d1EmailOtpRateLimitStore';
import { CloudflareD1EmailOtpRecoveryEscrowStore } from './d1EmailOtpRecoveryEscrowStore';
import { CloudflareD1EmailOtpServerSealRuntime } from './d1EmailOtpServerSealRuntime';
import { CloudflareD1EmailOtpRegistrationEnrollmentFinalizer } from './d1EmailOtpRegistrationEnrollmentFinalizer';
import { CloudflareD1EmailOtpChallengeVerifier } from './d1EmailOtpChallengeVerifier';
import { CloudflareD1EmailOtpChallengeIssuer } from './d1EmailOtpChallengeIssuer';
import { CloudflareD1EmailOtpChallengeService } from './d1EmailOtpChallengeService';
import { CloudflareD1EmailOtpRecoveryService } from './d1EmailOtpRecoveryService';
import { CloudflareD1RouterAbSigningRuntime } from './d1RouterAbSigningRuntime';
import { CloudflareD1GoogleEmailOtpRegistrationAttemptStore } from './d1GoogleEmailOtpRegistrationAttemptStore';
import { CloudflareD1GoogleEmailOtpSessionResolver } from './d1GoogleEmailOtpSessionResolver';
import { CloudflareD1SessionStore } from './d1SessionStore';
import { CloudflareD1SessionService } from './d1SessionService';
import { CloudflareD1IdentityService } from './d1IdentityService';
import { CloudflareD1OidcVerificationService } from './d1OidcVerificationService';
import { CloudflareD1WebAuthnAuthService } from './d1WebAuthnAuthService';
import { CloudflareD1WalletAuthMethodService } from './d1WalletAuthMethodService';
import { CloudflareD1WalletRegistrationService } from './d1WalletRegistrationService';
import { CloudflareD1WalletRegistrationCommitStore } from './d1WalletRegistrationCommitStore';
import { CloudflareD1WalletAddSignerService } from './d1WalletAddSignerService';
import { CloudflareD1RegistrationIntentService } from './d1RegistrationIntentService';
import {
  createNamedNearAccountWithRelayer,
  fundImplicitNearAccountWithRelayer,
} from '../../core/nearRelayerAccountProvisioning';
import {
  normalizeD1RouterApiAuthOptions,
  type CloudflareD1RouterApiAuthServiceOptions,
  type NormalizedCloudflareD1RouterApiAuthServiceOptions,
} from './d1RouterApiAuthConfig';

export type {
  CloudflareD1EmailOtpDeliveryProvider,
  CloudflareD1EmailOtpDeliveryProviderInput,
  CloudflareD1EmailOtpDeliveryProviderResult,
  CloudflareD1EmailOtpServerSealConfig,
  CloudflareD1RouterApiAuthServiceOptions,
} from './d1RouterApiAuthConfig';

export type CloudflareD1RouterApiAuthService = Omit<RouterApiServiceBag, 'thresholdRuntime'> & {
  readonly thresholdRuntime: RouterApiServiceBag['thresholdRuntime'] &
    Pick<CloudflareD1RouterAbSigningRuntime, 'getRouterAbLocalSigningSeedRuntime'>;
};

type ScopedD1Prepare = (sql: string, values: readonly unknown[]) => D1PreparedStatementLike;

type D1IdentityLinkInput = {
  readonly userId: string;
  readonly subject: string;
  readonly allowMoveIfSoleIdentity?: boolean;
};

type SponsoredNamedNearAccountInput = {
  readonly accountId: string;
  readonly publicKey: string;
};

type CloudflareD1RouterApiLazyStoreState = {
  readonly options: NormalizedCloudflareD1RouterApiAuthServiceOptions;
  walletStore: D1WalletStore | null;
  walletAuthMethodStore: WalletAuthMethodStore | null;
  registrationCeremonyIntentStore: CloudflareD1RegistrationCeremonyIntentStore | null;
};

type CloudflareD1RouterApiAuthAssembly = {
  readonly options: NormalizedCloudflareD1RouterApiAuthServiceOptions;
  readonly emailOtpServerSeal: CloudflareD1EmailOtpServerSealRuntime;
  readonly emailOtpChallengeService: CloudflareD1EmailOtpChallengeService;
  readonly emailOtpRecoveryService: CloudflareD1EmailOtpRecoveryService;
  readonly identityService: CloudflareD1IdentityService;
  readonly oidcVerification: CloudflareD1OidcVerificationService;
  readonly sessionService: CloudflareD1SessionService;
  readonly googleEmailOtpSessions: CloudflareD1GoogleEmailOtpSessionResolver;
  readonly nearPublicKeys: CloudflareD1NearPublicKeyStore;
  readonly webAuthnAuthService: CloudflareD1WebAuthnAuthService;
  readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;
  readonly walletRegistrations: CloudflareD1WalletRegistrationService;
  readonly walletAddSigners: CloudflareD1WalletAddSignerService;
  readonly registrationIntents: CloudflareD1RegistrationIntentService;
  readonly routerAbSigning: CloudflareD1RouterAbSigningRuntime;
};

type D1WalletRegistrationRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'registrationIntents' | 'walletRegistrations'
>;

type D1WalletAuthMethodRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'registrationIntents' | 'walletAuthMethods' | 'walletAddSigners'
>;

type D1WalletUnlockRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'emailOtpRecoveryService' | 'webAuthnAuthService'
>;

type D1EmailOtpRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  | 'emailOtpServerSeal'
  | 'emailOtpChallengeService'
  | 'emailOtpRecoveryService'
  | 'googleEmailOtpSessions'
  | 'oidcVerification'
>;

type D1WebAuthnRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'webAuthnAuthService'
>;

type D1IdentityRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'googleEmailOtpSessions' | 'identityService' | 'oidcVerification'
>;

type D1SessionVersionRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'sessionService'
>;

type D1ThresholdRuntimeRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'routerAbSigning'
>;

type D1NearFundingRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'nearPublicKeys' | 'options'
>;

type D1RecoveryRouteServiceAssembly = Pick<CloudflareD1RouterApiAuthAssembly, 'sessionService'>;

type D1EmailRecoveryAuthServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'options' | 'routerAbSigning'
>;

type D1RouterAccountRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'routerAbSigning'
>;

function d1RouterApiErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

async function linkD1Identity(
  identityStore: IdentityStore,
  input: D1IdentityLinkInput,
): Promise<LinkIdentityResult> {
  try {
    return await identityStore.linkSubjectToUserId(input);
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: d1RouterApiErrorMessage(error) || 'Failed to link identity',
    };
  }
}

function createLazyStoreState(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
): CloudflareD1RouterApiLazyStoreState {
  return {
    options,
    walletStore: null,
    walletAuthMethodStore: null,
    registrationCeremonyIntentStore: null,
  };
}

function getRegistrationCeremonyIntentStoreForState(
  state: CloudflareD1RouterApiLazyStoreState,
): CloudflareD1RegistrationCeremonyIntentStore | null {
  if (state.registrationCeremonyIntentStore) return state.registrationCeremonyIntentStore;
  const config = resolveRegistrationCeremonyDoConfig(state.options.thresholdStore);
  if (!config) return null;
  state.registrationCeremonyIntentStore = new CloudflareD1RegistrationCeremonyIntentStore(config);
  return state.registrationCeremonyIntentStore;
}

function getWalletAuthMethodStoreForState(
  state: CloudflareD1RouterApiLazyStoreState,
): WalletAuthMethodStore {
  if (state.walletAuthMethodStore) return state.walletAuthMethodStore;
  state.walletAuthMethodStore = new D1WalletAuthMethodStore({
    database: state.options.database,
    namespace: state.options.namespace,
    orgId: state.options.orgId,
    projectId: state.options.projectId,
    envId: state.options.envId,
    ensureSchema: false,
  });
  return state.walletAuthMethodStore;
}

function getWalletStoreForState(state: CloudflareD1RouterApiLazyStoreState): D1WalletStore {
  if (state.walletStore) return state.walletStore;
  state.walletStore = new D1WalletStore({
    database: state.options.database,
    namespace: state.options.namespace,
    orgId: state.options.orgId,
    projectId: state.options.projectId,
    envId: state.options.envId,
    ensureSchema: false,
  });
  return state.walletStore;
}

function scopePrepareForOptions(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
  sql: string,
  values: readonly unknown[],
): D1PreparedStatementLike {
  return options.database.prepare(sql).bind(...scopeValuesForOptions(options, values));
}

function scopeValuesForOptions(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
  values: readonly unknown[],
): readonly unknown[] {
  return [options.namespace, options.orgId, options.projectId, options.envId, ...values];
}

async function ensureD1EmailRecoverySignerRuntimeReady(): Promise<void> {}

class CloudflareD1EmailRecoveryAuthService implements RouterApiEmailRecoveryAuthService {
  private readonly operations: EmailRecoveryAuthOperations;

  constructor(assembly: D1EmailRecoveryAuthServiceAssembly) {
    const options = assembly.options;
    this.operations = new EmailRecoveryAuthOperations({
      ensureSignerAndRelayerAccount: ensureD1EmailRecoverySignerRuntimeReady,
      getRouterAbEcdsaBootstrapExportRuntime:
        assembly.routerAbSigning.getRouterAbEcdsaBootstrapExportRuntime.bind(
          assembly.routerAbSigning,
        ),
      getDefaultRuntimePolicyScope: () => ({
        orgId: options.orgId,
        projectId: options.projectId,
        envId: options.envId,
        signingRootVersion: 'default',
      }),
      webAuthnAuthenticatorStore: new D1WebAuthnAuthenticatorStore({
        database: options.database,
        namespace: options.namespace,
        orgId: options.orgId,
        projectId: options.projectId,
        envId: options.envId,
        ensureSchema: false,
      }),
      webAuthnCredentialBindingStore: new D1WebAuthnCredentialBindingStore({
        database: options.database,
        namespace: options.namespace,
        orgId: options.orgId,
        projectId: options.projectId,
        envId: options.envId,
        ensureSchema: false,
      }),
      emailRecoveryPreparationStore: new D1EmailRecoveryPreparationStore({
        database: options.database,
        namespace: options.namespace,
        orgId: options.orgId,
        projectId: options.projectId,
        envId: options.envId,
        ensureSchema: false,
      }),
      recoverySessionStore: new D1RecoverySessionStore({
        database: options.database,
        namespace: options.namespace,
        orgId: options.orgId,
        projectId: options.projectId,
        envId: options.envId,
        ensureSchema: false,
      }),
    });
  }

  async prepareEmailRecovery(
    request: Parameters<RouterApiEmailRecoveryAuthService['prepareEmailRecovery']>[0],
  ): ReturnType<RouterApiEmailRecoveryAuthService['prepareEmailRecovery']> {
    return await this.operations.prepareEmailRecovery(request);
  }

  async respondEmailRecoveryEcdsa(
    request: Parameters<RouterApiEmailRecoveryAuthService['respondEmailRecoveryEcdsa']>[0],
  ): ReturnType<RouterApiEmailRecoveryAuthService['respondEmailRecoveryEcdsa']> {
    return await this.operations.respondEmailRecoveryEcdsa(request);
  }
}

async function fundImplicitNearAccountForOptions(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
  input: FundImplicitNearAccountRequest,
): Promise<FundImplicitNearAccountResult> {
  if (!options.implicitNearAccountTestFundingEnabled) {
    return {
      ok: false,
      code: 'not_configured',
      message: 'Implicit NEAR account test funding is not enabled on this server',
    };
  }
  const relayerAccount = options.relayerAccount;
  const relayerPrivateKey = options.relayerPrivateKey;
  const nearRpcUrl = options.nearRpcUrl;
  const fundedAmountYocto = options.accountInitialBalance;
  if (!relayerAccount || !relayerPrivateKey || !nearRpcUrl || !fundedAmountYocto) {
    return {
      ok: false,
      code: 'not_configured',
      message: 'Implicit NEAR account funding is not configured on this server',
    };
  }
  return await fundImplicitNearAccountWithRelayer({
    ...input,
    relayerAccount,
    relayerPrivateKey,
    relayerPublicKey: options.relayerPublicKey,
    nearRpcUrl,
    fundedAmountYocto,
  });
}

async function createSponsoredNamedNearAccountForOptions(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
  input: SponsoredNamedNearAccountInput,
): Promise<AccountCreationResult> {
  const relayerAccount = options.relayerAccount;
  const relayerPrivateKey = options.relayerPrivateKey;
  const nearRpcUrl = options.nearRpcUrl;
  const initialBalanceYocto = options.accountInitialBalance;
  if (!relayerAccount || !relayerPrivateKey || !nearRpcUrl || !initialBalanceYocto) {
    return {
      success: false,
      error: 'Sponsored NEAR account creation is not configured on this server',
      message: 'Sponsored NEAR account creation is not configured on this server',
    };
  }
  return await createNamedNearAccountWithRelayer({
    ...input,
    relayerAccount,
    relayerPrivateKey,
    relayerPublicKey: options.relayerPublicKey,
    nearRpcUrl,
    initialBalanceYocto,
  });
}

function createCloudflareD1RouterApiAuthAssembly(
  input: CloudflareD1RouterApiAuthServiceOptions,
): CloudflareD1RouterApiAuthAssembly {
  const options = normalizeD1RouterApiAuthOptions(input);
  const prepare: ScopedD1Prepare = scopePrepareForOptions.bind(undefined, options);
  const lazyStores = createLazyStoreState(options);
  const getRegistrationCeremonyIntentStore = getRegistrationCeremonyIntentStoreForState.bind(
    undefined,
    lazyStores,
  );
  const getWalletAuthMethodStore = getWalletAuthMethodStoreForState.bind(undefined, lazyStores);
  const getWalletStore = getWalletStoreForState.bind(undefined, lazyStores);
  const createSponsoredNamedNearAccount = createSponsoredNamedNearAccountForOptions.bind(
    undefined,
    options,
  );

  const identityStore = new D1IdentityStore({
    database: options.database,
    namespace: options.namespace,
    orgId: options.orgId,
    projectId: options.projectId,
    envId: options.envId,
    ensureSchema: false,
  });
  const linkIdentity = linkD1Identity.bind(undefined, identityStore);
  const sessionStore = new CloudflareD1SessionStore({ prepare });
  const sessionService = new CloudflareD1SessionService({ sessionStore });
  const googleEmailOtpRegistrationAttempts = new CloudflareD1GoogleEmailOtpRegistrationAttemptStore(
    {
      prepare,
      orgId: options.orgId,
    },
  );
  const nearPublicKeys = new CloudflareD1NearPublicKeyStore({ prepare });
  const webAuthnStore = new CloudflareD1WebAuthnStore({
    database: options.database,
    namespace: options.namespace,
    orgId: options.orgId,
    projectId: options.projectId,
    envId: options.envId,
  });
  const webAuthnAuthService = new CloudflareD1WebAuthnAuthService({ webAuthnStore });
  const emailOtpChallenges = new CloudflareD1EmailOtpChallengeStore({
    database: options.database,
    namespace: options.namespace,
    orgId: options.orgId,
    projectId: options.projectId,
    envId: options.envId,
  });
  const emailOtpDelivery = new CloudflareD1EmailOtpDeliveryRuntime(options.emailOtp);
  const emailOtpEnrollments = new CloudflareD1EmailOtpEnrollmentStore({ prepare });
  const emailOtpGrants = new CloudflareD1EmailOtpGrantStore({ prepare });
  const emailOtpRateLimits = new CloudflareD1EmailOtpRateLimitStore({
    prepare,
    rateLimits: options.emailOtp.rateLimits,
  });
  const emailOtpRecoveryEscrows = new CloudflareD1EmailOtpRecoveryEscrowStore({
    database: options.database,
    namespace: options.namespace,
    orgId: options.orgId,
    projectId: options.projectId,
    envId: options.envId,
  });
  const emailOtpServerSeal = new CloudflareD1EmailOtpServerSealRuntime(options.emailOtpServerSeal);
  const googleEmailOtpSessions = new CloudflareD1GoogleEmailOtpSessionResolver({
    emailOtpEnrollments,
    emailOtpRateLimits,
    identityStore,
    linkIdentity,
    production: options.emailOtp.production,
    registrationAttempts: googleEmailOtpRegistrationAttempts,
  });
  const identityService = new CloudflareD1IdentityService({
    accountIdDerivationSecret: options.accountIdDerivationSecret,
    identityStore,
    relayerAccount: options.relayerAccount,
    resolveGoogleEmailOtpSession: googleEmailOtpSessions.resolve.bind(googleEmailOtpSessions),
  });
  const oidcVerification = new CloudflareD1OidcVerificationService({
    googleOidcClientId: options.googleOidcClientId,
    identityStore,
    linkIdentity,
    oidcExchange: options.oidcExchange,
  });
  const emailOtpRegistrationEnrollmentFinalizer =
    new CloudflareD1EmailOtpRegistrationEnrollmentFinalizer({
      emailOtpEnrollments,
      emailOtpRecoveryEscrows,
      googleEmailOtpSessions,
    });
  const emailOtpChallengeVerifier = new CloudflareD1EmailOtpChallengeVerifier({
    emailOtpChallenges,
    emailOtpEnrollments,
    emailOtpRateLimits,
    lockoutTtlMs: options.emailOtp.lockoutTtlMs,
  });
  const walletAuthMethods = new CloudflareD1WalletAuthMethodService({
    emailOtpChallengeVerifier,
    getRegistrationCeremonyIntentStore,
    getWalletAuthMethodStore,
    googleEmailOtpRegistrationAttempts,
    sha256Bytes: sha256BytesPortable,
    webAuthnStore,
  });
  const walletRegistrationCommitStore = new CloudflareD1WalletRegistrationCommitStore({
    database: options.database,
    namespace: options.namespace,
    orgId: options.orgId,
    projectId: options.projectId,
    envId: options.envId,
  });
  const routerAbSigning = new CloudflareD1RouterAbSigningRuntime({
    relayerAccount: options.relayerAccount,
    relayerPublicKey: options.relayerPublicKey,
    routerAbSigningRuntimes: options.routerAbSigningRuntimes,
    thresholdStore: options.thresholdStore,
    auth: {
      verifyWebAuthnAuthenticationLite:
        webAuthnAuthService.verifyWebAuthnAuthenticationLite.bind(webAuthnAuthService),
    },
  });
  const walletRegistrations = new CloudflareD1WalletRegistrationService({
    createSponsoredNamedNearAccount,
    emailOtpRegistrationEnrollmentFinalizer,
    getRegistrationCeremonyIntentStore,
    getEd25519YaoProductRegistration: () => options.ed25519YaoProductRegistration || null,
    getRouterAbNormalSigningRuntime:
      routerAbSigning.getRouterAbNormalSigningRuntime.bind(routerAbSigning),
    getRouterAbEcdsaBootstrapExportRuntime:
      routerAbSigning.getRouterAbEcdsaBootstrapExportRuntime.bind(routerAbSigning),
    getWalletStore,
    walletRegistrationCommitStore,
    walletAuthMethods,
  });
  const walletAddSigners = new CloudflareD1WalletAddSignerService({
    getRegistrationCeremonyIntentStore,
    getEd25519YaoProductRegistration: () => options.ed25519YaoProductRegistration || null,
    getRouterAbNormalSigningRuntime:
      routerAbSigning.getRouterAbNormalSigningRuntime.bind(routerAbSigning),
    getRouterAbEcdsaBootstrapExportRuntime:
      routerAbSigning.getRouterAbEcdsaBootstrapExportRuntime.bind(routerAbSigning),
    getWalletStore,
    walletAuthMethods,
  });
  const registrationIntents = new CloudflareD1RegistrationIntentService({
    getRegistrationCeremonyIntentStore,
    signerWallets: emailOtpEnrollments,
  });
  const emailOtpChallengeIssuer = new CloudflareD1EmailOtpChallengeIssuer({
    config: {
      challengeTtlMs: options.emailOtp.challengeTtlMs,
      codeLength: options.emailOtp.codeLength,
      deliveryMode: options.emailOtp.deliveryMode,
      maxActiveChallengesPerContext: options.emailOtp.maxActiveChallengesPerContext,
      maxAttempts: options.emailOtp.maxAttempts,
    },
    emailOtpChallenges,
    emailOtpDelivery,
    emailOtpEnrollments,
    emailOtpRateLimits,
  });
  const emailOtpChallengeService = new CloudflareD1EmailOtpChallengeService({
    challenges: emailOtpChallenges,
    devOutboxEnabled: options.emailOtp.devOutboxEnabled,
    finalizer: emailOtpRegistrationEnrollmentFinalizer,
    grantTtlMs: options.emailOtp.grantTtlMs,
    grants: emailOtpGrants,
    issuer: emailOtpChallengeIssuer,
    registrationAttempts: googleEmailOtpRegistrationAttempts,
    verifier: emailOtpChallengeVerifier,
  });
  const emailOtpRecoveryService = new CloudflareD1EmailOtpRecoveryService({
    challengeVerifier: emailOtpChallengeVerifier,
    emailOtpChallenges,
    emailOtpEnrollments,
    emailOtpGrants,
    emailOtpRateLimits,
    emailOtpRecoveryEscrows,
    grantTtlMs: options.emailOtp.grantTtlMs,
    sha256Bytes: sha256BytesPortable,
  });

  return {
    options,
    emailOtpServerSeal,
    emailOtpChallengeService,
    emailOtpRecoveryService,
    identityService,
    oidcVerification,
    sessionService,
    googleEmailOtpSessions,
    nearPublicKeys,
    webAuthnAuthService,
    walletAuthMethods,
    walletRegistrations,
    walletAddSigners,
    registrationIntents,
    routerAbSigning,
  };
}

function createD1WalletRegistrationRouteService(
  assembly: D1WalletRegistrationRouteServiceAssembly,
): RouterApiServiceBag['walletRegistration'] {
  return {
    createRegistrationIntent: assembly.registrationIntents.createRegistrationIntent.bind(
      assembly.registrationIntents,
    ),
    cancelRegistrationIntent: assembly.registrationIntents.cancelRegistrationIntent.bind(
      assembly.registrationIntents,
    ),
    startWalletRegistration: assembly.walletRegistrations.startWalletRegistration.bind(
      assembly.walletRegistrations,
    ),
    respondWalletRegistrationEcdsaDerivation: assembly.walletRegistrations.respondWalletRegistrationEcdsaDerivation.bind(
      assembly.walletRegistrations,
    ),
    finalizeWalletRegistration: assembly.walletRegistrations.finalizeWalletRegistration.bind(
      assembly.walletRegistrations,
    ),
    refreshEd25519YaoWalletSession:
      assembly.walletRegistrations.refreshEd25519YaoWalletSession.bind(
        assembly.walletRegistrations,
      ),
    recoverEd25519YaoEmailOtpWalletSession:
      assembly.walletRegistrations.recoverEd25519YaoEmailOtpWalletSession.bind(
        assembly.walletRegistrations,
      ),
  };
}

function createD1WalletAuthMethodRouteService(
  assembly: D1WalletAuthMethodRouteServiceAssembly,
): RouterApiServiceBag['walletAuthMethods'] {
  return {
    createAddAuthMethodIntent: assembly.registrationIntents.createAddAuthMethodIntent.bind(
      assembly.registrationIntents,
    ),
    createAddSignerIntent: assembly.registrationIntents.createAddSignerIntent.bind(
      assembly.registrationIntents,
    ),
    finalizeWalletAddAuthMethod: assembly.walletAuthMethods.finalizeWalletAddAuthMethod.bind(
      assembly.walletAuthMethods,
    ),
    finalizeWalletAddSigner: assembly.walletAddSigners.finalizeWalletAddSigner.bind(
      assembly.walletAddSigners,
    ),
    respondWalletAddSignerEcdsaDerivation: assembly.walletAddSigners.respondWalletAddSignerEcdsaDerivation.bind(
      assembly.walletAddSigners,
    ),
    revokeWalletAuthMethod: assembly.walletAuthMethods.revokeWalletAuthMethod.bind(
      assembly.walletAuthMethods,
    ),
    startWalletAddAuthMethod: assembly.walletAuthMethods.startWalletAddAuthMethod.bind(
      assembly.walletAuthMethods,
    ),
    startWalletAddSigner: assembly.walletAddSigners.startWalletAddSigner.bind(
      assembly.walletAddSigners,
    ),
  };
}

function createD1WalletUnlockRouteService(
  assembly: D1WalletUnlockRouteServiceAssembly,
): RouterApiServiceBag['walletUnlock'] {
  return {
    createEmailOtpUnlockChallenge:
      assembly.emailOtpRecoveryService.createEmailOtpUnlockChallenge.bind(
        assembly.emailOtpRecoveryService,
      ),
    createWebAuthnLoginOptions: assembly.webAuthnAuthService.createWebAuthnLoginOptions.bind(
      assembly.webAuthnAuthService,
    ),
    markEmailOtpStrongAuthSatisfied:
      assembly.emailOtpRecoveryService.markEmailOtpStrongAuthSatisfied.bind(
        assembly.emailOtpRecoveryService,
      ),
    verifyEmailOtpUnlockProof: assembly.emailOtpRecoveryService.verifyEmailOtpUnlockProof.bind(
      assembly.emailOtpRecoveryService,
    ),
    verifyWebAuthnLogin: assembly.webAuthnAuthService.verifyWebAuthnLogin.bind(
      assembly.webAuthnAuthService,
    ),
  };
}

function createD1EmailOtpRouteService(
  assembly: D1EmailOtpRouteServiceAssembly,
): RouterApiServiceBag['emailOtp'] {
  return {
    applyEmailOtpServerSeal: assembly.emailOtpServerSeal.applyEmailOtpServerSeal.bind(
      assembly.emailOtpServerSeal,
    ),
    cleanupGoogleEmailOtpDevRegistrationState:
      assembly.googleEmailOtpSessions.cleanupDevRegistrationState.bind(
        assembly.googleEmailOtpSessions,
      ),
    consumeEmailOtpGrant: assembly.emailOtpRecoveryService.consumeEmailOtpGrant.bind(
      assembly.emailOtpRecoveryService,
    ),
    consumeEmailOtpRecoveryKey: assembly.emailOtpRecoveryService.consumeEmailOtpRecoveryKey.bind(
      assembly.emailOtpRecoveryService,
    ),
    createEmailOtpChallenge: assembly.emailOtpChallengeService.createEmailOtpChallenge.bind(
      assembly.emailOtpChallengeService,
    ),
    createEmailOtpDeviceRecoveryChallenge:
      assembly.emailOtpChallengeService.createEmailOtpDeviceRecoveryChallenge.bind(
        assembly.emailOtpChallengeService,
      ),
    createEmailOtpEnrollmentChallenge:
      assembly.emailOtpChallengeService.createEmailOtpEnrollmentChallenge.bind(
        assembly.emailOtpChallengeService,
      ),
    getEmailOtpRecoveryCodeStatus:
      assembly.emailOtpRecoveryService.getEmailOtpRecoveryCodeStatus.bind(
        assembly.emailOtpRecoveryService,
      ),
    isEmailOtpStrongAuthRequired:
      assembly.emailOtpRecoveryService.isEmailOtpStrongAuthRequired.bind(
        assembly.emailOtpRecoveryService,
      ),
    markEmailOtpStrongAuthSatisfied:
      assembly.emailOtpRecoveryService.markEmailOtpStrongAuthSatisfied.bind(
        assembly.emailOtpRecoveryService,
      ),
    readActiveEmailOtpEnrollment:
      assembly.emailOtpRecoveryService.readActiveEmailOtpEnrollment.bind(
        assembly.emailOtpRecoveryService,
      ),
    readEmailOtpEnrollment: assembly.emailOtpRecoveryService.readEmailOtpEnrollment.bind(
      assembly.emailOtpRecoveryService,
    ),
    readEmailOtpOutboxEntry: assembly.emailOtpChallengeService.readEmailOtpOutboxEntry.bind(
      assembly.emailOtpChallengeService,
    ),
    recordEmailOtpRecoveryKeyAttemptFailure:
      assembly.emailOtpRecoveryService.recordEmailOtpRecoveryKeyAttemptFailure.bind(
        assembly.emailOtpRecoveryService,
      ),
    removeEmailOtpServerSeal: assembly.emailOtpServerSeal.removeEmailOtpServerSeal.bind(
      assembly.emailOtpServerSeal,
    ),
    rotateEmailOtpRecoveryKeys: assembly.emailOtpRecoveryService.rotateEmailOtpRecoveryKeys.bind(
      assembly.emailOtpRecoveryService,
    ),
    validateGoogleEmailOtpRegistrationCandidateWallet:
      assembly.googleEmailOtpSessions.validateRegistrationCandidateWallet.bind(
        assembly.googleEmailOtpSessions,
      ),
    verifyEmailOtpChallenge: assembly.emailOtpChallengeService.verifyEmailOtpChallenge.bind(
      assembly.emailOtpChallengeService,
    ),
    verifyEmailOtpDeviceRecoveryChallenge:
      assembly.emailOtpRecoveryService.verifyEmailOtpDeviceRecoveryChallenge.bind(
        assembly.emailOtpRecoveryService,
      ),
    verifyEmailOtpEnrollment: assembly.emailOtpChallengeService.verifyEmailOtpEnrollment.bind(
      assembly.emailOtpChallengeService,
    ),
    verifyGoogleLogin: assembly.oidcVerification.verifyGoogleLogin.bind(assembly.oidcVerification),
  };
}

function createD1WebAuthnRouteService(
  assembly: D1WebAuthnRouteServiceAssembly,
): RouterApiServiceBag['webAuthn'] {
  return {
    createWebAuthnLoginOptions: assembly.webAuthnAuthService.createWebAuthnLoginOptions.bind(
      assembly.webAuthnAuthService,
    ),
    createWebAuthnSyncAccountOptions:
      assembly.webAuthnAuthService.createWebAuthnSyncAccountOptions.bind(
        assembly.webAuthnAuthService,
      ),
    listWebAuthnAuthenticatorsForUser:
      assembly.webAuthnAuthService.listWebAuthnAuthenticatorsForUser.bind(
        assembly.webAuthnAuthService,
      ),
    verifyWebAuthnAuthenticationLite:
      assembly.webAuthnAuthService.verifyWebAuthnAuthenticationLite.bind(
        assembly.webAuthnAuthService,
      ),
    verifyWebAuthnLogin: assembly.webAuthnAuthService.verifyWebAuthnLogin.bind(
      assembly.webAuthnAuthService,
    ),
    verifyWebAuthnSyncAccount: assembly.webAuthnAuthService.verifyWebAuthnSyncAccount.bind(
      assembly.webAuthnAuthService,
    ),
  };
}

function createD1IdentityRouteService(
  assembly: D1IdentityRouteServiceAssembly,
): RouterApiServiceBag['identity'] {
  return {
    consumeGoogleEmailOtpRegistrationAttemptRateLimit:
      assembly.googleEmailOtpSessions.consumeRegistrationAttemptRateLimit.bind(
        assembly.googleEmailOtpSessions,
      ),
    getGoogleOidcPublicConfig: assembly.oidcVerification.getGoogleOidcPublicConfig.bind(
      assembly.oidcVerification,
    ),
    linkIdentity: assembly.identityService.linkIdentity.bind(assembly.identityService),
    listIdentities: assembly.identityService.listIdentities.bind(assembly.identityService),
    resolveGoogleEmailOtpSession: assembly.googleEmailOtpSessions.resolve.bind(
      assembly.googleEmailOtpSessions,
    ),
    resolveOidcWalletId: assembly.identityService.resolveOidcWalletId.bind(
      assembly.identityService,
    ),
    unlinkIdentity: assembly.identityService.unlinkIdentity.bind(assembly.identityService),
    verifyGoogleLogin: assembly.oidcVerification.verifyGoogleLogin.bind(assembly.oidcVerification),
    verifyOidcJwtExchange: assembly.oidcVerification.verifyOidcJwtExchange.bind(
      assembly.oidcVerification,
    ),
  };
}

function createD1SessionVersionRouteService(
  assembly: D1SessionVersionRouteServiceAssembly,
): RouterApiServiceBag['sessionVersions'] {
  return {
    getOrCreateAppSessionVersion: assembly.sessionService.getOrCreateAppSessionVersion.bind(
      assembly.sessionService,
    ),
    rotateAppSessionVersion: assembly.sessionService.rotateAppSessionVersion.bind(
      assembly.sessionService,
    ),
    validateAppSessionVersion: assembly.sessionService.validateAppSessionVersion.bind(
      assembly.sessionService,
    ),
  };
}

function createD1ThresholdRuntimeRouteService(
  assembly: D1ThresholdRuntimeRouteServiceAssembly,
): CloudflareD1RouterApiAuthService['thresholdRuntime'] {
  return {
    ecdsaDerivationRoleLocalBootstrap: assembly.routerAbSigning.ecdsaDerivationRoleLocalBootstrap.bind(
      assembly.routerAbSigning,
    ),
    ecdsaDerivationRoleLocalExportShare: assembly.routerAbSigning.ecdsaDerivationRoleLocalExportShare.bind(
      assembly.routerAbSigning,
    ),
    getRouterAbNormalSigningRuntime: assembly.routerAbSigning.getRouterAbNormalSigningRuntime.bind(
      assembly.routerAbSigning,
    ),
    getRouterAbEcdsaBootstrapExportRuntime:
      assembly.routerAbSigning.getRouterAbEcdsaBootstrapExportRuntime.bind(
        assembly.routerAbSigning,
      ),
    getRouterAbEcdsaPresignRuntime:
      assembly.routerAbSigning.getRouterAbEcdsaPresignRuntime.bind(assembly.routerAbSigning),
    getRouterAbLocalSigningSeedRuntime:
      assembly.routerAbSigning.getRouterAbLocalSigningSeedRuntime.bind(assembly.routerAbSigning),
    listThresholdEcdsaKeyIdentityTargetsForUser:
      assembly.routerAbSigning.listThresholdEcdsaKeyIdentityTargetsForUser.bind(
        assembly.routerAbSigning,
      ),
    listWalletEcdsaKeyFactsInventory:
      assembly.routerAbSigning.listWalletEcdsaKeyFactsInventory.bind(assembly.routerAbSigning),
    verifyEcdsaDerivationRoleLocalClientRootProofForExistingKey:
      assembly.routerAbSigning.verifyEcdsaDerivationRoleLocalClientRootProofForExistingKey.bind(
        assembly.routerAbSigning,
      ),
  };
}

function createD1NearFundingRouteService(
  assembly: D1NearFundingRouteServiceAssembly,
): RouterApiServiceBag['nearFunding'] {
  return {
    fundImplicitNearAccount: fundImplicitNearAccountForOptions.bind(undefined, assembly.options),
    listNearPublicKeysForUser: assembly.nearPublicKeys.listForRelayUser.bind(
      assembly.nearPublicKeys,
    ),
  };
}

function createD1RecoveryRouteService(
  assembly: D1RecoveryRouteServiceAssembly,
): RouterApiServiceBag['recovery'] {
  return {
    getRecoverySession: assembly.sessionService.getRecoverySession.bind(assembly.sessionService),
    recordRecoveryExecution: assembly.sessionService.recordRecoveryExecution.bind(
      assembly.sessionService,
    ),
    updateRecoverySessionStatus: assembly.sessionService.updateRecoverySessionStatus.bind(
      assembly.sessionService,
    ),
  };
}

function createD1EmailRecoveryAuthService(
  assembly: D1EmailRecoveryAuthServiceAssembly,
): RouterApiEmailRecoveryAuthService {
  return new CloudflareD1EmailRecoveryAuthService(assembly);
}

function createD1RouterAccountRouteService(
  assembly: D1RouterAccountRouteServiceAssembly,
): RouterApiServiceBag['router'] {
  return {
    getConfiguredRelayerAccount: assembly.routerAbSigning.getConfiguredRelayerAccount.bind(
      assembly.routerAbSigning,
    ),
    getRelayerAccount: assembly.routerAbSigning.getRelayerAccount.bind(assembly.routerAbSigning),
  };
}

export function createCloudflareD1RouterApiAuthService(
  input: CloudflareD1RouterApiAuthServiceOptions,
): CloudflareD1RouterApiAuthService {
  const assembly = createCloudflareD1RouterApiAuthAssembly(input);
  return {
    walletRegistration: createD1WalletRegistrationRouteService(assembly),
    walletAuthMethods: createD1WalletAuthMethodRouteService(assembly),
    walletUnlock: createD1WalletUnlockRouteService(assembly),
    emailOtp: createD1EmailOtpRouteService(assembly),
    webAuthn: createD1WebAuthnRouteService(assembly),
    identity: createD1IdentityRouteService(assembly),
    sessionVersions: createD1SessionVersionRouteService(assembly),
    thresholdRuntime: createD1ThresholdRuntimeRouteService(assembly),
    nearFunding: createD1NearFundingRouteService(assembly),
    recovery: createD1RecoveryRouteService(assembly),
    router: createD1RouterAccountRouteService(assembly),
  };
}

export function createCloudflareD1RouterApiEmailRecoveryAuthService(
  input: CloudflareD1RouterApiAuthServiceOptions,
): RouterApiEmailRecoveryAuthService {
  const assembly = createCloudflareD1RouterApiAuthAssembly(input);
  return createD1EmailRecoveryAuthService(assembly);
}
