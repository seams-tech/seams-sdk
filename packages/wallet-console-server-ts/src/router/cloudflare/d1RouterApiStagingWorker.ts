import type { D1DatabaseLike } from '@seams/wallet-server/cloud-host';
import {
  resolveSponsoredEvmCallConfigFromWorkerEnv,
  resolveSponsoredEvmWorkerExecutionAdapter,
} from '@seams-internal/wallet-console-server/sponsorship/evmWorkerExecutionAdapter';
import { resolveSponsoredExecutionPricingFromEnv } from '@seams-internal/wallet-console-server/sponsorship/pricing';
import { requireStripeBillingProviderAdaptersFromEnv } from '@seams-internal/console-server/billing/stripeProvider';
import { createCloudflareRouter } from '@seams/wallet-server/cloud-host';
import { withCors } from '@seams/wallet-server/cloud-host';
import {
  consoleCoreServicesFromBundle,
  createCloudflareD1ConsoleServiceBundle,
  createCloudflareD1RouterApiRouteExtensions,
  createConsoleWebhookSecretCipherFromEnv,
  walletConsoleServicesFromBundle,
} from './d1ConsoleServices';
import { createHostedWalletConsoleRouter } from '../consoleComposition';
import { HostedConsoleAuthHandler } from '../hostedConsoleAuth';
import {
  createWalletConsoleOpsClient,
  type WalletConsoleServiceBinding,
} from '../../serviceBinding/walletConsoleOpsClient';
import { createWalletConsoleRelayProxyExtension } from '../../serviceBinding/walletConsoleRelay';
import { createWalletRuntimeOpsHandler } from '../../serviceBinding/walletRuntimeOpsHandler';
import {
  createCloudflareD1RouterAbNormalSigningAdmissionStore,
  createRouterAbNormalSigningAdmissionAdapter,
} from '@seams/wallet-server/cloud-host';
import type { CloudflareD1EmailOtpServerSealConfig } from '@seams/wallet-server/cloud-host';
import {
  createCloudflareD1RouterApiAuthService,
  createCloudflareLinkedDeviceEd25519SourcePreservingRouterEndpointV1,
  createCloudflareOrdinaryInactiveSignerMaterialActivationEndpointV1,
  createCloudflareOrdinaryInactiveSignerMaterialDeactivationEndpointV1,
  createCloudflareOrdinaryInactiveSignerMaterialReservationEndpointV1,
  createD1LinkedDeviceOwnerSourceChildReaderV1,
  createD1LinkedDeviceSourceContributionPreparationPlannerV1,
  D1LinkedDeviceTargetCredentialProviderV1,
  D1WalletAuthMethodStore,
  type CloudflareD1RouterApiAuthServiceOptions,
} from '@seams/wallet-server/cloud-host';
import { loadCloudflareSignerWasmModule } from './d1SignerWasm';
import { createSigningSessionSealOptions } from '@seams/wallet-server/cloud-host';
import { RouterAbEcdsaPresignRuntime } from '@seams/wallet-server/cloud-host';
import type { SigningSessionSealRoutesOptions } from '@seams/wallet-server/cloud-host';
import type {
  CfExecutionContext,
  CfScheduledEvent,
  FetchHandler,
  ScheduledHandler,
} from '@seams/wallet-server/cloud-host';
import {
  createRouterAbEd25519YaoHttpRegistrationBackendFromEnv,
  type RouterAbEd25519YaoGatewaySpanV1,
} from '@seams/wallet-server/cloud-host';
import { type RouterAbEd25519YaoProductRegistrationRuntimeV1 } from '@seams/wallet-server/cloud-host';
import { D1WalletStore } from '@seams/wallet-server/cloud-host';
import { CloudflareD1RouterAbEd25519YaoCapabilityPersistence } from '@seams/wallet-server/cloud-host';
import {
  createRouterAbEcdsaEd25519CeremonyTokenIssuer,
  createRouterAbEcdsaStrictPostRegistrationPort,
  createRouterAbEcdsaStrictRegistrationPort,
  parseRouterAbEcdsaEd25519PrivateJwk,
  parseRouterAbEcdsaStrictRegistrationTopology,
  type RouterAbEcdsaCeremonyTokenIssuer,
  type RouterAbEcdsaStrictRegistrationTopology,
} from '@seams/wallet-server/cloud-host';
import {
  createEd25519SessionAdapter,
  createConsoleSessionAuthAdapter,
  createHmacSessionAdapterFromEnv,
  readCsvList,
  readEnvString,
  requireEnvString,
  type CloudflareD1StagingSessionEnv,
} from './d1StagingSession';
import {
  parseRouterAbPublicKeysetV2,
  type RouterAbPublicKeysetV2,
} from '@seams/wallet-server/cloud-host';
import { base64UrlEncode, parseWalletId } from '@seams/wallet-server/cloud-host';
import {
  createRouterAbServiceBindingFetch,
  ROUTER_AB_MPC_ROUTER_ORIGIN,
  ROUTER_AB_SIGNING_WORKER_ORIGIN,
  type RouterAbServiceBindingEnv,
} from './routerAbServiceBindings';
import { handleRouterAbEd25519YaoRegistrationRequestScopedCloudflareV1 } from '@seams/wallet-server/cloud-host';
import { createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreFromD1V1 } from '@seams/wallet-server/cloud-host';
import { RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter } from '@seams/wallet-server/cloud-host';
import { RouterAbEd25519YaoExportOwnerProofAuthorizationAdapter } from '@seams/wallet-server/cloud-host';
import { createRouterAbEd25519YaoProductRegistrationRequestScopedRuntimeV1 } from '@seams/wallet-server/cloud-host';
import { handleRouterAbEd25519YaoRecoveryRequestScopedCloudflareV1 } from '@seams/wallet-server/cloud-host';
import { handleRouterAbEd25519YaoExportRequestScopedCloudflareV1 } from '@seams/wallet-server/cloud-host';
import {
  ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_STATUS_PATH_V1,
  ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1,
} from '@seams/wallet-server/cloud-host';
import { createCloudflareCron, resolveCloudflareConsoleEmailDispatchCronOptions } from './cron';
import type { RouterApiCloudflareConsoleWorkerEnv } from './cloudflareConsole.types';
import { resolveEmailOtpDeliveryProviderFromEnv } from '../../email/otp/emailOtpProviders';

export interface CloudflareD1GatewayBaseEnv
  extends CloudflareD1StagingSessionEnv, RouterAbServiceBindingEnv {
  readonly SIGNER_DB: D1DatabaseLike;
  readonly SEAMS_TENANT_STORAGE_NAMESPACE?: string;
  readonly SEAMS_STAGING_ORG_ID?: string;
  readonly SEAMS_STAGING_PROJECT_ID?: string;
  readonly SEAMS_STAGING_ENV_ID?: string;
  readonly RELAY_SESSION_HMAC_SECRET?: string;
  readonly SESSION_COOKIE_NAME?: string;
  readonly RELAY_SESSION_ISSUER?: string;
  readonly RELAY_SESSION_AUDIENCE?: string;
  readonly RELAY_CORS_ORIGINS?: string;
  readonly RELAYER_ACCOUNT_ID?: string;
  readonly RELAYER_PUBLIC_KEY?: string;
  readonly RELAYER_PRIVATE_KEY?: string;
  readonly NEAR_RPC_URL?: string;
  readonly ARC_RPC_URL?: string;
  readonly ACCOUNT_INITIAL_BALANCE?: string;
  readonly ENABLE_IMPLICIT_NEAR_ACCOUNT_TEST_FUNDING?: string;
  readonly GOOGLE_OIDC_CLIENT_ID?: string;
  readonly GITHUB_OAUTH_CLIENT_ID?: string;
  readonly GITHUB_OAUTH_CLIENT_SECRET?: string;
  readonly GITHUB_OAUTH_CALLBACK_URL?: string;
  readonly ACCOUNT_ID_DERIVATION_SECRET?: string;
  readonly ROUTER_AB_NORMAL_SIGNING_WORKER_ID?: string;
  readonly SIGNING_WORKER_ID?: string;
  readonly ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET?: string;
  readonly ROUTER_AB_PREWARM_ENABLED: string;
  readonly ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK?: string;
  readonly ROUTER_AB_CEREMONY_JWT_ISSUER?: string;
  readonly ROUTER_AB_CEREMONY_JWT_AUDIENCE?: string;
  readonly ROUTER_AB_CEREMONY_JWT_KEY_ID?: string;
  readonly ROUTER_AB_ECDSA_REGISTRATION_TOPOLOGY_JSON?: string;
  readonly ROUTER_AB_PUBLIC_KEYSET_JSON?: string;
  readonly LINKED_DEVICE_WEBAUTHN_RP_ID?: string;
  readonly SIGNING_SESSION_SEAL_ROOT_SECRET_B64U?: string;
  readonly SIGNING_SESSION_SEAL_CURRENT_KEY_VERSION?: string;
  readonly SIGNING_SESSION_SEAL_ACCEPTED_WARM_KEY_VERSIONS?: string;
  readonly EMAIL_OTP_DELIVERY_MODE?: string;
  readonly EMAIL_OTP_RUNTIME_PROFILE?: string;
  readonly EMAIL_OTP_PROVIDER?: string;
  readonly EMAIL_OTP_FROM_ADDRESS?: string;
  readonly RESEND_API_KEY?: string;
  readonly EMAIL_OTP_SES_REGION?: string;
  readonly EMAIL_OTP_SES_ACCESS_KEY_ID?: string;
  readonly EMAIL_OTP_SES_SECRET_ACCESS_KEY?: string;
  readonly EMAIL_OTP_DEMO_ALLOWED_ORIGINS?: string;
  readonly EMAIL_OTP_PRODUCTION?: string;
  readonly EMAIL_OTP_DEV_OUTBOX_ENABLED?: string;
  readonly EMAIL_OTP_CHALLENGE_RATE_LIMIT_MAX?: string;
  readonly EMAIL_OTP_CHALLENGE_RATE_LIMIT_WINDOW_MS?: string;
  readonly EMAIL_OTP_VERIFY_RATE_LIMIT_MAX?: string;
  readonly EMAIL_OTP_VERIFY_RATE_LIMIT_WINDOW_MS?: string;
  readonly EMAIL_OTP_GRANT_RATE_LIMIT_MAX?: string;
  readonly EMAIL_OTP_GRANT_RATE_LIMIT_WINDOW_MS?: string;
  readonly EMAIL_OTP_MAX_ATTEMPTS?: string;
  readonly EMAIL_OTP_LOCKOUT_TTL_MS?: string;
  readonly EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_MAX?: string;
  readonly EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_WINDOW_MS?: string;
}

type CloudflareD1RouterApiStagingEnv = CloudflareD1GatewayBaseEnv &
  RouterApiCloudflareConsoleWorkerEnv & {
    readonly CONSOLE_DB: D1DatabaseLike;
    readonly SPONSORED_EVM_EXECUTORS_JSON?: string;
    readonly SPONSORED_EXECUTION_REAL_PRICING_JSON?: string;
    readonly SPONSORED_EXECUTION_STATIC_PRICING_JSON?: string;
    readonly STRIPE_API_SK?: string;
    readonly STRIPE_WEBHOOK_SECRET?: string;
    readonly STRIPE_API_BASE_URL?: string;
    readonly STRIPE_API_TIMEOUT_MS?: string;
    readonly CONSOLE_INITIAL_OWNER_EMAIL?: string;
    readonly CONSOLE_PLATFORM_SUPPORT_EMAILS?: string;
    readonly CONSOLE_BASE_URL?: string;
    readonly CONSOLE_SESSION_HMAC_SECRET: string;
    readonly CONSOLE_SESSION_COOKIE_NAME: string;
    readonly CONSOLE_SESSION_ISSUER: string;
    readonly CONSOLE_SESSION_AUDIENCE: string;
  };

export interface CloudflareD1GatewayEnv extends CloudflareD1GatewayBaseEnv {
  readonly WALLET_CONSOLE: WalletConsoleServiceBinding;
}

type RouterApiReadyRow = {
  readonly table_count?: unknown;
};

type RouterApiTenantScope = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

const RELAY_CONSOLE_READY_TABLES = Object.freeze([
  'organizations',
  'projects',
  'environments',
  'organization_memberships',
  'organization_admin_permissions',
  'organization_invitations',
  'project_member_access',
  'organization_owner_events',
  'api_keys',
  'billing_accounts',
  'billing_ledger_entries',
  'billing_ledger_postings',
  'billing_credit_purchases',
  'billing_refunds',
  'billing_prepaid_reservations',
  'stripe_webhook_events',
  'billing_stripe_post_processing_outbox',
  'sponsorship_spend_cap_reservations',
  'sponsorship_pricing_rules',
  'sponsored_call_records',
  'console_email_outbox',
  'console_email_deliveries',
]);
const RELAY_SIGNER_READY_TABLES = Object.freeze([
  'wallets',
  'wallet_auth_methods',
  'reusable_wallet_sessions',
  'opaque_wallet_session_tokens',
  'registration_replay_opaque_wallet_session_tokens_v1',
  'verified_wallet_operation_evidence_sets',
  'verified_owner_proof_consumptions',
  'hosted_wallet_session_exchange_codes',
  'email_otp_challenges',
  'email_otp_grants',
  'router_ab_yao_versioned_json_records',
  'router_ab_yao_versioned_json_cas_guard',
  'router_ab_yao_capability_replacements',
  'router_ab_normal_signing_admission_records',
  'registration_ceremony_records',
  'registration_ceremony_cas_guard',
  'lane_enrollments',
  'lane_protocol_operations',
  'lane_product_epochs',
  'lane_receipts',
  'lane_effect_journal',
  'lane_locks',
  'lane_cas_guard',
  'linked_device_sessions',
  'linked_device_session_cas_guard',
  'linked_device_session_transcripts',
  'linked_device_request_proof_nonces',
  'linked_device_target_credentials',
  'linked_device_target_commit_reservations',
  'linked_device_email_otp_grants',
  'linked_device_ed25519_export_root_transfers',
]);

const ROUTER_AB_CEREMONY_JWKS_PATH = '/.well-known/router-ab-ceremony-jwks.json';

function emitRefactor93GatewaySpan(span: RouterAbEd25519YaoGatewaySpanV1): void {
  console.log(JSON.stringify(span));
}

export function createStagingEd25519YaoBackend(env: CloudflareD1GatewayBaseEnv) {
  const keyEnvironment = stagingEd25519YaoKeyEnvironment(env);
  return createRouterAbEd25519YaoHttpRegistrationBackendFromEnv({
    env: {
      MPC_ROUTER_URL: ROUTER_AB_MPC_ROUTER_ORIGIN,
      SIGNING_WORKER_ID: requireEnvString(env, 'SIGNING_WORKER_ID'),
      ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: requireEnvString(
        env,
        'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
      ),
      DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY: keyEnvironment.DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY,
      DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY: keyEnvironment.DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY,
      SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY:
        keyEnvironment.SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY,
    },
    onSpan: emitRefactor93GatewaySpan,
    fetch: createRouterAbServiceBindingFetch(env),
  });
}

function stagingTenantScope(env: CloudflareD1GatewayBaseEnv): RouterApiTenantScope {
  return {
    namespace: requireEnvString(env, 'SEAMS_TENANT_STORAGE_NAMESPACE'),
    orgId: requireEnvString(env, 'SEAMS_STAGING_ORG_ID'),
    projectId: requireEnvString(env, 'SEAMS_STAGING_PROJECT_ID'),
    envId: requireEnvString(env, 'SEAMS_STAGING_ENV_ID'),
  };
}

async function createStagingRouterApiAuthComposition(
  env: CloudflareD1GatewayBaseEnv,
  scope: RouterApiTenantScope,
  yaoRuntime: RouterAbEd25519YaoProductRegistrationRuntimeV1,
) {
  const ecdsaCeremonyTokenIssuer = createStagingEcdsaCeremonyTokenIssuer(env);
  const topology = requireStagingEcdsaRegistrationTopology(env);
  const tokenScope = {
    orgId: scope.orgId,
    projectId: scope.projectId,
    environment: scope.envId,
  };
  const ecdsaStrictRegistration = createRouterAbEcdsaStrictRegistrationPort({
    router: env.MPC_ROUTER,
    tokenIssuer: ecdsaCeremonyTokenIssuer,
    tokenScope,
    topology,
  });
  const ecdsaStrictPostRegistration = createRouterAbEcdsaStrictPostRegistrationPort({
    router: env.MPC_ROUTER,
    tokenIssuer: ecdsaCeremonyTokenIssuer,
    tokenScope,
    topology,
  });
  const service = createCloudflareD1RouterApiAuthService({
    database: env.SIGNER_DB,
    namespace: scope.namespace,
    orgId: scope.orgId,
    projectId: scope.projectId,
    envId: scope.envId,
    relayerAccount: readEnvString(env, 'RELAYER_ACCOUNT_ID'),
    relayerPublicKey: readEnvString(env, 'RELAYER_PUBLIC_KEY'),
    relayerPrivateKey: readEnvString(env, 'RELAYER_PRIVATE_KEY'),
    nearRpcUrl: readEnvString(env, 'NEAR_RPC_URL'),
    signerWasmModuleOrPath: loadCloudflareSignerWasmModule,
    accountInitialBalance: readEnvString(env, 'ACCOUNT_INITIAL_BALANCE'),
    implicitNearAccountTestFundingEnabled: readEnvString(
      env,
      'ENABLE_IMPLICIT_NEAR_ACCOUNT_TEST_FUNDING',
    ),
    googleOidcClientId: readEnvString(env, 'GOOGLE_OIDC_CLIENT_ID'),
    githubOAuth: stagingGithubOAuthConfig(env),
    accountIdDerivationSecret: requireEnvString(env, 'ACCOUNT_ID_DERIVATION_SECRET'),
    emailOtpServerSeal: stagingEmailOtpServerSealConfig(env),
    emailOtpDeliveryMode: readEnvString(env, 'EMAIL_OTP_DELIVERY_MODE'),
    emailOtpRuntimeProfile: readEnvString(env, 'EMAIL_OTP_RUNTIME_PROFILE'),
    emailOtpDeliveryProvider: resolveEmailOtpDeliveryProviderFromEnv(env),
    emailOtpDemoAllowedOrigins: readEnvString(env, 'EMAIL_OTP_DEMO_ALLOWED_ORIGINS'),
    emailOtpProduction: readEnvString(env, 'EMAIL_OTP_PRODUCTION'),
    emailOtpDevOutboxEnabled: readEnvString(env, 'EMAIL_OTP_DEV_OUTBOX_ENABLED'),
    emailOtpChallengeRateLimitMax: readEnvString(env, 'EMAIL_OTP_CHALLENGE_RATE_LIMIT_MAX'),
    emailOtpChallengeRateLimitWindowMs: readEnvString(
      env,
      'EMAIL_OTP_CHALLENGE_RATE_LIMIT_WINDOW_MS',
    ),
    emailOtpVerifyRateLimitMax: readEnvString(env, 'EMAIL_OTP_VERIFY_RATE_LIMIT_MAX'),
    emailOtpVerifyRateLimitWindowMs: readEnvString(env, 'EMAIL_OTP_VERIFY_RATE_LIMIT_WINDOW_MS'),
    emailOtpGrantRateLimitMax: readEnvString(env, 'EMAIL_OTP_GRANT_RATE_LIMIT_MAX'),
    emailOtpGrantRateLimitWindowMs: readEnvString(env, 'EMAIL_OTP_GRANT_RATE_LIMIT_WINDOW_MS'),
    emailOtpMaxAttempts: readEnvString(env, 'EMAIL_OTP_MAX_ATTEMPTS'),
    emailOtpLockoutTtlMs: readEnvString(env, 'EMAIL_OTP_LOCKOUT_TTL_MS'),
    emailOtpGoogleRegistrationAttemptRateLimitMax: readEnvString(
      env,
      'EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_MAX',
    ),
    emailOtpGoogleRegistrationAttemptRateLimitWindowMs: readEnvString(
      env,
      'EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_WINDOW_MS',
    ),
    routerAbEcdsaPresignRuntime: createStagingEcdsaPresignRuntime(env),
    ed25519YaoProductRegistration: yaoRuntime,
    ecdsaStrictRegistration,
    linkedDevice: stagingLinkedDeviceSessionComposition(env, scope),
  });
  return { service, ecdsaStrictPostRegistration };
}

function stagingLinkedDeviceSessionComposition(
  env: CloudflareD1GatewayBaseEnv,
  scope: RouterApiTenantScope,
): NonNullable<CloudflareD1RouterApiAuthServiceOptions['linkedDevice']> {
  const walletStore = new D1WalletStore({
    database: env.SIGNER_DB,
    ...scope,
    ensureSchema: false,
  });
  const walletAuthMethodStore = new D1WalletAuthMethodStore({
    database: env.SIGNER_DB,
    ...scope,
    ensureSchema: false,
  });
  const sourceChildReader = createD1LinkedDeviceOwnerSourceChildReaderV1({
    walletAuthMethodStore,
    walletStore,
  });
  const serviceFetch = createRouterAbServiceBindingFetch(env);
  const internalServiceAuthSecret = requireEnvString(env, 'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET');
  const keyEnvironment = stagingEd25519YaoKeyEnvironment(env);
  const deriverAInputPublicKeyB64u = x25519PublicKeyB64u(
    keyEnvironment.DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY,
  );
  const deriverBInputPublicKeyB64u = x25519PublicKeyB64u(
    keyEnvironment.DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY,
  );
  const signingWorkerRecipientPublicKeyB64u = x25519PublicKeyB64u(
    keyEnvironment.SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY,
  );
  return {
    session: {
      readOwnerSourceChildV1: sourceChildReader.readOwnerSourceChildV1,
      targetPasskeyRpId: requireEnvString(env, 'LINKED_DEVICE_WEBAUTHN_RP_ID'),
      targetCredential: ({
        verifiedLinkBuilder,
        targetCredentialVerification,
        targetPlanner,
        resolveOwnerSourceChildV1,
        emailOtpGrants,
      }) =>
        new D1LinkedDeviceTargetCredentialProviderV1({
          database: env.SIGNER_DB,
          scope,
          verifier: targetCredentialVerification,
          ...(emailOtpGrants === undefined ? {} : { emailOtpGrants }),
          planner: targetPlanner,
          sourceContributionPreparationPlanner:
            createD1LinkedDeviceSourceContributionPreparationPlannerV1({
              resolveOwnerSourceChildV1,
              deriverAInputPublicKeyB64u,
              deriverBInputPublicKeyB64u,
              signingWorkerRecipientPublicKeyB64u,
            }),
          verifiedLinkBuilder,
        }),
      authorityInstallation: {
        reservationEndpoint: createCloudflareOrdinaryInactiveSignerMaterialReservationEndpointV1({
          fetch: serviceFetch,
          internalServiceAuthSecret,
        }),
        activationEndpoint: createCloudflareOrdinaryInactiveSignerMaterialActivationEndpointV1({
          fetch: serviceFetch,
          internalServiceAuthSecret,
        }),
        deactivationEndpoint: createCloudflareOrdinaryInactiveSignerMaterialDeactivationEndpointV1({
          fetch: serviceFetch,
          internalServiceAuthSecret,
        }),
      },
      sourceContributionRouter: createCloudflareLinkedDeviceEd25519SourcePreservingRouterEndpointV1(
        {
          fetch: serviceFetch,
          internalServiceAuthSecret,
        },
      ),
    },
  };
}

async function createRouterApiHandler(env: CloudflareD1RouterApiStagingEnv): Promise<FetchHandler> {
  const scope = stagingTenantScope(env);
  const sponsoredEvmCallConfig = await resolveSponsoredEvmCallConfigFromWorkerEnv(env);
  const bundle = await createCloudflareD1ConsoleServiceBundle({
    bindings: {
      consoleDatabase: env.CONSOLE_DB,
      signerMetadataDatabase: env.SIGNER_DB,
    },
    route: {
      namespace: scope.namespace,
    },
    adapters: {
      ensureSchema: false,
      billingProviders: requireStripeBillingProviderAdaptersFromEnv(env),
      billingEmailConsoleBaseUrl: requireEnvString(env, 'CONSOLE_BASE_URL'),
      ...(readEnvString(env, 'CONSOLE_DOCS_BASE_URL')
        ? {
            onboardingEmail: {
              consoleBaseUrl: requireEnvString(env, 'CONSOLE_BASE_URL'),
              docsBaseUrl: requireEnvString(env, 'CONSOLE_DOCS_BASE_URL'),
            },
          }
        : {}),
      sponsoredEvmCallConfig,
      resolveSponsoredEvmExecutionAdapter: resolveSponsoredEvmWorkerExecutionAdapter,
      sponsorshipPricing: resolveSponsoredExecutionPricingFromEnv(env),
      webhookSecretCipher: createConsoleWebhookSecretCipherFromEnv(env),
    },
  });
  const session = stagingSessionAdapter(env);
  const yaoRuntime = createStagingYaoRequestScopedRuntime(env);
  const { service, ecdsaStrictPostRegistration } = await createStagingRouterApiAuthComposition(
    env,
    scope,
    yaoRuntime,
  );
  const routerApiHandler = createCloudflareRouter(service, {
    ...bundle.routerApiRouterOptions,
    routeExtensions: createCloudflareD1RouterApiRouteExtensions(bundle, service),
    healthz: true,
    readyz: true,
    corsOrigins: readCsvList(env.RELAY_CORS_ORIGINS),
    session,
    sessionCookieName: readEnvString(env, 'SESSION_COOKIE_NAME'),
    routerAbPublicKeyset: requireStagingRouterAbPublicKeyset(env),
    routerAbNormalSigningRouterProxy: {
      internalServiceAuthSecret: requireEnvString(env, 'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET'),
      fetch: (request) => env.MPC_ROUTER.fetch(request),
    },
    routerAbEcdsaStrictPostRegistration: ecdsaStrictPostRegistration,
    readyCheck: createRouterApiReadyCheck(env),
    signingSessionSeal: stagingSigningSessionSealOptions(env),
    routerAbEd25519YaoProduct: yaoRuntime,
  });
  const consoleSession = createHmacSessionAdapterFromEnv({
    env,
    secretName: 'CONSOLE_SESSION_HMAC_SECRET',
    cookieName: requireEnvString(env, 'CONSOLE_SESSION_COOKIE_NAME'),
    issuer: requireEnvString(env, 'CONSOLE_SESSION_ISSUER'),
    audience: requireEnvString(env, 'CONSOLE_SESSION_AUDIENCE'),
  });
  const consoleAuth = createConsoleSessionAuthAdapter({
    session: consoleSession,
    organizationAccess: bundle.organizationAccess,
    defaultOrgId: scope.orgId,
    defaultProjectId: scope.projectId,
    defaultEnvironmentId: scope.envId,
    platformSupportEmails: readEnvString(env, 'CONSOLE_PLATFORM_SUPPORT_EMAILS'),
  });
  const consoleHandler = createHostedWalletConsoleRouter({
    core: consoleCoreServicesFromBundle(bundle),
    walletConsole: walletConsoleServicesFromBundle(bundle),
    tenantStorage: {
      resolver: bundle.tenantStorageRouteResolver,
      namespace: bundle.tenantStorageNamespace,
    },
    corsOrigins: readCsvList(env.RELAY_CORS_ORIGINS),
    auth: consoleAuth,
    session: consoleSession,
    readyCheck: createRouterApiReadyCheck(env),
    billingStripeWebhookSigningSecret: readEnvString(env, 'STRIPE_WEBHOOK_SECRET'),
  });
  const hostedConsoleHandler = new HostedConsoleAuthHandler({
    handler: consoleHandler,
    identity: service.identity,
    session: consoleSession,
    organizationAccess: bundle.organizationAccess,
    orgProjectEnv: bundle.orgProjectEnv,
    scope,
    initialOwner: {
      kind: 'configured_google_email',
      email: readEnvString(env, 'CONSOLE_INITIAL_OWNER_EMAIL'),
    },
    corsOrigins: readCsvList(env.RELAY_CORS_ORIGINS),
  });
  return dispatchHostedGatewayRequest.bind(
    null,
    hostedConsoleHandler.fetch.bind(hostedConsoleHandler),
    routerApiHandler,
  );
}

/**
 * The split Wallet Gateway (R105 Phase 4 cutover target): serves the Wallet
 * runtime only, holds no Console database binding, and reaches the Wallet
 * Console deployment exclusively through the exact service-binding ops.
 * The sponsored-relay route extensions stay on the Wallet Console deployment
 * until policy/sponsorship resolution operations join the binding.
 */
export async function createSplitGatewayRouterHandler(
  env: CloudflareD1GatewayEnv,
): Promise<FetchHandler> {
  const scope = stagingTenantScope(env);
  const session = stagingSessionAdapter(env);
  const yaoRuntime = createStagingYaoRequestScopedRuntime(env);
  const { service, ecdsaStrictPostRegistration } = await createStagingRouterApiAuthComposition(
    env,
    scope,
    yaoRuntime,
  );
  const ops = createWalletConsoleOpsClient(env.WALLET_CONSOLE);
  const admissionStore = createCloudflareD1RouterAbNormalSigningAdmissionStore({
    database: env.SIGNER_DB,
    storageNamespace: scope.namespace,
  });
  return createCloudflareRouter(service, {
    apiKeyAuth: ops.apiKeyAuth,
    publishableKeyAuth: ops.publishableKeyAuth,
    apiKeyUsageMeter: ops.usageMeter,
    orgProjectEnv: ops.projectEnvironments,
    routerAbNormalSigningAdmission: createRouterAbNormalSigningAdmissionAdapter(admissionStore),
    routeExtensions: [createWalletConsoleRelayProxyExtension(env.WALLET_CONSOLE)],
    healthz: true,
    readyz: true,
    corsOrigins: readCsvList(env.RELAY_CORS_ORIGINS),
    session,
    sessionCookieName: readEnvString(env, 'SESSION_COOKIE_NAME'),
    routerAbPublicKeyset: requireStagingRouterAbPublicKeyset(env),
    routerAbNormalSigningRouterProxy: {
      internalServiceAuthSecret: requireEnvString(env, 'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET'),
      fetch: (request) => env.MPC_ROUTER.fetch(request),
    },
    routerAbEcdsaStrictPostRegistration: ecdsaStrictPostRegistration,
    readyCheck: async () => {
      await assertD1Tables({
        database: env.SIGNER_DB,
        label: 'SIGNER_DB',
        tables: RELAY_SIGNER_READY_TABLES,
      });
    },
    signingSessionSeal: stagingSigningSessionSealOptions(env),
    routerAbEd25519YaoProduct: yaoRuntime,
  });
}

export async function handleSplitGatewayWalletRuntimeRequest(
  request: Request,
  env: CloudflareD1GatewayBaseEnv,
): Promise<Response | null> {
  const handler = createWalletRuntimeOpsHandler(async () => {
    const scope = stagingTenantScope(env);
    const yaoRuntime = createStagingYaoRequestScopedRuntime(env);
    const { service } = await createStagingRouterApiAuthComposition(env, scope, yaoRuntime);
    return {
      executeSignedDelegate: service.executeSignedDelegate.bind(service),
      getRelayerAccount: service.router.getRelayerAccount.bind(service.router),
    };
  });
  return await handler(request);
}

export async function handleSplitGatewayRequest(
  request: Request,
  env: CloudflareD1GatewayEnv,
  ctx: CfExecutionContext,
): Promise<Response> {
  if (request.method === 'GET' && new URL(request.url).pathname === ROUTER_AB_CEREMONY_JWKS_PATH) {
    return routerAbCeremonyJwksResponse(env);
  }
  const operation = yaoDirectOperationForRequest(request);
  if (operation !== null) {
    const response = await handlePartitionedD1Operation(env, request, operation);
    withCors(response.headers, { corsOrigins: readCsvList(env.RELAY_CORS_ORIGINS) }, request);
    return response;
  }
  const handler = await createSplitGatewayRouterHandler(env);
  return await handler(request, env, ctx);
}

export async function dispatchHostedGatewayRequest(
  consoleHandler: FetchHandler,
  routerApiHandler: FetchHandler,
  request: Request,
  env?: object,
  ctx?: CfExecutionContext,
): Promise<Response> {
  const pathname = new URL(request.url).pathname;
  const handler =
    pathname === '/console' || pathname.startsWith('/console/') ? consoleHandler : routerApiHandler;
  return await handler(request, env, ctx);
}

function requireStagingRouterAbPublicKeyset(
  env: CloudflareD1GatewayBaseEnv,
): RouterAbPublicKeysetV2 {
  const source = requireEnvString(env, 'ROUTER_AB_PUBLIC_KEYSET_JSON');
  const parsed = parseJsonObject(source);
  if (!parsed) {
    throw new Error('ROUTER_AB_PUBLIC_KEYSET_JSON must contain a JSON object');
  }
  return parseRouterAbPublicKeysetV2(parsed);
}

function stagingEd25519YaoKeyEnvironment(env: CloudflareD1GatewayBaseEnv) {
  const keyset = requireStagingRouterAbPublicKeyset(env);
  return {
    DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY:
      keyset.signer_envelope_hpke.current.deriver_a.public_key,
    DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY:
      keyset.signer_envelope_hpke.current.deriver_b.public_key,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY:
      keyset.signing_worker_server_output_hpke.public_key,
  };
}

function x25519PublicKeyB64u(value: string): string {
  if (!/^x25519:[0-9a-f]{64}$/.test(value)) {
    throw new Error(
      'signing worker server output HPKE public key must use x25519:<64 lowercase hex chars> encoding',
    );
  }
  const hex = value.slice('x25519:'.length);
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return base64UrlEncode(bytes);
}

function createStagingEcdsaCeremonyTokenIssuer(
  env: CloudflareD1GatewayBaseEnv,
): RouterAbEcdsaCeremonyTokenIssuer {
  return createRouterAbEcdsaEd25519CeremonyTokenIssuer({
    issuer: requireEnvString(env, 'ROUTER_AB_CEREMONY_JWT_ISSUER'),
    audience: requireEnvString(env, 'ROUTER_AB_CEREMONY_JWT_AUDIENCE'),
    keyId: requireEnvString(env, 'ROUTER_AB_CEREMONY_JWT_KEY_ID'),
    privateJwk: requireStagingEcdsaCeremonyPrivateJwk(env),
  });
}

function requireStagingEcdsaCeremonyPrivateJwk(env: CloudflareD1GatewayBaseEnv) {
  const privateJwkSource = requireEnvString(env, 'ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK');
  const privateJwk = parseRouterAbEcdsaEd25519PrivateJwk(parseJsonObject(privateJwkSource));
  if (!privateJwk) {
    throw new Error('ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK must be an Ed25519 private JWK');
  }
  return privateJwk;
}

function requireStagingEcdsaRegistrationTopology(
  env: CloudflareD1GatewayBaseEnv,
): RouterAbEcdsaStrictRegistrationTopology {
  const source = requireEnvString(env, 'ROUTER_AB_ECDSA_REGISTRATION_TOPOLOGY_JSON');
  const topology = parseRouterAbEcdsaStrictRegistrationTopology(parseJsonObject(source));
  if (!topology) {
    throw new Error(
      'ROUTER_AB_ECDSA_REGISTRATION_TOPOLOGY_JSON must contain the MPCRouter topology',
    );
  }
  return topology;
}

function routerAbCeremonyJwksResponse(env: CloudflareD1GatewayBaseEnv): Response {
  const issuer = createStagingEcdsaCeremonyTokenIssuer(env);
  return new Response(JSON.stringify(issuer.publicJwks()), {
    status: 200,
    headers: {
      'cache-control': 'public, max-age=300',
      'content-type': 'application/json; charset=utf-8',
    },
  });
}

let cachedStagingSigningSessionSealOptions: SigningSessionSealRoutesOptions | null = null;

export function stagingSigningSessionSealOptions(
  env: Pick<
    CloudflareD1GatewayBaseEnv,
    | 'SIGNING_SESSION_SEAL_ROOT_SECRET_B64U'
    | 'SIGNING_SESSION_SEAL_CURRENT_KEY_VERSION'
    | 'SIGNING_SESSION_SEAL_ACCEPTED_WARM_KEY_VERSIONS'
  >,
): SigningSessionSealRoutesOptions | undefined {
  if (cachedStagingSigningSessionSealOptions) return cachedStagingSigningSessionSealOptions;
  const seal = stagingEmailOtpServerSealConfig(env);
  if (!seal) return undefined;
  cachedStagingSigningSessionSealOptions = createSigningSessionSealOptions({
    rootSecretB64u: seal.rootSecretB64u,
    currentKeyVersion: seal.currentKeyVersion,
    acceptedWarmKeyVersions: seal.acceptedWarmKeyVersions,
  });
  return cachedStagingSigningSessionSealOptions;
}

function createStagingEcdsaPresignRuntime(
  env: CloudflareD1GatewayBaseEnv,
): RouterAbEcdsaPresignRuntime {
  return new RouterAbEcdsaPresignRuntime({
    config: {
      nodeRole: 'coordinator',
      participantIds: {
        clientParticipantId: 1,
        relayerParticipantId: 2,
        participantIds2p: [1, 2],
      },
    },
    signingWorkerTransport: {
      kind: 'configured',
      signingWorkerBaseUrl: ROUTER_AB_SIGNING_WORKER_ORIGIN,
      auth: {
        kind: 'internal_service_auth_secret',
        secret: requireEnvString(env, 'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET'),
      },
      fetchImpl: createRouterAbServiceBindingFetch(env),
    },
    ensureReady: readyStagingEcdsaPresignRuntime,
  });
}

async function readyStagingEcdsaPresignRuntime(): Promise<void> {}

function createRouterApiReadyCheck(env: CloudflareD1RouterApiStagingEnv): () => Promise<void> {
  const check = new RouterApiStagingReadyCheck(env);
  return check.check.bind(check);
}

class RouterApiStagingReadyCheck {
  constructor(private readonly env: CloudflareD1RouterApiStagingEnv) {}

  async check(): Promise<void> {
    await assertD1Tables({
      database: this.env.CONSOLE_DB,
      label: 'CONSOLE_DB',
      tables: RELAY_CONSOLE_READY_TABLES,
    });
    await assertD1Tables({
      database: this.env.SIGNER_DB,
      label: 'SIGNER_DB',
      tables: RELAY_SIGNER_READY_TABLES,
    });
  }
}

async function assertD1Tables(input: {
  readonly database: D1DatabaseLike;
  readonly label: string;
  readonly tables: readonly string[];
}): Promise<void> {
  const row = await input.database
    .prepare(
      `SELECT COUNT(*) AS table_count
         FROM sqlite_master
        WHERE type = 'table'
          AND name IN (${d1StringList(input.tables)})`,
    )
    .first<RouterApiReadyRow>();
  const count = Number(row?.table_count || 0);
  if (count !== input.tables.length) {
    throw new Error(
      `${input.label} migration has created ${count} of ${input.tables.length} staging-ready tables`,
    );
  }
}

function stagingEmailOtpServerSealConfig(
  env: Pick<
    CloudflareD1GatewayBaseEnv,
    | 'SIGNING_SESSION_SEAL_ROOT_SECRET_B64U'
    | 'SIGNING_SESSION_SEAL_CURRENT_KEY_VERSION'
    | 'SIGNING_SESSION_SEAL_ACCEPTED_WARM_KEY_VERSIONS'
  >,
): CloudflareD1EmailOtpServerSealConfig | undefined {
  const rootSecretB64u = readEnvString(env, 'SIGNING_SESSION_SEAL_ROOT_SECRET_B64U');
  const currentKeyVersion = readEnvString(env, 'SIGNING_SESSION_SEAL_CURRENT_KEY_VERSION');
  const acceptedWarmKeyVersions = readEnvString(
    env,
    'SIGNING_SESSION_SEAL_ACCEPTED_WARM_KEY_VERSIONS',
  )
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  if (!rootSecretB64u && !currentKeyVersion) {
    return undefined;
  }
  if (!rootSecretB64u || !currentKeyVersion || acceptedWarmKeyVersions.length === 0) {
    throw new Error(
      'Email OTP server seal requires the root secret, current key version, and accepted warm key versions',
    );
  }
  return {
    rootSecretB64u,
    currentKeyVersion,
    acceptedWarmKeyVersions,
  };
}

function stagingGithubOAuthConfig(env: CloudflareD1GatewayBaseEnv) {
  const clientId = readEnvString(env, 'GITHUB_OAUTH_CLIENT_ID');
  const clientSecret = readEnvString(env, 'GITHUB_OAUTH_CLIENT_SECRET');
  const callbackUrl = readEnvString(env, 'GITHUB_OAUTH_CALLBACK_URL');
  if (!clientId && !clientSecret && !callbackUrl) return undefined;
  if (!clientId || !clientSecret || !callbackUrl) {
    throw new Error(
      'GitHub OAuth requires GITHUB_OAUTH_CLIENT_ID, GITHUB_OAUTH_CLIENT_SECRET, and GITHUB_OAUTH_CALLBACK_URL',
    );
  }
  return { clientId, clientSecret, callbackUrl };
}

function parseJsonObject(text: string): Record<string, unknown> | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  return isRecord(parsed) ? parsed : null;
}

function isRecord(input: unknown): input is Record<string, unknown> {
  return typeof input === 'object' && input !== null && !Array.isArray(input);
}

function d1StringList(values: readonly string[]): string {
  return values.map(d1StringLiteral).join(', ');
}

function d1StringLiteral(value: string): string {
  if (!/^[a-z0-9_]+$/.test(value)) {
    throw new Error(`invalid D1 table name ${value}`);
  }
  return `'${value}'`;
}

async function handlePartitionedRouterApiRequest(
  env: CloudflareD1RouterApiStagingEnv,
  request: Request,
  ctx?: CfExecutionContext,
): Promise<Response> {
  const handler = await createRouterApiHandler(env);
  return await handler(request, env, ctx);
}

async function fetch(
  request: Request,
  env: CloudflareD1RouterApiStagingEnv,
  ctx: CfExecutionContext,
): Promise<Response> {
  if (request.method === 'GET' && new URL(request.url).pathname === ROUTER_AB_CEREMONY_JWKS_PATH) {
    return routerAbCeremonyJwksResponse(env);
  }
  const operation = yaoDirectOperationForRequest(request);
  if (operation !== null) {
    const response = await handlePartitionedD1Operation(env, request, operation);
    withCors(response.headers, { corsOrigins: readCsvList(env.RELAY_CORS_ORIGINS) }, request);
    return response;
  }
  return await handlePartitionedRouterApiRequest(env, request, ctx);
}

function gatewayScheduledHandler(env: CloudflareD1RouterApiStagingEnv): ScheduledHandler {
  const runtimeProfile = readEnvString(env, 'CONSOLE_EMAIL_RUNTIME_PROFILE');
  if (!runtimeProfile) return createCloudflareCron({});
  return createCloudflareCron({
    consoleEmailDispatch: resolveCloudflareConsoleEmailDispatchCronOptions({
      env,
      database: env.CONSOLE_DB,
      namespace: requireEnvString(env, 'SEAMS_TENANT_STORAGE_NAMESPACE'),
      ensureSchema: false,
      invitationDelivery: { kind: 'DISABLED' },
    }),
  });
}

const ROUTER_AB_PREWARM_CRON = '* * * * *';
const ROUTER_AB_PREWARM_PATH = '/internal/prewarm';
const ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER = 'x-router-ab-internal-service-auth';

function parseRouterAbPrewarmEnabled(value: unknown): boolean {
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error('ROUTER_AB_PREWARM_ENABLED must be true or false');
}

function isSuccessfulPrewarmResponse(value: unknown): value is { readonly ok: true } {
  return isRecord(value) && value.ok === true;
}

export async function runRouterAbPrewarmScheduled(
  event: CfScheduledEvent,
  env: Pick<
    CloudflareD1GatewayBaseEnv,
    'MPC_ROUTER' | 'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET' | 'ROUTER_AB_PREWARM_ENABLED'
  >,
): Promise<void> {
  if (event.cron !== ROUTER_AB_PREWARM_CRON) return;
  if (!parseRouterAbPrewarmEnabled(env.ROUTER_AB_PREWARM_ENABLED)) return;
  const response = await env.MPC_ROUTER.fetch(
    new Request(`${ROUTER_AB_MPC_ROUTER_ORIGIN}${ROUTER_AB_PREWARM_PATH}`, {
      method: 'POST',
      headers: {
        [ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER]: requireEnvString(
          env,
          'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
        ),
      },
    }),
  );
  if (!response.ok) {
    throw new Error(`Router A/B prewarm failed with HTTP ${response.status}`);
  }
  const body: unknown = await response.json();
  if (!isSuccessfulPrewarmResponse(body)) {
    throw new Error('Router A/B prewarm returned an invalid response');
  }
}

async function scheduled(
  event: CfScheduledEvent,
  env: CloudflareD1RouterApiStagingEnv,
  ctx: CfExecutionContext,
): Promise<void> {
  await Promise.all([
    gatewayScheduledHandler(env)(event, env, ctx),
    runRouterAbPrewarmScheduled(event, env),
  ]);
}

type RouterApiYaoDirectOperationV1 =
  | 'registration_admission'
  | 'registration_execute'
  | 'recovery_bootstrap'
  | 'recovery_admission'
  | 'recovery_execute'
  | 'recovery_activate'
  | 'recovery_status'
  | 'export_admission'
  | 'export_execute';

function yaoDirectOperationForRequest(request: Request): RouterApiYaoDirectOperationV1 | null {
  if (request.method !== 'POST') return null;
  const pathname = new URL(request.url).pathname;
  switch (pathname) {
    case ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1:
      return 'registration_admission';
    case ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1:
      return 'registration_execute';
    case ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1:
      return 'recovery_bootstrap';
    case ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1:
      return 'recovery_admission';
    case ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1:
      return 'recovery_execute';
    case ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1:
      return 'recovery_activate';
    case ROUTER_AB_ED25519_YAO_RECOVERY_STATUS_PATH_V1:
      return 'recovery_status';
    case ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1:
      return 'export_admission';
    case ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1:
      return 'export_execute';
    default:
      return null;
  }
}

async function handlePartitionedD1Operation(
  env: CloudflareD1GatewayBaseEnv,
  request: Request,
  operation: RouterApiYaoDirectOperationV1,
): Promise<Response> {
  switch (operation) {
    case 'registration_admission':
    case 'registration_execute':
      return await handleRouterAbEd25519YaoRegistrationRequestScopedCloudflareV1({
        request,
        store: createStagingYaoPartitionedStateStore(env),
        backend: createStagingEd25519YaoBackend(env),
      });
    case 'recovery_bootstrap':
    case 'recovery_admission':
    case 'recovery_execute':
    case 'recovery_activate':
    case 'recovery_status':
      return await handleRouterAbEd25519YaoRecoveryRequestScopedCloudflareV1({
        request,
        ...createStagingRecoveryRequestScopedDependencies(env),
      });
    case 'export_admission':
    case 'export_execute': {
      const scope = stagingTenantScope(env);
      const yaoRuntime = createStagingYaoRequestScopedRuntime(env);
      const { service } = await createStagingRouterApiAuthComposition(env, scope, yaoRuntime);
      return await handleRouterAbEd25519YaoExportRequestScopedCloudflareV1({
        request,
        ...createStagingExportRequestScopedDependencies(env, service),
      });
    }
  }
}

function createStagingYaoPartitionedStateStore(
  env: CloudflareD1GatewayBaseEnv,
): ReturnType<typeof createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreFromD1V1> {
  const scope = stagingTenantScope(env);
  return createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreFromD1V1({
    database: env.SIGNER_DB,
    scope,
  });
}

async function loadStagingPersistedActiveCapability(
  env: CloudflareD1GatewayBaseEnv,
  lookup: Parameters<RouterAbEd25519YaoProductRegistrationRuntimeV1['resolveActiveCapability']>[0],
) {
  const walletId = parseWalletId(lookup.walletId);
  if (!walletId.ok) return null;
  const signer = await stagingWalletStore(env).getEd25519SignerBySlot({
    walletId: walletId.value,
    signerSlot: lookup.signerSlot,
  });
  return signer?.activeYaoCapability || null;
}

function createStagingYaoRequestScopedRuntime(
  env: CloudflareD1GatewayBaseEnv,
): RouterAbEd25519YaoProductRegistrationRuntimeV1 {
  return createRouterAbEd25519YaoProductRegistrationRequestScopedRuntimeV1({
    signingWorkerId: requireEnvString(env, 'SIGNING_WORKER_ID'),
    store: createStagingYaoPartitionedStateStore(env),
    registrationBackend: createStagingEd25519YaoBackend(env),
    loadPersistedActiveCapability: loadStagingPersistedActiveCapability.bind(undefined, env),
  });
}

export default { fetch, scheduled };

/**
 * Builds the recovery request-scoped dependencies from the environment alone.
 * This is new composition wiring over the existing authorization classes, not a
 * second authorization implementation: the same adapter the tenant runtime uses
 * is constructed here against request-scoped state instead of runtime-held
 * state, which is the dependency Refactor 93 exists to remove.
 */
export function createStagingRecoveryRequestScopedDependencies(env: CloudflareD1GatewayBaseEnv): {
  readonly store: ReturnType<typeof createStagingYaoPartitionedStateStore>;
  readonly backend: ReturnType<typeof createStagingEd25519YaoBackend>;
  readonly authorization: RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter;
  readonly capabilityPersistence: CloudflareD1RouterAbEd25519YaoCapabilityPersistence;
  readonly capabilities: RouterAbEd25519YaoProductRegistrationRuntimeV1;
} {
  const scope = stagingTenantScope(env);
  const store = createStagingYaoPartitionedStateStore(env);
  const session = stagingSessionAdapter(env);
  return {
    store,
    backend: createStagingEd25519YaoBackend(env),
    authorization: new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(async () => {
      const yaoRuntime = createStagingYaoRequestScopedRuntime(env);
      const { service } = await createStagingRouterApiAuthComposition(env, scope, yaoRuntime);
      return {
        authorizationSessions: service.authorizationSessions,
        preparedRecoveryAdmission: service.passkeyCustody,
        session,
      };
    }),
    capabilityPersistence: new CloudflareD1RouterAbEd25519YaoCapabilityPersistence({
      database: env.SIGNER_DB,
      scope,
      walletStore: stagingWalletStore(env),
      ensureSchema: false,
    }),
    capabilities: createStagingYaoRequestScopedRuntime(env),
  };
}

/**
 * Builds export request-scoped state while reusing the request's authoritative
 * Router API factor and owner-proof services.
 */
export function createStagingExportRequestScopedDependencies(
  env: CloudflareD1GatewayBaseEnv,
  service: ReturnType<typeof createCloudflareD1RouterApiAuthService>,
): {
  readonly store: ReturnType<typeof createStagingYaoPartitionedStateStore>;
  readonly backend: ReturnType<typeof createStagingEd25519YaoBackend>;
  readonly authorization: RouterAbEd25519YaoExportOwnerProofAuthorizationAdapter;
  readonly capabilities: RouterAbEd25519YaoProductRegistrationRuntimeV1;
} {
  const store = createStagingYaoPartitionedStateStore(env);
  return {
    store,
    backend: createStagingEd25519YaoBackend(env),
    authorization: new RouterAbEd25519YaoExportOwnerProofAuthorizationAdapter(
      service.webAuthn,
      service.emailOtp,
      service.walletAuthMethods,
      service.authorizedOperations,
      service.walletRegistration.resolveEd25519MaterialActivation.bind(service.walletRegistration),
    ),
    capabilities: createStagingYaoRequestScopedRuntime(env),
  };
}

function stagingSessionAdapter(env: CloudflareD1GatewayBaseEnv) {
  return createEd25519SessionAdapter({
    privateJwk: requireStagingEcdsaCeremonyPrivateJwk(env),
    keyId: requireEnvString(env, 'ROUTER_AB_CEREMONY_JWT_KEY_ID'),
    cookieName: readEnvString(env, 'SESSION_COOKIE_NAME'),
    issuer: requireEnvString(env, 'ROUTER_AB_CEREMONY_JWT_ISSUER'),
    audience: requireEnvString(env, 'ROUTER_AB_CEREMONY_JWT_AUDIENCE'),
  });
}

function stagingWalletStore(env: CloudflareD1GatewayBaseEnv): D1WalletStore {
  const scope = stagingTenantScope(env);
  return new D1WalletStore({
    database: env.SIGNER_DB,
    namespace: scope.namespace,
    orgId: scope.orgId,
    projectId: scope.projectId,
    envId: scope.envId,
    ensureSchema: false,
  });
}
