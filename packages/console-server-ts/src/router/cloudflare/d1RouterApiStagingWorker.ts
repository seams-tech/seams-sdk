import type { D1DatabaseLike } from '@seams/sdk-server/cloud-host';
import {
  resolveSponsoredEvmCallConfigFromWorkerEnv,
  resolveSponsoredEvmWorkerExecutionAdapter,
} from '@seams-internal/console-server/sponsorship/evmWorkerExecutionAdapter';
import { resolveSponsoredExecutionPricingFromEnv } from '@seams-internal/console-server/sponsorship/pricing';
import { requireStripeBillingProviderAdaptersFromEnv } from '@seams-internal/console-server/billing/stripeProvider';
import { createCloudflareRouter } from '@seams/sdk-server/cloud-host';
import { withCors } from '@seams/sdk-server/cloud-host';
import { createCloudflareConsoleRouter } from './createCloudflareConsoleRouter';
import {
  createCloudflareD1ConsoleServiceBundle,
  createCloudflareD1RouterApiRouteExtensions,
} from './d1ConsoleServices';
import type { CloudflareD1EmailOtpServerSealConfig } from '@seams/sdk-server/cloud-host';
import { createCloudflareD1RouterApiAuthService } from '@seams/sdk-server/cloud-host';
import { loadCloudflareSignerWasmModule } from './d1SignerWasm';
import { createSigningSessionSealOptions } from '@seams/sdk-server/cloud-host';
import { RouterAbEcdsaPresignRuntime } from '@seams/sdk-server/cloud-host';
import type { SigningSessionSealRoutesOptions } from '@seams/sdk-server/cloud-host';
import type {
  CfExecutionContext,
  CfScheduledEvent,
  FetchHandler,
  ScheduledHandler,
} from '@seams/sdk-server/cloud-host';
import {
  createRouterAbEd25519YaoHttpRegistrationBackendFromEnv,
  parseRouterAbEd25519YaoActivationKeysetFromEnvV1,
  type RouterAbEd25519YaoGatewaySpanV1,
} from '@seams/sdk-server/cloud-host';
import { type RouterAbEd25519YaoProductRegistrationRuntimeV1 } from '@seams/sdk-server/cloud-host';
import type { SessionAdapter } from '@seams/sdk-server/cloud-host';
import { D1WalletStore } from '@seams/sdk-server/cloud-host';
import { CloudflareD1RouterAbEd25519YaoCapabilityPersistence } from '@seams/sdk-server/cloud-host';
import {
  createRouterAbEcdsaEd25519CeremonyTokenIssuer,
  createRouterAbEcdsaStrictPostRegistrationPort,
  createRouterAbEcdsaStrictRegistrationPort,
  parseRouterAbEcdsaEd25519PrivateJwk,
  parseRouterAbEcdsaStrictRegistrationTopology,
  type RouterAbEcdsaCeremonyTokenIssuer,
  type RouterAbEcdsaStrictRegistrationTopology,
} from '@seams/sdk-server/cloud-host';
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
} from '@seams/sdk-server/cloud-host';
import { parseWalletId } from '@seams/sdk-server/cloud-host';
import { normalizeLogger, parseWebAuthnRpId } from '@seams/sdk-server/cloud-host';
import {
  createRouterAbServiceBindingFetch,
  ROUTER_AB_MPC_ROUTER_ORIGIN,
  ROUTER_AB_SIGNING_WORKER_ORIGIN,
  type RouterAbServiceBindingEnv,
} from './routerAbServiceBindings';
import { handleRouterAbEd25519YaoRegistrationRequestScopedCloudflareV1 } from '@seams/sdk-server/cloud-host';
import { createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreFromD1V1 } from '@seams/sdk-server/cloud-host';
import { RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter } from '@seams/sdk-server/cloud-host';
import { RouterAbEd25519YaoExportOwnerProofAuthorizationAdapter } from '@seams/sdk-server/cloud-host';
import { createRouterAbEd25519YaoProductRegistrationRequestScopedRuntimeV1 } from '@seams/sdk-server/cloud-host';
import { createD1LinkedDeviceTargetDeploymentDescriptorRuntimeV1 } from '@seams/sdk-server/cloud-host';
import {
  base64UrlEncode,
  sha256Bytes,
  buildSigningWorkerParticipantRecordWithDigestV1,
  parseHpkePublicKeyB64u,
  parseSigningWorkerParticipantId,
  parseSigningWorkerRecipientKeyDigestB64u,
  parseSigningWorkerRecipientKeyId,
} from '@seams/sdk-server/cloud-host';
import { handleRouterAbEd25519YaoRecoveryRequestScopedCloudflareV1 } from '@seams/sdk-server/cloud-host';
import { handleRouterAbEd25519YaoExportRequestScopedCloudflareV1 } from '@seams/sdk-server/cloud-host';
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
} from '@seams/sdk-server/cloud-host';
import { createCloudflareCron, resolveCloudflareConsoleEmailDispatchCronOptions } from './cron';
import type { RouterApiCloudflareConsoleWorkerEnv } from './cloudflareConsole.types';
import { resolveEmailOtpDeliveryProviderFromEnv } from '../../email/otp/emailOtpProviders';

interface CloudflareD1RouterApiStagingEnv
  extends
    CloudflareD1StagingSessionEnv,
    RouterAbServiceBindingEnv,
    RouterApiCloudflareConsoleWorkerEnv {
  readonly CONSOLE_DB: D1DatabaseLike;
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
  readonly LINKED_DEVICE_WEBAUTHN_ORIGIN?: string;
  readonly LINKED_DEVICE_OPERATOR_RECOVERY_SECRET?: string;
  readonly LINKED_DEVICE_TARGET_DESCRIPTOR_HMAC_SECRET?: string;
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
  'linked_device_wallet_session_authorizations',
  'linked_device_wallet_session_quotas',
  'linked_device_sessions',
  'linked_device_session_transcripts',
  'linked_device_request_proof_nonces',
  'linked_device_target_credentials',
  'linked_device_target_commit_reservations',
  'linked_device_provisioning_records',
  'linked_device_source_handoffs',
  'linked_device_owner_planning_snapshots',
  'linked_device_target_deployment_descriptors',
]);

const ROUTER_AB_CEREMONY_JWKS_PATH = '/.well-known/router-ab-ceremony-jwks.json';

function emitRefactor93GatewaySpan(span: RouterAbEd25519YaoGatewaySpanV1): void {
  console.log(JSON.stringify(span));
}

export function createStagingEd25519YaoBackend(env: CloudflareD1RouterApiStagingEnv) {
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

function stagingTenantScope(env: CloudflareD1RouterApiStagingEnv): RouterApiTenantScope {
  return {
    namespace: requireEnvString(env, 'SEAMS_TENANT_STORAGE_NAMESPACE'),
    orgId: requireEnvString(env, 'SEAMS_STAGING_ORG_ID'),
    projectId: requireEnvString(env, 'SEAMS_STAGING_PROJECT_ID'),
    envId: requireEnvString(env, 'SEAMS_STAGING_ENV_ID'),
  };
}

async function createStagingRouterApiAuthComposition(
  env: CloudflareD1RouterApiStagingEnv,
  scope: RouterApiTenantScope,
  session: SessionAdapter,
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
    linkedDevice: await stagingLinkedDeviceComposition(env, session),
  });
  return { service, ecdsaStrictPostRegistration };
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
    },
  });
  const session = stagingSessionAdapter(env);
  const yaoRuntime = createStagingYaoRequestScopedRuntime(env);
  const { service, ecdsaStrictPostRegistration } = await createStagingRouterApiAuthComposition(
    env,
    scope,
    session,
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
  const consoleAuth = createConsoleSessionAuthAdapter({
    session: createHmacSessionAdapterFromEnv({
      env,
      secretName: 'RELAY_SESSION_HMAC_SECRET',
      cookieName: readEnvString(env, 'CONSOLE_SESSION_COOKIE_NAME'),
      issuer: readEnvString(env, 'CONSOLE_SESSION_ISSUER'),
      audience: readEnvString(env, 'CONSOLE_SESSION_AUDIENCE'),
    }),
    organizationAccess: bundle.organizationAccess,
    defaultOrgId: scope.orgId,
    defaultProjectId: scope.projectId,
    defaultEnvironmentId: scope.envId,
    platformSupportEmails: readEnvString(env, 'CONSOLE_PLATFORM_SUPPORT_EMAILS'),
  });
  const consoleHandler = createCloudflareConsoleRouter({
    ...bundle.consoleRouterOptions,
    healthz: true,
    readyz: true,
    corsOrigins: readCsvList(env.RELAY_CORS_ORIGINS),
    auth: consoleAuth,
    readyCheck: createRouterApiReadyCheck(env),
    billingStripeWebhookSigningSecret: readEnvString(env, 'STRIPE_WEBHOOK_SECRET'),
  });
  return dispatchHostedGatewayRequest.bind(null, consoleHandler, routerApiHandler);
}

function stagingLinkedDeviceExecution(env: CloudflareD1RouterApiStagingEnv) {
  const rpId = parseWebAuthnRpId(requireEnvString(env, 'LINKED_DEVICE_WEBAUTHN_RP_ID'));
  if (!rpId.ok) throw new Error(rpId.error.message);
  return {
    nowV1: Date.now,
    rpId: rpId.value,
    expectedOrigin: requireEnvString(env, 'LINKED_DEVICE_WEBAUTHN_ORIGIN'),
    logger: normalizeLogger(),
  };
}

async function stagingLinkedDeviceComposition(
  env: CloudflareD1RouterApiStagingEnv,
  session: SessionAdapter,
) {
  const internalServiceAuth = requireEnvString(env, 'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET');
  const scope = stagingTenantScope(env);
  const operatorRecoverySecret = stagingLinkedDeviceOperatorRecoverySecret(
    env,
    internalServiceAuth,
  );
  const descriptorHmacSecret = requireEnvString(env, 'LINKED_DEVICE_TARGET_DESCRIPTOR_HMAC_SECRET');
  if (
    descriptorHmacSecret === internalServiceAuth ||
    descriptorHmacSecret === operatorRecoverySecret
  ) {
    throw new Error(
      'LINKED_DEVICE_TARGET_DESCRIPTOR_HMAC_SECRET must differ from Router internal auth and operator recovery',
    );
  }
  const targetRuntime = await createD1LinkedDeviceTargetDeploymentDescriptorRuntimeV1({
    database: env.SIGNER_DB,
    scope,
    targetSigningWorker: await stagingLinkedDeviceTargetSigningWorker(env),
    descriptorHmacSecret,
    ed25519: {
      yaoSuiteId: 'ed25519-yao-suite:A',
      circuitDigestB64u: 'uojcq1xwowjW5QC2ZkQk0aevJmiiHYdJh41CtSpIaRk',
    },
  });
  return {
    execution: stagingLinkedDeviceExecution(env),
    session: {
      session,
      laneRuntime: {
        router: env.MPC_ROUTER,
        signingWorker: env.SIGNING_WORKER,
        internalServiceAuth,
        ed25519YaoKeyset: stagingEd25519YaoActivationKeyset(env),
      },
      operatorRecovery: {
        operatorSecret: operatorRecoverySecret,
      },
      targetDeploymentDescriptorProvider: targetRuntime.provider,
    },
    management: {},
  };
}

async function stagingLinkedDeviceTargetSigningWorker(env: CloudflareD1RouterApiStagingEnv) {
  const participantId = requireEnvString(env, 'SIGNING_WORKER_ID');
  const keyset = stagingEd25519YaoActivationKeyset(env);
  const hpkePublicKey = new Uint8Array(keyset.signing_worker_recipient_public_key);
  const hpkePublicKeyB64u = base64UrlEncode(hpkePublicKey);
  const parsedParticipantId = parseSigningWorkerParticipantId(participantId);
  if (!parsedParticipantId.ok) throw new Error(parsedParticipantId.error.message);
  const recipientKeyId =
    requireStagingRouterAbPublicKeyset(env).signing_worker_server_output_hpke.key_epoch;
  const parsedRecipientKeyId = parseSigningWorkerRecipientKeyId(recipientKeyId);
  if (!parsedRecipientKeyId.ok) throw new Error(parsedRecipientKeyId.error.message);
  const parsedHpkePublicKeyB64u = parseHpkePublicKeyB64u(hpkePublicKeyB64u);
  if (!parsedHpkePublicKeyB64u.ok) {
    throw new Error(parsedHpkePublicKeyB64u.error.message);
  }
  const hpkePublicKeyDigestB64u = base64UrlEncode(await sha256Bytes(hpkePublicKey));
  const parsedHpkePublicKeyDigestB64u =
    parseSigningWorkerRecipientKeyDigestB64u(hpkePublicKeyDigestB64u);
  if (!parsedHpkePublicKeyDigestB64u.ok) {
    throw new Error(parsedHpkePublicKeyDigestB64u.error.message);
  }
  const participant = await buildSigningWorkerParticipantRecordWithDigestV1({
    participantId: parsedParticipantId.value,
    recipient: {
      kind: 'signing_worker_recipient_identity_v1',
      recipientKeyId: parsedRecipientKeyId.value,
      hpkePublicKeyB64u: parsedHpkePublicKeyB64u.value,
      hpkePublicKeyDigestB64u: parsedHpkePublicKeyDigestB64u.value,
    },
  });
  return {
    participantId: participant.participantId,
    participantBindingDigestB64u: participant.participantBindingDigestB64u,
    recipientKeyId: participant.recipientKeyId,
    hpkePublicKeyB64u: participant.hpkePublicKeyB64u,
    hpkePublicKeyDigestB64u: participant.hpkePublicKeyDigestB64u,
  };
}

function stagingLinkedDeviceOperatorRecoverySecret(
  env: CloudflareD1RouterApiStagingEnv,
  internalServiceAuth: string,
): string {
  const secret = requireEnvString(env, 'LINKED_DEVICE_OPERATOR_RECOVERY_SECRET');
  if (secret === internalServiceAuth) {
    throw new Error('LINKED_DEVICE_OPERATOR_RECOVERY_SECRET must differ from Router internal auth');
  }
  return secret;
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
  env: CloudflareD1RouterApiStagingEnv,
): RouterAbPublicKeysetV2 {
  const source = requireEnvString(env, 'ROUTER_AB_PUBLIC_KEYSET_JSON');
  const parsed = parseJsonObject(source);
  if (!parsed) {
    throw new Error('ROUTER_AB_PUBLIC_KEYSET_JSON must contain a JSON object');
  }
  return parseRouterAbPublicKeysetV2(parsed);
}

function stagingEd25519YaoKeyEnvironment(env: CloudflareD1RouterApiStagingEnv) {
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

function stagingEd25519YaoActivationKeyset(env: CloudflareD1RouterApiStagingEnv) {
  return parseRouterAbEd25519YaoActivationKeysetFromEnvV1(stagingEd25519YaoKeyEnvironment(env));
}

function createStagingEcdsaCeremonyTokenIssuer(
  env: CloudflareD1RouterApiStagingEnv,
): RouterAbEcdsaCeremonyTokenIssuer {
  return createRouterAbEcdsaEd25519CeremonyTokenIssuer({
    issuer: requireEnvString(env, 'ROUTER_AB_CEREMONY_JWT_ISSUER'),
    audience: requireEnvString(env, 'ROUTER_AB_CEREMONY_JWT_AUDIENCE'),
    keyId: requireEnvString(env, 'ROUTER_AB_CEREMONY_JWT_KEY_ID'),
    privateJwk: requireStagingEcdsaCeremonyPrivateJwk(env),
  });
}

function requireStagingEcdsaCeremonyPrivateJwk(env: CloudflareD1RouterApiStagingEnv) {
  const privateJwkSource = requireEnvString(env, 'ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK');
  const privateJwk = parseRouterAbEcdsaEd25519PrivateJwk(parseJsonObject(privateJwkSource));
  if (!privateJwk) {
    throw new Error('ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK must be an Ed25519 private JWK');
  }
  return privateJwk;
}

function requireStagingEcdsaRegistrationTopology(
  env: CloudflareD1RouterApiStagingEnv,
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

function routerAbCeremonyJwksResponse(env: CloudflareD1RouterApiStagingEnv): Response {
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
    CloudflareD1RouterApiStagingEnv,
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
  env: CloudflareD1RouterApiStagingEnv,
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
    CloudflareD1RouterApiStagingEnv,
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

function stagingGithubOAuthConfig(env: CloudflareD1RouterApiStagingEnv) {
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

function normalizeString(input: unknown): string {
  return String(input || '').trim();
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
    CloudflareD1RouterApiStagingEnv,
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
  env: CloudflareD1RouterApiStagingEnv,
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
    case 'export_execute':
      {
      const scope = stagingTenantScope(env);
      const session = stagingSessionAdapter(env);
      const yaoRuntime = createStagingYaoRequestScopedRuntime(env);
      const { service } = await createStagingRouterApiAuthComposition(
        env,
        scope,
        session,
        yaoRuntime,
      );
      return await handleRouterAbEd25519YaoExportRequestScopedCloudflareV1({
        request,
        ...createStagingExportRequestScopedDependencies(env, service),
      });
      }
  }
}

function createStagingYaoPartitionedStateStore(
  env: CloudflareD1RouterApiStagingEnv,
): ReturnType<typeof createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreFromD1V1> {
  const scope = stagingTenantScope(env);
  return createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreFromD1V1({
    database: env.SIGNER_DB,
    scope,
  });
}

async function loadStagingPersistedActiveCapability(
  env: CloudflareD1RouterApiStagingEnv,
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
  env: CloudflareD1RouterApiStagingEnv,
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
export function createStagingRecoveryRequestScopedDependencies(
  env: CloudflareD1RouterApiStagingEnv,
): {
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
    authorization: new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(
      session,
      async () => {
        const yaoRuntime = createStagingYaoRequestScopedRuntime(env);
        const { service } = await createStagingRouterApiAuthComposition(
          env,
          scope,
          session,
          yaoRuntime,
        );
        return service.authorizationSessions;
      },
    ),
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
  env: CloudflareD1RouterApiStagingEnv,
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
    ),
    capabilities: createStagingYaoRequestScopedRuntime(env),
  };
}

function stagingSessionAdapter(env: CloudflareD1RouterApiStagingEnv) {
  return createEd25519SessionAdapter({
    privateJwk: requireStagingEcdsaCeremonyPrivateJwk(env),
    keyId: requireEnvString(env, 'ROUTER_AB_CEREMONY_JWT_KEY_ID'),
    cookieName: readEnvString(env, 'SESSION_COOKIE_NAME'),
    issuer: requireEnvString(env, 'ROUTER_AB_CEREMONY_JWT_ISSUER'),
    audience: requireEnvString(env, 'ROUTER_AB_CEREMONY_JWT_AUDIENCE'),
  });
}

function stagingWalletStore(env: CloudflareD1RouterApiStagingEnv): D1WalletStore {
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
