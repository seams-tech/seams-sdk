import {
  MinimalNearClient,
  type AccessKeyList,
} from '../rpcClients/near/NearClient';
import type { FinalExecutionOutcome } from '@near-js/types';
import { createAuthServiceConfig } from '../config';
import { formatGasToTGas, formatYoctoToNear } from '../utils';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  parseRouterAbEd25519NormalSigningState,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '@shared/utils/emailOtpDomain';
import type { ThresholdSigningService as ThresholdSigningServiceType } from '../ThresholdService';
import {
  createThresholdSigningService,
  ensureThresholdEd25519HssWasm,
} from '../ThresholdService';
import { sha256BytesUtf8 } from '@shared/utils/digests';

import type {
  AuthServiceConfig,
  AuthServiceConfigInput,
  AccountCreationRequest,
  AccountCreationResult,
  FundImplicitNearAccountRequest,
  FundImplicitNearAccountResult,
  ThresholdRuntimePolicyScope,
  EcdsaHssClientBootstrapRequest,
  EcdsaHssExportShareRequest,
  EcdsaHssExportShareResponse,
  EcdsaHssRouteResult,
  EcdsaHssServerBootstrapResponse,
  WebAuthnAuthenticationCredential,
  WalletRegistrationFinalizeRequest,
  WalletRegistrationPrepareRequest,
} from '../types';
import { type RouterAbEcdsaHssWalletSessionClaims } from '../ThresholdService/validation';
import type { GoogleEmailOtpResolutionResult } from './googleEmailOtpRegistration';
export type {
  GoogleEmailOtpRegistrationOffer,
  GoogleEmailOtpRegistrationOfferCandidate,
  GoogleEmailOtpResolutionMode,
  GoogleEmailOtpResolutionResult,
} from './googleEmailOtpRegistration';

import { EMAIL_DKIM_VERIFIER_CONTRACT_DEFAULT } from '../defaultConfigsServer';
import { EmailRecoveryService } from '../../email-recovery';
import type { SignedDelegate } from '@shared/near/delegate';
import {
  parseWebAuthnRpId,
  type GoogleProviderSubject,
  type VerifiedGoogleEmail,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import type { RegistrationSignerPlan } from '@shared/utils/registrationIntent';
import type { StoredRegistrationIntent } from '../RegistrationCeremonyStore';
import { type DelegateActionPolicy, type ExecuteSignedDelegateResult } from '../../delegateAction';
import { coerceLogger, type NormalizedLogger } from '../logger';
import {
  createWebAuthnSyncAccountOptionsWithStores,
  createWebAuthnLoginOptionsWithStore,
  listWebAuthnAuthenticatorsForUserWithStores,
  verifyWebAuthnAuthenticationLiteWithStore,
  verifyWebAuthnLoginWithStores,
  verifyWebAuthnRegistrationCredentialForIntent,
  verifyWebAuthnSyncAccountWithStores,
  type WebAuthnSyncAccountVerificationRequest,
  type WebAuthnSyncAccountVerificationResult,
  type WebAuthnSyncAccountOptionsResult,
} from './webauthn';
import { randomBase64Url, randomOpaqueId } from './bytes';
import {
  isAuthServiceProductionEnvironment,
  readAuthServiceConfigValue,
  type AuthServiceConfigSource,
} from './configValues';
import {
  resolveEmailOtpConfig as resolveEmailOtpConfigFromSource,
  resolveEmailOtpRateLimitPolicies as resolveEmailOtpRateLimitPoliciesFromSource,
  resolveRegistrationPrepareRateLimitPolicy as resolveRegistrationPrepareRateLimitPolicyFromSource,
} from './emailOtpConfig';
import {
  deliverEmailOtpCode as deliverEmailOtpCodeWithDeps,
  readEmailOtpOutboxEntry as readEmailOtpOutboxEntryWithDeps,
  type EmailOtpMemoryOutbox,
  type EmailOtpOutboxReadResult,
} from './emailOtpDelivery';
import {
  createEmailOtpChallengeWithAction as createEmailOtpChallengeWithActionWithStores,
  pruneExpiredEmailOtpChallengesWithStore,
  type CreateEmailOtpChallengeWithActionResult,
} from './emailOtpChallenges';
import {
  createEmailOtpChallenge as createEmailOtpChallengeOperation,
  createEmailOtpDeviceRecoveryChallenge as createEmailOtpDeviceRecoveryChallengeOperation,
  createEmailOtpEnrollmentChallenge as createEmailOtpEnrollmentChallengeOperation,
  verifyEmailOtpChallenge as verifyEmailOtpChallengeOperation,
  verifyEmailOtpDeviceRecoveryChallenge as verifyEmailOtpDeviceRecoveryChallengeOperation,
  type EmailOtpChallengeOperationsInput,
} from './emailOtpChallengeOperations';
import {
  verifyEmailOtpChallengeCode as verifyEmailOtpChallengeCodeWithStores,
} from './emailOtpChallengeVerification';
import {
  verifyEmailOtpEnrollment as verifyEmailOtpEnrollmentWithStores,
} from './emailOtpRegistrationEnrollment';
import {
  consumeEmailOtpRecoveryKey as consumeEmailOtpRecoveryKeyWithStores,
  getEmailOtpRecoveryCodeStatus as getEmailOtpRecoveryCodeStatusWithStores,
  recordEmailOtpRecoveryKeyAttemptFailure as recordEmailOtpRecoveryKeyAttemptFailureWithStores,
  rotateEmailOtpRecoveryKeys as rotateEmailOtpRecoveryKeysWithStores,
  type EmailOtpRecoveryCodeStatusRequest,
  type EmailOtpRecoveryCodeStatusResult,
  type EmailOtpRecoveryKeyAttemptFailureRequest,
  type EmailOtpRecoveryKeyAttemptFailureResult,
  type EmailOtpRecoveryKeyConsumeRequest,
  type EmailOtpRecoveryKeyConsumeResult,
  type EmailOtpRecoveryKeysRotateRequest,
  type EmailOtpRecoveryKeysRotateResult,
} from './emailOtpRecoveryKeys';
import { EmailRecoveryAuthOperations } from './emailRecoveryAuthOperations';
import {
  createEmailOtpUnlockChallenge as createEmailOtpUnlockChallengeWithStores,
  verifyEmailOtpUnlockProof as verifyEmailOtpUnlockProofWithStores,
} from './emailOtpUnlock';
import {
  buildVerifiedEmailOtpRegistrationChallengeProof,
  emailOtpChallengeVerificationIntentFromRequest,
  emailOtpStoredChallengePurposeMatches,
  expectedEmailOtpStoredChallengePurpose,
  parseRawEmailOtpRegistrationChallengeProofInput,
  readEmailOtpStoredChallengePurpose,
  type EmailOtpChallengeBindingMismatchCode,
  type EmailOtpRecoveryChallengeEscrow,
  type EmailOtpRegistrationChallengeProof,
  type EmailOtpRegistrationChallengeProofInput,
  type EmailOtpRegistrationChallengeProofResult,
  type EmailOtpRegistrationEnrollmentPersistence,
  type VerifiedEmailOtpChallengeCodeResult,
  type VerifiedEmailOtpChallengeCodeSuccessBase,
} from './emailOtpChallengeProof';
import {
  createEmailOtpShamirCipherFromConfig,
  runEmailOtpServerSealOperation,
  type EmailOtpServerSealRequest,
  type EmailOtpServerSealResult,
} from './emailOtpSeal';
import {
  isEmailOtpStrongAuthRequiredWithStores,
  markEmailOtpStrongAuthSatisfiedWithStores,
  putEmailOtpAuthStateForEnrollmentWithStore,
  readActiveEmailOtpEnrollmentWithStore,
  readEmailOtpAuthStateForEnrollmentWithStore,
  readEmailOtpEnrollmentWithStore,
  type EmailOtpAuthStatePatch,
  type EmailOtpAuthStateReadResult,
  type EmailOtpEnrollmentReadResult,
  type EmailOtpStrongAuthRequiredResult,
  type EmailOtpStrongAuthSatisfiedResult,
} from './emailOtpEnrollment';
import {
  consumeEmailOtpGrantWithStore,
  type EmailOtpGrantConsumeRequest,
  type EmailOtpGrantConsumeResult,
} from './emailOtpGrant';
import {
  cleanupGoogleEmailOtpRegistrationAttemptsWithStore,
} from './googleEmailOtpRegistration';
import {
  cleanupGoogleEmailOtpDevRegistrationStateForAuthService,
  completeGoogleEmailOtpRegistrationAttemptForAuthService,
  consumeGoogleEmailOtpRegistrationAttemptRateLimitForAuthService,
  failGoogleEmailOtpRegistrationAttemptForAuthService,
  recordGoogleEmailOtpRegistrationAttemptPublicKeyForAuthService,
  resolveGoogleEmailOtpSessionForAuthService,
  resolveOidcWalletIdWithGoogleEmailOtp,
  validateGoogleEmailOtpRegistrationCandidateWalletForAuthService,
  type GoogleEmailOtpOperationsInput,
} from './googleEmailOtpOperations';
import {
  consumeEmailOtpRateLimit as consumeEmailOtpRateLimitWithDeps,
  consumeRegistrationPrepareRateLimit as consumeRegistrationPrepareRateLimitWithDeps,
} from './rateLimits';
import { isObject } from './record';
import { summarizeThresholdStoreConfig } from './thresholdStoreSummary';
import {
  listThresholdEcdsaKeyIdentityTargetsForUser as listThresholdEcdsaKeyIdentityTargetsForUserWithDeps,
  type ThresholdEcdsaKeyInventoryDiagnostics,
  type ThresholdEcdsaKeyInventoryRecord,
} from './thresholdEcdsaKeyInventory';
import {
  ecdsaHssRoleLocalBootstrapWithThreshold,
  ecdsaHssRoleLocalExportShareWithThreshold,
  verifyEcdsaHssRoleLocalClientRootProofForExistingKeyWithThreshold,
} from './thresholdEcdsaOperations';
import { normalizeThresholdRuntimePolicyScope } from './thresholdRuntimePolicy';
import {
  buildEcdsaWalletKeysFromBootstrap,
  toEcdsaHssClientBootstrapRequest,
} from './registrationThresholdHelpers';
import {
  createGoogleJwksState,
  createOidcJwksState,
  verifyGoogleLoginWithIdentityStore,
  verifyOidcJwtExchangeWithIdentityStore,
  type GoogleLoginFacadeResult,
  type OidcJwtExchangeFacadeResult,
} from './oidcVerification';
import type {
  AppSessionVersionMutationResult,
  AppSessionVersionValidationResult,
  ListIdentitiesResult,
} from './identity';
import {
  isNodeEnvironment as isAuthServiceNodeEnvironment,
} from './wasm';
import {
  createInitialAuthServiceRuntimeState,
  ensureAuthServiceRuntimeReady,
  ensureAuthServiceSignerWasmReady,
  type AuthServiceRuntimeState,
} from './runtime';
import { AuthServiceStoreRegistry } from './storeRegistry';
import { NearAccountOperations } from './nearAccountOperations';
import { IdentityOperations } from './identityOperations';
import { RecoveryTrackingOperations } from './recoveryTrackingOperations';

import {
  type EmailOtpWalletEnrollmentRecord,
  type EmailOtpAuthStateRecord,
  type EmailOtpChannel,
  type EmailOtpChallengeAction,
  type EmailOtpChallengeOperation,
  type EmailOtpChallengeStore,
  type EmailOtpLoginChallengeOperation,
} from '../EmailOtpStores';
import {
  validateSecp256k1PublicKey33,
  verifySecp256k1RecoverableSignatureAgainstPublicKey33,
} from '../ThresholdService/ethSignerWasm';
import { type NearPublicKeyKind } from '../NearPublicKeyStore';
import {
  listNearPublicKeysForUserWithStore,
  recordNearPublicKeyMetadataWithStore,
  type ListNearPublicKeysResult,
  type RecordNearPublicKeyMetadataResult,
} from './nearPublicKeyMetadata';
import type { RecoverySessionStatus } from '../RecoverySessionStore';
import { type RecoveryExecutionStatus } from '../RecoveryExecutionStore';
import {
  type GetRecoveryExecutionResult,
  type GetRecoverySessionResult,
  type ListRecoveryExecutionsResult,
  type RecordRecoveryExecutionResult,
  type UpdateRecoverySessionStatusResult,
} from './recoveryTracking';
import { type LinkIdentityResult, type UnlinkIdentityResult } from '../IdentityStore';
import type { ThresholdEcdsaChainTarget } from '../thresholdEcdsaChainTarget';
import {
  buildPreparedRecoverySessionRecord,
  DEFAULT_RECOVERY_SESSION_TTL_MS,
} from '../recoverySessionRecords';

const REGISTRATION_WALLET_SIGNING_SESSION_REMAINING_USES = 3;

function assertNever(value: never): never {
  throw new Error(`Unexpected variant: ${JSON.stringify(value)}`);
}

/**
 * Framework-agnostic NEAR account service
 * Core business logic for account creation and registration operations
 */
export class AuthService {
  private config: AuthServiceConfig;
  private nearClient: MinimalNearClient;
  private runtimeState: AuthServiceRuntimeState = createInitialAuthServiceRuntimeState();
  private readonly logger: NormalizedLogger;
  private readonly stores: AuthServiceStoreRegistry;
  private readonly nearAccounts: NearAccountOperations;
  private thresholdSigningServiceInitialized = false;
  private thresholdSigningService: ThresholdSigningServiceType | null = null;
  private readonly emailOtpMemoryOutbox: EmailOtpMemoryOutbox = new Map();
  private registrationRuntimeWarmPromise: Promise<void> | null = null;
  private readonly googleJwksState = createGoogleJwksState();
  private readonly oidcJwksState = createOidcJwksState();

  // DKIM/TEE email recovery logic (delegated to EmailRecoveryService)
  public readonly emailRecovery: EmailRecoveryService | null = null;

  constructor(config: AuthServiceConfigInput) {
    this.config = createAuthServiceConfig(config);
    this.logger = coerceLogger(this.config.logger);
    this.nearClient = new MinimalNearClient(this.config.nearRpcUrl);
    this.stores = new AuthServiceStoreRegistry({
      config: this.config,
      logger: this.logger,
      isNode: this.isNodeEnvironment.bind(this),
    });
    this.nearAccounts = new NearAccountOperations({
      config: this.config,
      nearClient: this.nearClient,
      logger: this.logger,
      ensureSignerAndRelayerAccount: this._ensureSignerAndRelayerAccount.bind(this),
      ensureSignerWasm: this.ensureSignerWasm.bind(this),
      getRelayerPublicKey: () => this.runtimeState.relayerPublicKey,
    });
    this.emailRecovery = new EmailRecoveryService({
      relayerAccount: this.config.relayerAccount,
      networkId: this.config.networkId,
      emailDkimVerifierContract: EMAIL_DKIM_VERIFIER_CONTRACT_DEFAULT,
      nearClient: this.nearClient,
      logger: this.config.logger,
      ensureSignerAndRelayerAccount: () => this._ensureSignerAndRelayerAccount(),
      queueTransaction: <T>(fn: () => Promise<T>, label: string) =>
        this.nearAccounts.queueTransaction(fn, label),
      fetchTxContext: (accountId: string, publicKey: string) =>
        this.nearAccounts.fetchTxContext(accountId, publicKey),
      signGasRelayerNearTransaction: (input) =>
        this.nearAccounts.signGasRelayerNearTransaction(input),
      getRelayerPublicKey: () => this.runtimeState.relayerPublicKey,
    });

    // Log effective configuration at construction time so operators can
    // verify wiring immediately when the service is created.
    this.logger.info(`
    AuthService initialized with:
    • networkId: ${this.config.networkId}
    • nearRpcUrl: ${this.config.nearRpcUrl}
    • relayerAccount: ${this.config.relayerAccount}
    • accountInitialBalance: ${this.config.accountInitialBalance} (${formatYoctoToNear(this.config.accountInitialBalance)} NEAR)
    • createAccountAndRegisterGas: ${this.config.createAccountAndRegisterGas} (${formatGasToTGas(this.config.createAccountAndRegisterGas)})
    • ${summarizeThresholdStoreConfig(this.config.thresholdStore)}
    ${
      this.config.googleOidc?.clientIds?.length
        ? `• googleOidc: ${this.config.googleOidc.clientIds.length} clientId(s)`
        : `• googleOidc: not configured`
    }
    ${
      this.config.oidcExchange?.issuers?.length
        ? `• oidcExchange: ${this.config.oidcExchange.issuers.length} issuer(s)`
        : `• oidcExchange: not configured`
    }
    `);
  }

  async getRelayerAccount(): Promise<{ accountId: string; publicKey: string }> {
    await this._ensureSignerAndRelayerAccount();
    return {
      accountId: this.config.relayerAccount,
      publicKey: this.runtimeState.relayerPublicKey,
    };
  }

  /**
   * Lightweight config accessor (no RPC) for diagnostics and well-known endpoints.
   * This is safe to call even when the relayer account has not been warmed/validated yet.
   */
  getConfiguredRelayerAccount(): string {
    return this.config.relayerAccount;
  }

  isGoogleOidcConfigured(): boolean {
    return Boolean(this.config.googleOidc?.clientIds?.length);
  }

  getGoogleOidcPublicConfig(): { configured: boolean; clientId?: string } {
    const clientId = String(this.config.googleOidc?.clientIds?.[0] || '').trim();
    return {
      configured: Boolean(clientId),
      ...(clientId ? { clientId } : {}),
    };
  }

  private async consumeGoogleEmailOtpRegistrationRateLimitScope(input: {
    scope: 'googleRegistrationAttempt';
    action:
      | 'google_email_otp_registration_create'
      | 'google_email_otp_registration_offer_restart';
    userId?: string;
    providerSubject: string;
    orgId: string;
    clientIp?: string;
  }) {
    return await this.consumeEmailOtpRateLimit(input);
  }

  private googleEmailOtpOperationsInput(): GoogleEmailOtpOperationsInput {
    return {
      config: this.config,
      identityStore: this.stores.getIdentityStore(),
      registrationAttemptStore: this.stores.getEmailOtpRegistrationAttemptStore(),
      walletEnrollmentStore: this.stores.getEmailOtpWalletEnrollmentStore(),
      readConfigValue: this.readConfigValue.bind(this),
      isProductionEnvironment: this.isProductionEnvironment(),
      consumeRateLimit: this.consumeGoogleEmailOtpRegistrationRateLimitScope.bind(this),
    };
  }

  async resolveOidcWalletId(input: {
    providerSubject?: string;
    sub?: string;
    email?: string;
    accountMode?: unknown;
    appSessionVersion?: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    restartRegistrationOffer?: unknown;
  }): Promise<string> {
    return await resolveOidcWalletIdWithGoogleEmailOtp({
      deps: this.googleEmailOtpOperationsInput(),
      request: input,
    });
  }

  private async cleanupGoogleEmailOtpRegistrationAttempts(nowMs = Date.now()): Promise<void> {
    await cleanupGoogleEmailOtpRegistrationAttemptsWithStore({
      registrationAttemptStore: this.stores.getEmailOtpRegistrationAttemptStore(),
      nowMs,
    });
  }

  async consumeGoogleEmailOtpRegistrationAttemptRateLimit(input: {
    providerSubject?: unknown;
    email?: unknown;
    accountMode?: unknown;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    clientIp?: string;
    appSessionUserId?: string;
    restartRegistrationOffer?: unknown;
  }): Promise<
    | { ok: true }
    | {
        ok: false;
        code: 'invalid_body' | 'rate_limited';
        message: string;
        retryAfterMs?: number;
        resetAtMs?: number;
      }
  > {
    return await consumeGoogleEmailOtpRegistrationAttemptRateLimitForAuthService({
      deps: this.googleEmailOtpOperationsInput(),
      request: input,
    });
  }

  async resolveGoogleEmailOtpSession(input: {
    providerSubject?: string | GoogleProviderSubject;
    sub?: string;
    email?: string | VerifiedGoogleEmail;
    accountMode?: unknown;
    appSessionVersion?: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    restartRegistrationOffer?: unknown;
  }): Promise<GoogleEmailOtpResolutionResult> {
    return await resolveGoogleEmailOtpSessionForAuthService({
      deps: this.googleEmailOtpOperationsInput(),
      request: input,
    });
  }

  async completeGoogleEmailOtpRegistrationAttempt(input: {
    registrationAttemptId?: unknown;
    walletId?: unknown;
  }): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    return await completeGoogleEmailOtpRegistrationAttemptForAuthService({
      deps: this.googleEmailOtpOperationsInput(),
      request: input,
    });
  }

  async validateGoogleEmailOtpRegistrationCandidateWallet(input: {
    registrationAttemptId: string;
    walletId: string;
    appSessionVersion: string;
    providerSubject: string;
  }): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    return await validateGoogleEmailOtpRegistrationCandidateWalletForAuthService({
      deps: this.googleEmailOtpOperationsInput(),
      request: input,
    });
  }

  async recordGoogleEmailOtpRegistrationAttemptPublicKey(input: {
    registrationAttemptId?: unknown;
    walletId?: unknown;
    finalizedPublicKey?: unknown;
  }): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    return await recordGoogleEmailOtpRegistrationAttemptPublicKeyForAuthService({
      deps: this.googleEmailOtpOperationsInput(),
      request: input,
    });
  }

  async failGoogleEmailOtpRegistrationAttempt(input: {
    registrationAttemptId?: unknown;
    walletId?: unknown;
    failureCode?: unknown;
  }): Promise<void> {
    await failGoogleEmailOtpRegistrationAttemptForAuthService({
      deps: this.googleEmailOtpOperationsInput(),
      request: input,
    });
  }

  async cleanupGoogleEmailOtpDevRegistrationState(input: {
    providerSubject?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    nowMs?: unknown;
  }): Promise<
    | {
        ok: true;
        providerSubject: string;
        expiredRegistrationAttemptsDeleted: number;
        linkedWalletId?: string;
        orphanedWalletMappingRemoved: boolean;
        orphanedWalletMappingSkippedReason?:
          | 'no_linked_wallet'
          | 'wallet_id_mismatch'
          | 'not_relayer_subaccount'
          | 'active_email_otp_enrollment'
          | 'mismatched_email_otp_enrollment';
      }
    | { ok: false; code: string; message: string }
  > {
    return await cleanupGoogleEmailOtpDevRegistrationStateForAuthService({
      deps: this.googleEmailOtpOperationsInput(),
      request: input,
    });
  }

  isOidcExchangeConfigured(): boolean {
    return Boolean(this.config.oidcExchange?.issuers?.length);
  }

  async warmRegistrationRuntime(): Promise<void> {
    if (this.registrationRuntimeWarmPromise) return this.registrationRuntimeWarmPromise;

    this.registrationRuntimeWarmPromise = (async () => {
      const warmStartedAt = Date.now();
      const relayerWarmStartedAt = Date.now();
      await this.getRelayerAccount();
      this.logger.info(
        `[AuthService] registration runtime relayer/signer warm completed in ${
          Date.now() - relayerWarmStartedAt
        }ms`,
      );

      const thresholdWarmStartedAt = Date.now();
      const threshold = this.getThresholdSigningService();
      if (threshold) {
        await ensureThresholdEd25519HssWasm();
      }
      this.logger.info(
        `[AuthService] registration runtime threshold warm completed in ${
          Date.now() - thresholdWarmStartedAt
        }ms`,
      );

      const storeWarmStartedAt = Date.now();
      this.stores.getWebAuthnAuthenticatorStore();
      this.stores.getWebAuthnCredentialBindingStore();
      this.stores.getNearPublicKeyStore();
      this.logger.info(
        `[AuthService] registration runtime storage warm completed in ${
          Date.now() - storeWarmStartedAt
        }ms`,
      );

      this.logger.info(
        `[AuthService] registration runtime warm completed in ${Date.now() - warmStartedAt}ms`,
      );
    })();

    try {
      await this.registrationRuntimeWarmPromise;
    } catch (error) {
      this.registrationRuntimeWarmPromise = null;
      throw error;
    }
  }

  async viewAccessKeyList(accountId: string): Promise<AccessKeyList> {
    return await this.nearAccounts.viewAccessKeyList(accountId);
  }

  async dispatchNearSignedTransactionBorsh(input: {
    signedTransactionBorshB64u: string;
  }): Promise<{ rpcResult: FinalExecutionOutcome }> {
    return await this.nearAccounts.dispatchNearSignedTransactionBorsh(input);
  }

  /**
   * Lazily constructs the threshold signing service when `thresholdStore` is configured.
   * Routers may call this to auto-enable `/threshold-ed25519/*` endpoints.
   */
  getThresholdSigningService(): ThresholdSigningServiceType | null {
    if (this.thresholdSigningServiceInitialized) return this.thresholdSigningService;
    this.thresholdSigningServiceInitialized = true;

    if (!this.config.thresholdStore) {
      this.thresholdSigningService = null;
      return null;
    }

    this.thresholdSigningService = createThresholdSigningService({
      authService: this,
      thresholdStore: this.config.thresholdStore,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.thresholdSigningService;
  }

  /**
   * Explicit injection seam for environments that need AuthService and the threshold
   * service to share one already-constructed instance, such as E2E harnesses.
   */
  setThresholdSigningService(service: ThresholdSigningServiceType | null): void {
    this.thresholdSigningServiceInitialized = true;
    this.thresholdSigningService = service;
  }

  private isProductionEnvironment(): boolean {
    return isAuthServiceProductionEnvironment();
  }

  private readConfigValue(name: string): string {
    return readAuthServiceConfigValue({
      thresholdStore: this.config.thresholdStore as AuthServiceConfigSource,
      name,
    });
  }

  private resolveRegistrationPrepareRateLimitPolicy(): { limit: number; windowMs: number } {
    return resolveRegistrationPrepareRateLimitPolicyFromSource({
      thresholdStore: this.config.thresholdStore as AuthServiceConfigSource,
      production: this.isProductionEnvironment(),
    });
  }

  private async consumeRegistrationPrepareRateLimit(args: {
    request: WalletRegistrationPrepareRequest;
    storedIntent: StoredRegistrationIntent;
  }): Promise<
    | { ok: true }
    | {
        ok: false;
        code: 'rate_limited' | 'invalid_body';
        message: string;
        retryAfterMs?: number;
        resetAtMs?: number;
      }
  > {
    return await consumeRegistrationPrepareRateLimitWithDeps({
      limiter: this.stores.getRegistrationPrepareRateLimiter(),
      policy: this.resolveRegistrationPrepareRateLimitPolicy(),
      request: args.request,
      storedIntent: args.storedIntent,
      production: this.isProductionEnvironment(),
    });
  }

  private resolveEmailOtpRateLimitPolicies(): {
    challenge: { limit: number; windowMs: number };
    verify: { limit: number; windowMs: number };
    grant: { limit: number; windowMs: number };
    recoveryKeyAttempt: { limit: number; windowMs: number };
    googleRegistrationAttempt: { limit: number; windowMs: number };
  } {
    return resolveEmailOtpRateLimitPoliciesFromSource({
      thresholdStore: this.config.thresholdStore as AuthServiceConfigSource,
      production: this.isProductionEnvironment(),
    });
  }

  private async consumeEmailOtpRateLimit(args: {
    scope: 'challenge' | 'verify' | 'grant' | 'recoveryKeyAttempt' | 'googleRegistrationAttempt';
    action?: string;
    userId?: string;
    walletId?: string;
    providerSubject?: string;
    orgId?: string;
    clientIp?: string;
  }): Promise<
    | { ok: true }
    | {
        ok: false;
        code: 'rate_limited';
        message: string;
        retryAfterMs?: number;
        resetAtMs?: number;
      }
  > {
    return await consumeEmailOtpRateLimitWithDeps({
      limiter: this.stores.getEmailOtpRateLimiter(),
      policies: this.resolveEmailOtpRateLimitPolicies(),
      scope: args.scope,
      action: args.action,
      userId: args.userId,
      walletId: args.walletId,
      providerSubject: args.providerSubject,
      orgId: args.orgId,
      clientIp: args.clientIp,
    });
  }

  private resolveEmailOtpConfig(): {
    deliveryMode: 'email_provider' | 'log' | 'memory';
    challengeTtlMs: number;
    grantTtlMs: number;
    maxAttempts: number;
    lockoutTtlMs: number;
    codeLength: number;
    devOutboxEnabled: boolean;
    maxActiveChallengesPerContext: number;
  } {
    return resolveEmailOtpConfigFromSource({
      thresholdStore: this.config.thresholdStore as AuthServiceConfigSource,
      production: this.isProductionEnvironment(),
    });
  }

  private createEmailOtpShamirCipher() {
    return createEmailOtpShamirCipherFromConfig({
      keyVersionRaw: this.readConfigValue('SIGNING_SESSION_SEAL_KEY_VERSION'),
      shamirPrimeB64u: this.readConfigValue('SIGNING_SESSION_SHAMIR_P_B64U'),
      serverEncryptExponentB64u: this.readConfigValue('SIGNING_SESSION_SEAL_E_S_B64U'),
      serverDecryptExponentB64u: this.readConfigValue('SIGNING_SESSION_SEAL_D_S_B64U'),
    });
  }

  private async deliverEmailOtpCode(input: {
    challengeId: string;
    walletId: string;
    userId: string;
    otpChannel: EmailOtpChannel;
    action: EmailOtpChallengeAction;
    operation: EmailOtpChallengeOperation;
    email: string;
    otpCode: string;
    expiresAtMs: number;
  }): Promise<
    | { ok: true; deliveryMode: 'email_provider' | 'log' | 'memory'; emailHint: string }
    | { ok: false; code: string; message: string; lockedUntilMs?: number }
  > {
    return await deliverEmailOtpCodeWithDeps({
      config: this.resolveEmailOtpConfig(),
      production: this.isProductionEnvironment(),
      logger: this.logger,
      memoryOutbox: this.emailOtpMemoryOutbox,
      challengeId: input.challengeId,
      walletId: input.walletId,
      userId: input.userId,
      otpChannel: input.otpChannel,
      action: input.action,
      operation: input.operation,
      email: input.email,
      otpCode: input.otpCode,
      expiresAtMs: input.expiresAtMs,
    });
  }

  private identityOperations(): IdentityOperations {
    return new IdentityOperations(this.stores.getIdentityStore());
  }

  async listIdentities(input: {
    userId: string;
  }): Promise<ListIdentitiesResult> {
    return await this.identityOperations().listIdentities(input);
  }

  async linkIdentity(input: {
    userId: string;
    subject: string;
    allowMoveIfSoleIdentity?: boolean;
  }): Promise<LinkIdentityResult> {
    return await this.identityOperations().linkIdentity(input);
  }

  async unlinkIdentity(input: { userId: string; subject: string }): Promise<UnlinkIdentityResult> {
    return await this.identityOperations().unlinkIdentity(input);
  }

  async getOrCreateAppSessionVersion(input: {
    userId: string;
  }): Promise<AppSessionVersionMutationResult> {
    return await this.identityOperations().getOrCreateAppSessionVersion(input);
  }

  async rotateAppSessionVersion(input: {
    userId: string;
  }): Promise<AppSessionVersionMutationResult> {
    return await this.identityOperations().rotateAppSessionVersion(input);
  }

  async validateAppSessionVersion(input: {
    userId: string;
    appSessionVersion: string;
  }): Promise<AppSessionVersionValidationResult> {
    return await this.identityOperations().validateAppSessionVersion(input);
  }

  async recordNearPublicKeyMetadata(input: {
    userId?: unknown;
    publicKey?: unknown;
    kind: NearPublicKeyKind;
    signerSlot?: unknown;
    credentialIdB64u?: unknown;
    rpId?: unknown;
    addedTxHash?: unknown;
    removedAtMs?: unknown;
    source?: string;
  }): Promise<RecordNearPublicKeyMetadataResult> {
    return await recordNearPublicKeyMetadataWithStore({
      store: this.stores.getNearPublicKeyStore(),
      logger: this.logger,
      userId: input.userId,
      publicKey: input.publicKey,
      kind: input.kind,
      signerSlot: input.signerSlot,
      credentialIdB64u: input.credentialIdB64u,
      rpId: input.rpId,
      addedTxHash: input.addedTxHash,
      removedAtMs: input.removedAtMs,
      source: input.source,
    });
  }

  private recoveryTrackingOperations(): RecoveryTrackingOperations {
    return new RecoveryTrackingOperations({
      recoverySessionStore: this.stores.getRecoverySessionStore(),
      recoveryExecutionStore: this.stores.getRecoveryExecutionStore(),
    });
  }

  async getRecoverySession(input: {
    sessionId: string;
  }): Promise<GetRecoverySessionResult> {
    return await this.recoveryTrackingOperations().getRecoverySession(input);
  }

  async updateRecoverySessionStatus(input: {
    sessionId: string;
    status: RecoverySessionStatus;
    metadataPatch?: Record<string, unknown> | null;
  }): Promise<UpdateRecoverySessionStatusResult> {
    return await this.recoveryTrackingOperations().updateRecoverySessionStatus(input);
  }

  async getRecoveryExecution(input: {
    sessionId: string;
    chainIdKey: string;
    accountAddress: string;
    action: string;
  }): Promise<GetRecoveryExecutionResult> {
    return await this.recoveryTrackingOperations().getRecoveryExecution(input);
  }

  async listRecoveryExecutions(input: {
    sessionId: string;
  }): Promise<ListRecoveryExecutionsResult> {
    return await this.recoveryTrackingOperations().listRecoveryExecutions(input);
  }

  async listRecoveryExecutionsByStatus(input: {
    status: RecoveryExecutionStatus;
    action?: string;
    updatedBeforeMs?: number;
    limit?: number;
  }): Promise<ListRecoveryExecutionsResult> {
    return await this.recoveryTrackingOperations().listRecoveryExecutionsByStatus(input);
  }

  async recordRecoveryExecution(input: {
    sessionId: string;
    chainIdKey: string;
    accountAddress: string;
    action: string;
    status: RecoveryExecutionStatus;
    transactionHash?: string;
    errorCode?: string;
    errorMessage?: string;
    metadata?: Record<string, unknown>;
  }): Promise<RecordRecoveryExecutionResult> {
    return await this.recoveryTrackingOperations().recordRecoveryExecution(input);
  }

  async txStatus(txHash: string, senderAccountId: string): Promise<FinalExecutionOutcome> {
    return await this.nearAccounts.txStatus(txHash, senderAccountId);
  }

  private async _ensureSignerAndRelayerAccount(): Promise<void> {
    this.runtimeState = await ensureAuthServiceRuntimeReady({
      state: this.runtimeState,
      relayerPrivateKey: this.config.relayerPrivateKey,
      signerWasmOverride: this.config.signerWasm?.moduleOrPath,
      logger: this.logger,
    });
  }

  private async ensureSignerWasm(): Promise<void> {
    this.runtimeState = await ensureAuthServiceSignerWasmReady({
      state: this.runtimeState,
      signerWasmOverride: this.config.signerWasm?.moduleOrPath,
      logger: this.logger,
    });
  }

  private isNodeEnvironment(): boolean {
    return isAuthServiceNodeEnvironment();
  }

  /**
   * ===== Registration & authentication =====
   *
   * Helpers for creating accounts, registering WebAuthn credentials,
   * and verifying authentication responses.
   */

  /**
   * Create a new account with the specified balance
   */
  async createAccount(request: AccountCreationRequest): Promise<AccountCreationResult> {
    return await this.nearAccounts.createAccount(request);
  }

  async fundImplicitNearAccount(
    request: FundImplicitNearAccountRequest,
  ): Promise<FundImplicitNearAccountResult> {
    return await this.nearAccounts.fundImplicitNearAccount(request);
  }

  private async verifyRegistrationCredentialForIntent(input: {
    webauthnRegistration: unknown;
    expectedChallenge: string;
    expectedOrigin: string;
    rpId: WebAuthnRpId;
  }) {
    return await verifyWebAuthnRegistrationCredentialForIntent(input);
  }

  /**
   * Standard WebAuthn assertion verification for lite flows.
   *
   * This verifies:
   * - the assertion signature against the credential public key stored in relay-private storage,
   * - the RP ID hash against `rpId`,
   * - the challenge against `expectedChallenge` (base64url string),
   * - and that `clientDataJSON.origin` is within the RP ID domain.
   *
   * Notes:
   * - This intentionally does not involve on-chain challenge proofs or `verify_authentication_response`.
   * - Replay protection is handled by upstream protocol bindings (e.g., unique sessionPolicyDigest32 via sessionId).
   */
  async verifyWebAuthnAuthenticationLite(input: {
    userId: string;
    rpId: WebAuthnRpId;
    expectedChallenge: string;
    webauthn_authentication: WebAuthnAuthenticationCredential;
    expected_origin: string;
  }): Promise<{ success: boolean; verified: boolean; code?: string; message?: string }> {
    await this._ensureSignerAndRelayerAccount();
    return await verifyWebAuthnAuthenticationLiteWithStore({
      userId: input.userId,
      rpId: input.rpId,
      expectedChallenge: input.expectedChallenge,
      webauthnAuthentication: input.webauthn_authentication,
      expectedOrigin: input.expected_origin,
      authenticatorStore: this.stores.getWebAuthnAuthenticatorStore(),
      logger: this.logger,
    });
  }

  /**
   * List WebAuthn authenticators for the given user.
   *
   * This is relay-private state (no on-chain authenticator registry).
   * Intended for UI surfaces like "Linked Devices" in the SDK.
   */
  async listWebAuthnAuthenticatorsForUser(input: { userId: string; rpId?: string }): Promise<{
    ok: boolean;
    code?: string;
    message?: string;
    authenticators?: Array<{
      credentialIdB64u: string;
      signerSlot?: number;
      publicKey?: string;
      createdAtMs?: number;
      updatedAtMs?: number;
    }>;
  }> {
    return await listWebAuthnAuthenticatorsForUserWithStores({
      userId: input.userId,
      rpId: String(input.rpId || '').trim(),
      authenticatorStore: this.stores.getWebAuthnAuthenticatorStore(),
      credentialBindingStore: this.stores.getWebAuthnCredentialBindingStore(),
    });
  }

  async listNearPublicKeysForUser(input: { userId: string }): Promise<ListNearPublicKeysResult> {
    return await listNearPublicKeysForUserWithStore({
      store: this.stores.getNearPublicKeyStore(),
      userId: input.userId,
    });
  }

  async createWebAuthnLoginOptions(request: {
    userId?: unknown;
    user_id?: unknown;
    rpId?: unknown;
    rp_id?: unknown;
    ttlMs?: unknown;
    ttl_ms?: unknown;
  }): Promise<{
    ok: boolean;
    challengeId?: string;
    challengeB64u?: string;
    expiresAtMs?: number;
    code?: string;
    message?: string;
  }> {
    return await createWebAuthnLoginOptionsWithStore({
      request,
      loginChallengeStore: this.stores.getWebAuthnLoginChallengeStore(),
    });
  }

  async verifyWebAuthnLogin(request: {
    challengeId?: unknown;
    challenge_id?: unknown;
    webauthn_authentication?: unknown;
    expected_origin?: string;
  }): Promise<{
    ok: boolean;
    verified?: boolean;
    userId?: string;
    rpId?: string;
    code?: string;
    message?: string;
  }> {
    return await verifyWebAuthnLoginWithStores({
      request,
      loginChallengeStore: this.stores.getWebAuthnLoginChallengeStore(),
      authenticatorStore: this.stores.getWebAuthnAuthenticatorStore(),
      identityStore: this.stores.getIdentityStore(),
      logger: this.logger,
    });
  }

  async createEmailOtpUnlockChallenge(request: {
    walletId?: unknown;
    orgId?: unknown;
    ttlMs?: unknown;
    ttl_ms?: unknown;
  }): Promise<
    | {
        ok: true;
        walletId: string;
        challengeId: string;
        challengeB64u: string;
        expiresAtMs: number;
        unlockKeyVersion: string;
      }
    | { ok: false; code: string; message: string; lockedUntilMs?: number }
  > {
    return await createEmailOtpUnlockChallengeWithStores({
      request,
      unlockChallengeStore: this.stores.getEmailOtpUnlockChallengeStore(),
      readActiveEnrollment: this.readActiveEmailOtpEnrollment.bind(this),
    });
  }

  async verifyEmailOtpUnlockProof(request: {
    walletId?: unknown;
    orgId?: unknown;
    challengeId?: unknown;
    unlockProof?: unknown;
  }): Promise<
    | {
        ok: true;
        verified: true;
        userId: string;
        walletId: string;
        unlockKeyVersion: string;
      }
    | { ok: false; verified: false; code: string; message: string }
  > {
    return await verifyEmailOtpUnlockProofWithStores({
      request,
      unlockChallengeStore: this.stores.getEmailOtpUnlockChallengeStore(),
      readActiveEnrollment: this.readActiveEmailOtpEnrollment.bind(this),
      putAuthStateForEnrollment: this.putEmailOtpAuthStateForEnrollment.bind(this),
    });
  }

  private async pruneExpiredEmailOtpChallenges(
    challengeStore: EmailOtpChallengeStore,
    nowMs: number,
  ): Promise<void> {
    await pruneExpiredEmailOtpChallengesWithStore({
      challengeStore,
      memoryOutbox: this.emailOtpMemoryOutbox,
      nowMs,
    });
  }

  private async readEmailOtpAuthStateForEnrollment(
    enrollmentRecord: EmailOtpWalletEnrollmentRecord,
  ): Promise<EmailOtpAuthStateReadResult> {
    return await readEmailOtpAuthStateForEnrollmentWithStore({
      authStateStore: this.stores.getEmailOtpAuthStateStore(),
      enrollment: enrollmentRecord,
    });
  }

  private async putEmailOtpAuthStateForEnrollment(
    enrollmentRecord: EmailOtpWalletEnrollmentRecord,
    patch: EmailOtpAuthStatePatch,
  ): Promise<EmailOtpAuthStateRecord> {
    return await putEmailOtpAuthStateForEnrollmentWithStore({
      authStateStore: this.stores.getEmailOtpAuthStateStore(),
      enrollment: enrollmentRecord,
      patch,
      nowMs: Date.now(),
    });
  }

  private async createEmailOtpChallengeWithAction(request: {
    challengeSubjectId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    email?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
    operation?: unknown;
    reuseActiveChallenge?: unknown;
    action: EmailOtpChallengeAction;
  }): Promise<CreateEmailOtpChallengeWithActionResult> {
    return await createEmailOtpChallengeWithActionWithStores({
      request,
      challengeStore: this.stores.getEmailOtpChallengeStore(),
      memoryOutbox: this.emailOtpMemoryOutbox,
      readActiveEnrollment: this.readActiveEmailOtpEnrollment.bind(this),
      readEnrollmentAuthState: this.readEmailOtpAuthStateForEnrollment.bind(this),
      consumeRateLimit: this.consumeEmailOtpRateLimit.bind(this),
      resolveConfig: this.resolveEmailOtpConfig.bind(this),
      deliverCode: this.deliverEmailOtpCode.bind(this),
    });
  }

  private emailOtpChallengeOperationsInput(): EmailOtpChallengeOperationsInput {
    return {
      createChallengeWithAction: this.createEmailOtpChallengeWithAction.bind(this),
      verifyChallengeCode: this.verifyEmailOtpChallengeCode.bind(this),
      readActiveEnrollment: this.readActiveEmailOtpEnrollment.bind(this),
      recoveryWrappedEnrollmentEscrowStore:
        this.stores.getEmailOtpRecoveryWrappedEnrollmentEscrowStore(),
      grantStore: this.stores.getEmailOtpGrantStore(),
      resolveConfig: this.resolveEmailOtpConfig.bind(this),
    };
  }

  async createEmailOtpChallenge(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    email?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
    operation?: unknown;
    reuseActiveChallenge?: unknown;
  }): Promise<
    | {
        ok: true;
        challenge: {
          challengeId: string;
          issuedAtMs: number;
          expiresAtMs: number;
          userId: string;
          walletId: string;
          orgId: string;
          otpChannel: EmailOtpChannel;
          sessionHash: string;
          appSessionVersion: string;
          action: typeof WALLET_EMAIL_OTP_ACTIONS.login;
          operation: EmailOtpLoginChallengeOperation;
        };
        delivery: {
          status: 'sent' | 'reused';
          mode: 'email_provider' | 'log' | 'memory';
          emailHint: string;
        };
      }
    | { ok: false; code: string; message: string }
  > {
    return await createEmailOtpChallengeOperation(this.emailOtpChallengeOperationsInput(), request);
  }

  async createEmailOtpEnrollmentChallenge(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    email?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
    operation?: unknown;
  }): Promise<
    | {
        ok: true;
        challenge: {
          challengeId: string;
          issuedAtMs: number;
          expiresAtMs: number;
          userId: string;
          walletId: string;
          orgId: string;
          otpChannel: EmailOtpChannel;
          sessionHash: string;
          appSessionVersion: string;
          action: typeof WALLET_EMAIL_OTP_ACTIONS.registration;
          operation: typeof WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
        };
        delivery: {
          mode: 'email_provider' | 'log' | 'memory';
          emailHint: string;
        };
      }
    | { ok: false; code: string; message: string }
  > {
    return await createEmailOtpEnrollmentChallengeOperation(
      this.emailOtpChallengeOperationsInput(),
      request,
    );
  }

  async createEmailOtpDeviceRecoveryChallenge(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    email?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
  }): Promise<
    | {
        ok: true;
        challenge: {
          challengeId: string;
          issuedAtMs: number;
          expiresAtMs: number;
          userId: string;
          walletId: string;
          orgId: string;
          otpChannel: EmailOtpChannel;
          sessionHash: string;
          appSessionVersion: string;
          action: typeof WALLET_EMAIL_OTP_ACTIONS.deviceRecovery;
          operation: typeof WALLET_EMAIL_OTP_UNLOCK_OPERATION;
        };
        delivery: {
          mode: 'email_provider' | 'log' | 'memory';
          emailHint: string;
        };
      }
    | { ok: false; code: string; message: string }
  > {
    return await createEmailOtpDeviceRecoveryChallengeOperation(
      this.emailOtpChallengeOperationsInput(),
      request,
    );
  }

  private async verifyEmailOtpChallengeCode(request: {
    challengeSubjectId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    challengeId?: unknown;
    otpCode?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    registrationChallengeProof?: EmailOtpRegistrationChallengeProof;
    allowRegistrationChallengeReroll?: boolean;
    clientIp?: unknown;
    expectedAction: EmailOtpChallengeAction;
    expectedOperation?: EmailOtpChallengeOperation;
  }): Promise<VerifiedEmailOtpChallengeCodeResult> {
    return await verifyEmailOtpChallengeCodeWithStores({
      request,
      challengeStore: this.stores.getEmailOtpChallengeStore(),
      walletEnrollmentStore: this.stores.getEmailOtpWalletEnrollmentStore(),
      memoryOutbox: this.emailOtpMemoryOutbox,
      logger: this.logger,
      readActiveEnrollment: this.readActiveEmailOtpEnrollment.bind(this),
      readEnrollmentAuthState: this.readEmailOtpAuthStateForEnrollment.bind(this),
      putEnrollmentAuthState: this.putEmailOtpAuthStateForEnrollment.bind(this),
      consumeRateLimit: this.consumeEmailOtpRateLimit.bind(this),
      resolveConfig: this.resolveEmailOtpConfig.bind(this),
    });
  }

  async verifyEmailOtpChallenge(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    challengeId?: unknown;
    otpCode?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
    operation?: unknown;
  }): Promise<
    | {
        ok: true;
        challengeId: string;
        loginGrant: string;
        grantExpiresAtMs: number;
        otpChannel: EmailOtpChannel;
      }
    | {
        ok: false;
        code: string;
        message: string;
        attemptsRemaining?: number;
        lockedUntilMs?: number;
      }
  > {
    return await verifyEmailOtpChallengeOperation(this.emailOtpChallengeOperationsInput(), request);
  }

  async verifyEmailOtpDeviceRecoveryChallenge(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    challengeId?: unknown;
    otpCode?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
  }): Promise<
    | {
        ok: true;
        challengeId: string;
        otpChannel: EmailOtpChannel;
        recoveryConsumeGrant: string;
        recoveryConsumeGrantExpiresAtMs: number;
        recoveryWrappedEnrollmentEscrows: EmailOtpRecoveryChallengeEscrow[];
        enrollment: {
          walletId: string;
          providerUserId: string;
          orgId: string;
          enrollmentId: string;
          enrollmentVersion: string;
          enrollmentSealKeyVersion: string;
          signingRootId: string;
          signingRootVersion: string;
          recoveryWrappedEnrollmentEscrowCount: number;
        };
      }
    | {
        ok: false;
        code: string;
        message: string;
        attemptsRemaining?: number;
        lockedUntilMs?: number;
      }
  > {
    return await verifyEmailOtpDeviceRecoveryChallengeOperation(
      this.emailOtpChallengeOperationsInput(),
      request,
    );
  }

  async verifyEmailOtpEnrollment(request: {
    /** Provider subject from the app-session JWT that requested the registration OTP. */
    providerSubject: unknown;
    walletId: unknown;
    orgId: unknown;
    challengeId: unknown;
    otpCode: unknown;
    otpChannel: unknown;
    sessionHash: unknown;
    appSessionVersion: unknown;
    /** Email asserted by the registration proof. It must match the challenged email. */
    proofEmail?: unknown;
    clientIp?: unknown;
    recoveryWrappedEnrollmentEscrows?: unknown;
    enrollmentSealKeyVersion?: unknown;
    clientUnlockPublicKeyB64u?: unknown;
    unlockKeyVersion?: unknown;
    thresholdEcdsaClientVerifyingShareB64u?: unknown;
    googleEmailOtpRegistrationAttemptId?: unknown;
  }): Promise<
    | {
        ok: true;
        walletId: string;
        otpChannel: EmailOtpChannel;
        enrollment: {
          createdAtMs: number;
          updatedAtMs: number;
          enrollmentSealKeyVersion: string;
          unlockKeyVersion: string;
        };
      }
    | {
        ok: false;
        code: string;
        message: string;
        attemptsRemaining?: number;
        lockedUntilMs?: number;
      }
  > {
    return await verifyEmailOtpEnrollmentWithStores({
      request,
      walletStore: this.stores.getWalletStore(),
      walletEnrollmentStore: this.stores.getEmailOtpWalletEnrollmentStore(),
      authStateStore: this.stores.getEmailOtpAuthStateStore(),
      recoveryWrappedEnrollmentEscrowStore: this.stores.getEmailOtpRecoveryWrappedEnrollmentEscrowStore(),
      registrationAttemptStore: this.stores.getEmailOtpRegistrationAttemptStore(),
      identityStore: this.stores.getIdentityStore(),
      verifyChallengeCode: this.verifyEmailOtpChallengeCode.bind(this),
    });
  }

  async readEmailOtpEnrollment(request: {
    walletId?: unknown;
    orgId: unknown;
  }): Promise<EmailOtpEnrollmentReadResult> {
    return await readEmailOtpEnrollmentWithStore({
      walletEnrollmentStore: this.stores.getEmailOtpWalletEnrollmentStore(),
      request,
    });
  }

  async readActiveEmailOtpEnrollment(request: {
    walletId?: unknown;
    orgId: unknown;
    providerUserId?: unknown;
  }): Promise<EmailOtpEnrollmentReadResult> {
    return await readActiveEmailOtpEnrollmentWithStore({
      walletEnrollmentStore: this.stores.getEmailOtpWalletEnrollmentStore(),
      request,
    });
  }

  async isEmailOtpStrongAuthRequired(
    request: { walletId?: unknown },
  ): Promise<EmailOtpStrongAuthRequiredResult> {
    return await isEmailOtpStrongAuthRequiredWithStores({
      walletEnrollmentStore: this.stores.getEmailOtpWalletEnrollmentStore(),
      authStateStore: this.stores.getEmailOtpAuthStateStore(),
      request,
    });
  }

  async markEmailOtpStrongAuthSatisfied(request: {
    walletId?: unknown;
  }): Promise<EmailOtpStrongAuthSatisfiedResult> {
    return await markEmailOtpStrongAuthSatisfiedWithStores({
      walletEnrollmentStore: this.stores.getEmailOtpWalletEnrollmentStore(),
      authStateStore: this.stores.getEmailOtpAuthStateStore(),
      request,
      nowMs: Date.now(),
    });
  }

  async consumeEmailOtpGrant(
    request: EmailOtpGrantConsumeRequest,
  ): Promise<EmailOtpGrantConsumeResult> {
    return await consumeEmailOtpGrantWithStore({
      request,
      grantStore: this.stores.getEmailOtpGrantStore(),
      consumeRateLimit: this.consumeEmailOtpRateLimit.bind(this),
      nowMs: Date.now(),
    });
  }

  async getEmailOtpRecoveryCodeStatus(
    request: EmailOtpRecoveryCodeStatusRequest,
  ): Promise<EmailOtpRecoveryCodeStatusResult> {
    return await getEmailOtpRecoveryCodeStatusWithStores({
      request,
      recoveryWrappedEnrollmentEscrowStore: this.stores.getEmailOtpRecoveryWrappedEnrollmentEscrowStore(),
      readActiveEnrollment: this.readActiveEmailOtpEnrollment.bind(this),
    });
  }
  async consumeEmailOtpRecoveryKey(
    request: EmailOtpRecoveryKeyConsumeRequest,
  ): Promise<EmailOtpRecoveryKeyConsumeResult> {
    return await consumeEmailOtpRecoveryKeyWithStores({
      request,
      stores: this.emailOtpRecoveryKeysStores(),
      ports: this.emailOtpRecoveryKeysPorts(),
    });
  }
  async rotateEmailOtpRecoveryKeys(
    request: EmailOtpRecoveryKeysRotateRequest,
  ): Promise<EmailOtpRecoveryKeysRotateResult> {
    return await rotateEmailOtpRecoveryKeysWithStores({
      request,
      store: this.stores.getEmailOtpRecoveryWrappedEnrollmentEscrowStore(),
      readActiveEnrollment: this.readActiveEmailOtpEnrollment.bind(this),
      readEnrollmentAuthState: this.readEmailOtpAuthStateForEnrollment.bind(this),
      resolveConfig: this.resolveEmailOtpConfig.bind(this),
    });
  }
  async recordEmailOtpRecoveryKeyAttemptFailure(
    request: EmailOtpRecoveryKeyAttemptFailureRequest,
  ): Promise<EmailOtpRecoveryKeyAttemptFailureResult> {
    return await recordEmailOtpRecoveryKeyAttemptFailureWithStores({
      request,
      stores: this.emailOtpRecoveryKeysStores(),
      ports: this.emailOtpRecoveryKeysPorts(),
    });
  }
  private emailOtpRecoveryKeysStores() {
    return {
      grantStore: this.stores.getEmailOtpGrantStore(),
      recoveryWrappedEnrollmentEscrowStore: this.stores.getEmailOtpRecoveryWrappedEnrollmentEscrowStore(),
    };
  }

  private emailOtpRecoveryKeysPorts() {
    return {
      readActiveEnrollment: this.readActiveEmailOtpEnrollment.bind(this),
      readEnrollmentAuthState: this.readEmailOtpAuthStateForEnrollment.bind(this),
      putEnrollmentAuthState: this.putEmailOtpAuthStateForEnrollment.bind(this),
      consumeRateLimit: this.consumeEmailOtpRateLimit.bind(this),
      resolveConfig: this.resolveEmailOtpConfig.bind(this),
    };
  }

  async readEmailOtpOutboxEntry(request: {
    challengeId?: unknown;
    userId?: unknown;
    walletId?: unknown;
  }): Promise<EmailOtpOutboxReadResult> {
    return readEmailOtpOutboxEntryWithDeps({
      config: this.resolveEmailOtpConfig(),
      memoryOutbox: this.emailOtpMemoryOutbox,
      request,
      nowMs: Date.now(),
    });
  }

  async removeEmailOtpServerSeal(
    request: EmailOtpServerSealRequest,
  ): Promise<EmailOtpServerSealResult> {
    return await runEmailOtpServerSealOperation({
      operation: 'remove-server-seal',
      request,
      shamir: this.createEmailOtpShamirCipher(),
    });
  }

  async applyEmailOtpServerSeal(
    request: EmailOtpServerSealRequest,
  ): Promise<EmailOtpServerSealResult> {
    return await runEmailOtpServerSealOperation({
      operation: 'apply-server-seal',
      request,
      shamir: this.createEmailOtpShamirCipher(),
    });
  }

  async verifyOidcJwtExchange(request: { token?: unknown }): Promise<OidcJwtExchangeFacadeResult> {
    return await verifyOidcJwtExchangeWithIdentityStore({
      request,
      config: this.config.oidcExchange,
      jwksState: this.oidcJwksState,
      identityStore: this.stores.getIdentityStore(),
    });
  }

  async verifyGoogleLogin(request: {
    idToken?: unknown;
    id_token?: unknown;
  }): Promise<GoogleLoginFacadeResult> {
    return await verifyGoogleLoginWithIdentityStore({
      request,
      config: this.config.googleOidc,
      jwksState: this.googleJwksState,
      identityStore: this.stores.getIdentityStore(),
    });
  }

  async createWebAuthnSyncAccountOptions(request: {
    rp_id?: unknown;
    account_id?: unknown;
    ttl_ms?: unknown;
    ttlMs?: unknown;
  }): Promise<WebAuthnSyncAccountOptionsResult> {
    return await createWebAuthnSyncAccountOptionsWithStores({
      request,
      syncChallengeStore: this.stores.getWebAuthnSyncChallengeStore(),
      credentialBindingStore: this.stores.getWebAuthnCredentialBindingStore(),
    });
  }

  async listThresholdEcdsaKeyIdentityTargetsForUser(input: {
    userId: string;
    rpId: string;
    keyTargets: readonly unknown[];
  }): Promise<{
    records: ThresholdEcdsaKeyInventoryRecord[];
    diagnostics: ThresholdEcdsaKeyInventoryDiagnostics;
  }> {
    return await listThresholdEcdsaKeyIdentityTargetsForUserWithDeps({
      userId: input.userId,
      rpId: input.rpId,
      keyTargets: input.keyTargets,
      threshold: this.getThresholdSigningService(),
      logger: this.logger,
    });
  }

  async listWalletEcdsaKeyFactsInventory(input: {
    walletId: string;
    rpId: string;
    keyTargets: readonly unknown[];
  }): Promise<{
    records: ThresholdEcdsaKeyInventoryRecord[];
    diagnostics: ThresholdEcdsaKeyInventoryDiagnostics;
  }> {
    return await this.listThresholdEcdsaKeyIdentityTargetsForUser({
      userId: input.walletId,
      rpId: input.rpId,
      keyTargets: input.keyTargets,
    });
  }

  async ecdsaHssRoleLocalBootstrap(
    request: EcdsaHssClientBootstrapRequest,
  ): Promise<EcdsaHssRouteResult<EcdsaHssServerBootstrapResponse>> {
    return await ecdsaHssRoleLocalBootstrapWithThreshold({
      deps: { threshold: this.getThresholdSigningService() },
      request,
    });
  }

  async verifyEcdsaHssRoleLocalClientRootProofForExistingKey(
    request: EcdsaHssClientBootstrapRequest & {
      clientRootProof: NonNullable<EcdsaHssClientBootstrapRequest['clientRootProof']>;
    },
  ): Promise<EcdsaHssRouteResult<{ keyHandle: string }>> {
    return await verifyEcdsaHssRoleLocalClientRootProofForExistingKeyWithThreshold({
      deps: { threshold: this.getThresholdSigningService() },
      request,
    });
  }

  async ecdsaHssRoleLocalExportShare(input: {
    request: EcdsaHssExportShareRequest;
    keyHandle: string;
    claims: RouterAbEcdsaHssWalletSessionClaims;
  }): Promise<EcdsaHssRouteResult<EcdsaHssExportShareResponse>> {
    return await ecdsaHssRoleLocalExportShareWithThreshold({
      deps: { threshold: this.getThresholdSigningService() },
      request: input.request,
      keyHandle: input.keyHandle,
      claims: input.claims,
    });
  }

  async verifyWebAuthnSyncAccount(
    request: WebAuthnSyncAccountVerificationRequest,
  ): Promise<WebAuthnSyncAccountVerificationResult> {
    return await verifyWebAuthnSyncAccountWithStores({
      request,
      syncChallengeStore: this.stores.getWebAuthnSyncChallengeStore(),
      credentialBindingStore: this.stores.getWebAuthnCredentialBindingStore(),
      authenticatorStore: this.stores.getWebAuthnAuthenticatorStore(),
      thresholdSigningService: this.getThresholdSigningService(),
      logger: this.logger,
    });
  }
  private emailRecoveryAuthOperations(): EmailRecoveryAuthOperations {
    return new EmailRecoveryAuthOperations({
      ensureSignerAndRelayerAccount: this._ensureSignerAndRelayerAccount.bind(this),
      getThresholdSigningService: this.getThresholdSigningService.bind(this),
      webAuthnAuthenticatorStore: this.stores.getWebAuthnAuthenticatorStore(),
      webAuthnCredentialBindingStore: this.stores.getWebAuthnCredentialBindingStore(),
      emailRecoveryPreparationStore: this.stores.getEmailRecoveryPreparationStore(),
      recoverySessionStore: this.stores.getRecoverySessionStore(),
    });
  }

  prepareEmailRecovery(
    request: Parameters<EmailRecoveryAuthOperations['prepareEmailRecovery']>[0],
  ): ReturnType<EmailRecoveryAuthOperations['prepareEmailRecovery']> {
    return this.emailRecoveryAuthOperations().prepareEmailRecovery(request);
  }

  respondEmailRecoveryEcdsa(
    request: Parameters<EmailRecoveryAuthOperations['respondEmailRecoveryEcdsa']>[0],
  ): ReturnType<EmailRecoveryAuthOperations['respondEmailRecoveryEcdsa']> {
    return this.emailRecoveryAuthOperations().respondEmailRecoveryEcdsa(request);
  }

  /**
   * Account existence helper used by registration flows.
   */
  async checkAccountExists(accountId: string): Promise<boolean> {
    return await this.nearAccounts.checkAccountExists(accountId);
  }

  /**
   * ===== Delegate actions & transaction execution =====
   *
   * Flows that build and submit on-chain transactions, including NEP-461
   * SignedDelegate meta-transactions.
   */

  /**
   * Execute a NEP-461 SignedDelegate by wrapping it in an outer transaction
   * from the relayer account. This method is intended to be called by
   * example relayers (Node/Cloudflare) once a SignedDelegate has been
   * produced by the signer worker and returned to the application.
   *
   * Notes:
   * - Signature and hash computation are performed by the signer worker.
   *   This method focuses on expiry/policy enforcement and meta-tx submission.
   * - Nonce/replay protection is left to the integrator; see docs for guidance.
   */
  async executeSignedDelegate(input: {
    hash: string;
    signedDelegate: SignedDelegate;
    policy?: DelegateActionPolicy;
  }): Promise<ExecuteSignedDelegateResult> {
    return await this.nearAccounts.executeSignedDelegate(input);
  }
}
