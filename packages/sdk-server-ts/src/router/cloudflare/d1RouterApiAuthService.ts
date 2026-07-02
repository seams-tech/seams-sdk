import {
  D1WalletAuthMethodStore,
  type WalletAuthMethodStore,
} from '../../core/d1WalletAuthMethodStore';
import { D1WalletStore, type WalletStore } from '../../core/d1WalletStore';
import { D1IdentityStore } from '../../core/d1IdentityStore';
import type { IdentityStore } from '../../core/IdentityStore';
import type { D1PreparedStatementLike } from '../../storage/tenantRoute';
import type { AccountCreationResult } from '../../core/types';
import type { RouterApiAuthService } from '../authServicePort';
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
import { CloudflareD1ThresholdSigningRuntime } from './d1ThresholdSigningRuntime';
import { CloudflareD1GoogleEmailOtpRegistrationAttemptStore } from './d1GoogleEmailOtpRegistrationAttemptStore';
import { CloudflareD1GoogleEmailOtpSessionResolver } from './d1GoogleEmailOtpSessionResolver';
import { CloudflareD1SessionStore } from './d1SessionStore';
import { CloudflareD1SessionService } from './d1SessionService';
import { CloudflareD1IdentityService } from './d1IdentityService';
import { CloudflareD1OidcVerificationService } from './d1OidcVerificationService';
import { CloudflareD1WebAuthnAuthService } from './d1WebAuthnAuthService';
import { CloudflareD1WalletAuthMethodService } from './d1WalletAuthMethodService';
import { CloudflareD1WalletRegistrationService } from './d1WalletRegistrationService';
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

type RouterApiAuthServiceCallableKey = {
  [K in keyof RouterApiAuthService]: RouterApiAuthService[K] extends (...args: never[]) => unknown
    ? K
    : never;
}[keyof RouterApiAuthService];

type RouterApiAuthServiceMethodAt<M extends RouterApiAuthServiceCallableKey> = Extract<
  RouterApiAuthService[M],
  (...args: never[]) => unknown
>;

type RouterApiInput<M extends RouterApiAuthServiceCallableKey> = Parameters<
  RouterApiAuthServiceMethodAt<M>
>[0];

type RouterApiResult<M extends RouterApiAuthServiceCallableKey> = Awaited<
  ReturnType<RouterApiAuthServiceMethodAt<M>>
>;

class CloudflareD1RouterApiAuthMetadataService {
  private readonly options: NormalizedCloudflareD1RouterApiAuthServiceOptions;
  private readonly emailOtpChallenges: CloudflareD1EmailOtpChallengeStore;
  private readonly emailOtpDelivery: CloudflareD1EmailOtpDeliveryRuntime;
  private readonly emailOtpEnrollments: CloudflareD1EmailOtpEnrollmentStore;
  private readonly emailOtpGrants: CloudflareD1EmailOtpGrantStore;
  private readonly emailOtpRateLimits: CloudflareD1EmailOtpRateLimitStore;
  private readonly emailOtpRecoveryEscrows: CloudflareD1EmailOtpRecoveryEscrowStore;
  private readonly emailOtpServerSeal: CloudflareD1EmailOtpServerSealRuntime;
  private readonly emailOtpRegistrationEnrollmentFinalizer: CloudflareD1EmailOtpRegistrationEnrollmentFinalizer;
  private readonly emailOtpChallengeVerifier: CloudflareD1EmailOtpChallengeVerifier;
  private readonly emailOtpChallengeIssuer: CloudflareD1EmailOtpChallengeIssuer;
  private readonly emailOtpChallengeService: CloudflareD1EmailOtpChallengeService;
  private readonly emailOtpRecoveryService: CloudflareD1EmailOtpRecoveryService;
  private readonly identityService: CloudflareD1IdentityService;
  private readonly oidcVerification: CloudflareD1OidcVerificationService;
  private readonly identityStore: IdentityStore;
  private readonly sessionStore: CloudflareD1SessionStore;
  private readonly sessionService: CloudflareD1SessionService;
  private readonly googleEmailOtpRegistrationAttempts: CloudflareD1GoogleEmailOtpRegistrationAttemptStore;
  private readonly googleEmailOtpSessions: CloudflareD1GoogleEmailOtpSessionResolver;
  private readonly nearPublicKeys: CloudflareD1NearPublicKeyStore;
  private readonly webAuthnStore: CloudflareD1WebAuthnStore;
  private readonly webAuthnAuthService: CloudflareD1WebAuthnAuthService;
  private readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;
  private readonly walletRegistrations: CloudflareD1WalletRegistrationService;
  private readonly walletAddSigners: CloudflareD1WalletAddSignerService;
  private readonly registrationIntents: CloudflareD1RegistrationIntentService;
  private readonly thresholdSigning: CloudflareD1ThresholdSigningRuntime;
  private walletStore: WalletStore | null = null;
  private walletAuthMethodStore: WalletAuthMethodStore | null = null;
  private registrationCeremonyIntentStore: CloudflareD1RegistrationCeremonyIntentStore | null =
    null;

  constructor(input: CloudflareD1RouterApiAuthServiceOptions) {
    this.options = normalizeD1RouterApiAuthOptions(input);
    this.identityStore = new D1IdentityStore({
      database: this.options.database,
      namespace: this.options.namespace,
      orgId: this.options.orgId,
      projectId: this.options.projectId,
      envId: this.options.envId,
      ensureSchema: false,
    });
    this.identityService = new CloudflareD1IdentityService({
      accountIdDerivationSecret: this.options.accountIdDerivationSecret,
      identityStore: this.identityStore,
      relayerAccount: this.options.relayerAccount,
      resolveGoogleEmailOtpSession: this.resolveGoogleEmailOtpSession.bind(this),
    });
    this.sessionStore = new CloudflareD1SessionStore({
      prepare: this.scopePrepare.bind(this),
    });
    this.sessionService = new CloudflareD1SessionService({
      sessionStore: this.sessionStore,
    });
    this.googleEmailOtpRegistrationAttempts =
      new CloudflareD1GoogleEmailOtpRegistrationAttemptStore({
        prepare: this.scopePrepare.bind(this),
        orgId: this.options.orgId,
      });
    this.nearPublicKeys = new CloudflareD1NearPublicKeyStore({
      prepare: this.scopePrepare.bind(this),
    });
    this.webAuthnStore = new CloudflareD1WebAuthnStore({
      database: this.options.database,
      namespace: this.options.namespace,
      orgId: this.options.orgId,
      projectId: this.options.projectId,
      envId: this.options.envId,
    });
    this.webAuthnAuthService = new CloudflareD1WebAuthnAuthService({
      webAuthnStore: this.webAuthnStore,
    });
    this.emailOtpChallenges = new CloudflareD1EmailOtpChallengeStore({
      database: this.options.database,
      namespace: this.options.namespace,
      orgId: this.options.orgId,
      projectId: this.options.projectId,
      envId: this.options.envId,
    });
    this.emailOtpDelivery = new CloudflareD1EmailOtpDeliveryRuntime(this.options.emailOtp);
    this.emailOtpEnrollments = new CloudflareD1EmailOtpEnrollmentStore({
      prepare: this.scopePrepare.bind(this),
    });
    this.emailOtpGrants = new CloudflareD1EmailOtpGrantStore({
      prepare: this.scopePrepare.bind(this),
    });
    this.emailOtpRateLimits = new CloudflareD1EmailOtpRateLimitStore({
      prepare: this.scopePrepare.bind(this),
      rateLimits: this.options.emailOtp.rateLimits,
    });
    this.emailOtpRecoveryEscrows = new CloudflareD1EmailOtpRecoveryEscrowStore({
      database: this.options.database,
      namespace: this.options.namespace,
      orgId: this.options.orgId,
      projectId: this.options.projectId,
      envId: this.options.envId,
    });
    this.emailOtpServerSeal = new CloudflareD1EmailOtpServerSealRuntime(
      this.options.emailOtpServerSeal,
    );
    this.googleEmailOtpSessions = new CloudflareD1GoogleEmailOtpSessionResolver({
      emailOtpEnrollments: this.emailOtpEnrollments,
      emailOtpRateLimits: this.emailOtpRateLimits,
      identityStore: this.identityStore,
      linkIdentity: this.identityService.linkIdentity.bind(this.identityService),
      production: this.options.emailOtp.production,
      registrationAttempts: this.googleEmailOtpRegistrationAttempts,
    });
    this.oidcVerification = new CloudflareD1OidcVerificationService({
      googleOidcClientId: this.options.googleOidcClientId,
      identityStore: this.identityStore,
      linkIdentity: this.identityService.linkIdentity.bind(this.identityService),
      oidcExchange: this.options.oidcExchange,
    });
    this.emailOtpRegistrationEnrollmentFinalizer =
      new CloudflareD1EmailOtpRegistrationEnrollmentFinalizer({
        emailOtpEnrollments: this.emailOtpEnrollments,
        emailOtpRecoveryEscrows: this.emailOtpRecoveryEscrows,
        googleEmailOtpSessions: this.googleEmailOtpSessions,
      });
    this.emailOtpChallengeVerifier = new CloudflareD1EmailOtpChallengeVerifier({
      emailOtpChallenges: this.emailOtpChallenges,
      emailOtpEnrollments: this.emailOtpEnrollments,
      emailOtpRateLimits: this.emailOtpRateLimits,
      lockoutTtlMs: this.options.emailOtp.lockoutTtlMs,
    });
    this.walletAuthMethods = new CloudflareD1WalletAuthMethodService({
      emailOtpChallengeVerifier: this.emailOtpChallengeVerifier,
      getRegistrationCeremonyIntentStore: this.getRegistrationCeremonyIntentStore.bind(this),
      getWalletAuthMethodStore: this.getWalletAuthMethodStore.bind(this),
      googleEmailOtpRegistrationAttempts: this.googleEmailOtpRegistrationAttempts,
      sha256Bytes: sha256BytesPortable,
      webAuthnStore: this.webAuthnStore,
    });
    this.walletRegistrations = new CloudflareD1WalletRegistrationService({
      createSponsoredNamedNearAccount: this.createSponsoredNamedNearAccount.bind(this),
      emailOtpRegistrationEnrollmentFinalizer: this.emailOtpRegistrationEnrollmentFinalizer,
      getRegistrationCeremonyIntentStore: this.getRegistrationCeremonyIntentStore.bind(this),
      getThresholdSigningService: this.getThresholdSigningService.bind(this),
      getWalletStore: this.getWalletStore.bind(this),
      walletAuthMethods: this.walletAuthMethods,
    });
    this.walletAddSigners = new CloudflareD1WalletAddSignerService({
      getRegistrationCeremonyIntentStore: this.getRegistrationCeremonyIntentStore.bind(this),
      getThresholdSigningService: this.getThresholdSigningService.bind(this),
      getWalletStore: this.getWalletStore.bind(this),
      walletAuthMethods: this.walletAuthMethods,
    });
    this.registrationIntents = new CloudflareD1RegistrationIntentService({
      getRegistrationCeremonyIntentStore: this.getRegistrationCeremonyIntentStore.bind(this),
      signerWallets: this.emailOtpEnrollments,
    });
    this.emailOtpChallengeIssuer = new CloudflareD1EmailOtpChallengeIssuer({
      config: {
        challengeTtlMs: this.options.emailOtp.challengeTtlMs,
        codeLength: this.options.emailOtp.codeLength,
        deliveryMode: this.options.emailOtp.deliveryMode,
        maxActiveChallengesPerContext: this.options.emailOtp.maxActiveChallengesPerContext,
        maxAttempts: this.options.emailOtp.maxAttempts,
      },
      emailOtpChallenges: this.emailOtpChallenges,
      emailOtpDelivery: this.emailOtpDelivery,
      emailOtpEnrollments: this.emailOtpEnrollments,
      emailOtpRateLimits: this.emailOtpRateLimits,
    });
    this.emailOtpChallengeService = new CloudflareD1EmailOtpChallengeService({
      challenges: this.emailOtpChallenges,
      devOutboxEnabled: this.options.emailOtp.devOutboxEnabled,
      finalizer: this.emailOtpRegistrationEnrollmentFinalizer,
      grantTtlMs: this.options.emailOtp.grantTtlMs,
      grants: this.emailOtpGrants,
      issuer: this.emailOtpChallengeIssuer,
      registrationAttempts: this.googleEmailOtpRegistrationAttempts,
      verifier: this.emailOtpChallengeVerifier,
    });
    this.emailOtpRecoveryService = new CloudflareD1EmailOtpRecoveryService({
      challengeVerifier: this.emailOtpChallengeVerifier,
      emailOtpChallenges: this.emailOtpChallenges,
      emailOtpEnrollments: this.emailOtpEnrollments,
      emailOtpGrants: this.emailOtpGrants,
      emailOtpRateLimits: this.emailOtpRateLimits,
      emailOtpRecoveryEscrows: this.emailOtpRecoveryEscrows,
      grantTtlMs: this.options.emailOtp.grantTtlMs,
      sha256Bytes: sha256BytesPortable,
    });
    this.thresholdSigning = new CloudflareD1ThresholdSigningRuntime({
      relayerAccount: this.options.relayerAccount,
      relayerPublicKey: this.options.relayerPublicKey,
      thresholdSigningService: this.options.thresholdSigningService,
      thresholdStore: this.options.thresholdStore,
      auth: {
        verifyWebAuthnAuthenticationLite: this.verifyWebAuthnAuthenticationLite.bind(this),
      },
    });
  }

  async createRegistrationIntent(
    input: RouterApiInput<'createRegistrationIntent'>,
  ): Promise<RouterApiResult<'createRegistrationIntent'>> {
    return await this.registrationIntents.createRegistrationIntent(input);
  }

  async startWalletRegistration(
    request: RouterApiInput<'startWalletRegistration'>,
  ): Promise<RouterApiResult<'startWalletRegistration'>> {
    return await this.walletRegistrations.startWalletRegistration(request);
  }

  async prepareWalletRegistration(
    request: RouterApiInput<'prepareWalletRegistration'>,
  ): Promise<RouterApiResult<'prepareWalletRegistration'>> {
    return await this.walletRegistrations.prepareWalletRegistration(request);
  }

  async respondWalletRegistrationHss(
    request: RouterApiInput<'respondWalletRegistrationHss'>,
  ): Promise<RouterApiResult<'respondWalletRegistrationHss'>> {
    return await this.walletRegistrations.respondWalletRegistrationHss(request);
  }

  async finalizeWalletRegistration(
    request: RouterApiInput<'finalizeWalletRegistration'>,
  ): Promise<RouterApiResult<'finalizeWalletRegistration'>> {
    return await this.walletRegistrations.finalizeWalletRegistration(request);
  }

  async createAddSignerIntent(
    input: RouterApiInput<'createAddSignerIntent'>,
  ): Promise<RouterApiResult<'createAddSignerIntent'>> {
    return await this.registrationIntents.createAddSignerIntent(input);
  }

  async startWalletAddSigner(
    request: RouterApiInput<'startWalletAddSigner'>,
  ): Promise<RouterApiResult<'startWalletAddSigner'>> {
    return await this.walletAddSigners.startWalletAddSigner(request);
  }

  async respondWalletAddSignerHss(
    request: RouterApiInput<'respondWalletAddSignerHss'>,
  ): Promise<RouterApiResult<'respondWalletAddSignerHss'>> {
    return await this.walletAddSigners.respondWalletAddSignerHss(request);
  }

  async finalizeWalletAddSigner(
    request: RouterApiInput<'finalizeWalletAddSigner'>,
  ): Promise<RouterApiResult<'finalizeWalletAddSigner'>> {
    return await this.walletAddSigners.finalizeWalletAddSigner(request);
  }

  async createAddAuthMethodIntent(
    input: RouterApiInput<'createAddAuthMethodIntent'>,
  ): Promise<RouterApiResult<'createAddAuthMethodIntent'>> {
    return await this.registrationIntents.createAddAuthMethodIntent(input);
  }

  async startWalletAddAuthMethod(
    request: RouterApiInput<'startWalletAddAuthMethod'>,
  ): Promise<RouterApiResult<'startWalletAddAuthMethod'>> {
    return await this.walletAuthMethods.startWalletAddAuthMethod(request);
  }

  async finalizeWalletAddAuthMethod(
    request: RouterApiInput<'finalizeWalletAddAuthMethod'>,
  ): Promise<RouterApiResult<'finalizeWalletAddAuthMethod'>> {
    return await this.walletAuthMethods.finalizeWalletAddAuthMethod(request);
  }

  async listIdentities(
    input: RouterApiInput<'listIdentities'>,
  ): Promise<RouterApiResult<'listIdentities'>> {
    return await this.identityService.listIdentities(input);
  }

  async linkIdentity(
    input: RouterApiInput<'linkIdentity'>,
  ): Promise<RouterApiResult<'linkIdentity'>> {
    return await this.identityService.linkIdentity(input);
  }

  async unlinkIdentity(
    input: RouterApiInput<'unlinkIdentity'>,
  ): Promise<RouterApiResult<'unlinkIdentity'>> {
    return await this.identityService.unlinkIdentity(input);
  }

  async resolveOidcWalletId(
    input: RouterApiInput<'resolveOidcWalletId'>,
  ): Promise<RouterApiResult<'resolveOidcWalletId'>> {
    return await this.identityService.resolveOidcWalletId(input);
  }

  async consumeGoogleEmailOtpRegistrationAttemptRateLimit(
    input: RouterApiInput<'consumeGoogleEmailOtpRegistrationAttemptRateLimit'>,
  ): Promise<RouterApiResult<'consumeGoogleEmailOtpRegistrationAttemptRateLimit'>> {
    return await this.googleEmailOtpSessions.consumeRegistrationAttemptRateLimit(input);
  }

  async resolveGoogleEmailOtpSession(
    input: RouterApiInput<'resolveGoogleEmailOtpSession'>,
  ): Promise<RouterApiResult<'resolveGoogleEmailOtpSession'>> {
    return await this.googleEmailOtpSessions.resolve(input);
  }

  async cleanupGoogleEmailOtpDevRegistrationState(
    input: RouterApiInput<'cleanupGoogleEmailOtpDevRegistrationState'>,
  ): Promise<RouterApiResult<'cleanupGoogleEmailOtpDevRegistrationState'>> {
    return await this.googleEmailOtpSessions.cleanupDevRegistrationState(input);
  }

  async validateGoogleEmailOtpRegistrationCandidateWallet(
    input: RouterApiInput<'validateGoogleEmailOtpRegistrationCandidateWallet'>,
  ): Promise<RouterApiResult<'validateGoogleEmailOtpRegistrationCandidateWallet'>> {
    return await this.googleEmailOtpSessions.validateRegistrationCandidateWallet(input);
  }

  async readEmailOtpEnrollment(
    input: RouterApiInput<'readEmailOtpEnrollment'>,
  ): Promise<RouterApiResult<'readEmailOtpEnrollment'>> {
    return await this.emailOtpRecoveryService.readEmailOtpEnrollment(input);
  }

  async readActiveEmailOtpEnrollment(
    input: RouterApiInput<'readActiveEmailOtpEnrollment'>,
  ): Promise<RouterApiResult<'readActiveEmailOtpEnrollment'>> {
    return await this.emailOtpRecoveryService.readActiveEmailOtpEnrollment(input);
  }

  async isEmailOtpStrongAuthRequired(
    input: RouterApiInput<'isEmailOtpStrongAuthRequired'>,
  ): Promise<RouterApiResult<'isEmailOtpStrongAuthRequired'>> {
    return await this.emailOtpRecoveryService.isEmailOtpStrongAuthRequired(input);
  }

  async markEmailOtpStrongAuthSatisfied(
    input: RouterApiInput<'markEmailOtpStrongAuthSatisfied'>,
  ): Promise<RouterApiResult<'markEmailOtpStrongAuthSatisfied'>> {
    return await this.emailOtpRecoveryService.markEmailOtpStrongAuthSatisfied(input);
  }

  async getEmailOtpRecoveryCodeStatus(
    input: RouterApiInput<'getEmailOtpRecoveryCodeStatus'>,
  ): Promise<RouterApiResult<'getEmailOtpRecoveryCodeStatus'>> {
    return await this.emailOtpRecoveryService.getEmailOtpRecoveryCodeStatus(input);
  }

  async createEmailOtpChallenge(
    input: RouterApiInput<'createEmailOtpChallenge'>,
  ): Promise<RouterApiResult<'createEmailOtpChallenge'>> {
    return await this.emailOtpChallengeService.createEmailOtpChallenge(input);
  }

  async createEmailOtpEnrollmentChallenge(
    input: RouterApiInput<'createEmailOtpEnrollmentChallenge'>,
  ): Promise<RouterApiResult<'createEmailOtpEnrollmentChallenge'>> {
    return await this.emailOtpChallengeService.createEmailOtpEnrollmentChallenge(input);
  }

  async createEmailOtpDeviceRecoveryChallenge(
    input: RouterApiInput<'createEmailOtpDeviceRecoveryChallenge'>,
  ): Promise<RouterApiResult<'createEmailOtpDeviceRecoveryChallenge'>> {
    return await this.emailOtpChallengeService.createEmailOtpDeviceRecoveryChallenge(input);
  }

  async verifyEmailOtpEnrollment(
    input: RouterApiInput<'verifyEmailOtpEnrollment'>,
  ): Promise<RouterApiResult<'verifyEmailOtpEnrollment'>> {
    return await this.emailOtpChallengeService.verifyEmailOtpEnrollment(input);
  }

  async verifyEmailOtpChallenge(
    input: RouterApiInput<'verifyEmailOtpChallenge'>,
  ): Promise<RouterApiResult<'verifyEmailOtpChallenge'>> {
    return await this.emailOtpChallengeService.verifyEmailOtpChallenge(input);
  }

  async revokeWalletAuthMethod(
    input: RouterApiInput<'revokeWalletAuthMethod'>,
  ): Promise<RouterApiResult<'revokeWalletAuthMethod'>> {
    return await this.walletAuthMethods.revokeWalletAuthMethod(input);
  }

  async removeEmailOtpServerSeal(
    input: RouterApiInput<'removeEmailOtpServerSeal'>,
  ): Promise<RouterApiResult<'removeEmailOtpServerSeal'>> {
    return await this.emailOtpServerSeal.removeEmailOtpServerSeal(input);
  }

  async applyEmailOtpServerSeal(
    input: RouterApiInput<'applyEmailOtpServerSeal'>,
  ): Promise<RouterApiResult<'applyEmailOtpServerSeal'>> {
    return await this.emailOtpServerSeal.applyEmailOtpServerSeal(input);
  }

  async verifyEmailOtpDeviceRecoveryChallenge(
    input: RouterApiInput<'verifyEmailOtpDeviceRecoveryChallenge'>,
  ): Promise<RouterApiResult<'verifyEmailOtpDeviceRecoveryChallenge'>> {
    return await this.emailOtpRecoveryService.verifyEmailOtpDeviceRecoveryChallenge(input);
  }

  async readEmailOtpOutboxEntry(
    input: RouterApiInput<'readEmailOtpOutboxEntry'>,
  ): Promise<RouterApiResult<'readEmailOtpOutboxEntry'>> {
    return await this.emailOtpChallengeService.readEmailOtpOutboxEntry(input);
  }

  async createEmailOtpUnlockChallenge(
    input: RouterApiInput<'createEmailOtpUnlockChallenge'>,
  ): Promise<RouterApiResult<'createEmailOtpUnlockChallenge'>> {
    return await this.emailOtpRecoveryService.createEmailOtpUnlockChallenge(input);
  }

  async verifyEmailOtpUnlockProof(
    input: RouterApiInput<'verifyEmailOtpUnlockProof'>,
  ): Promise<RouterApiResult<'verifyEmailOtpUnlockProof'>> {
    return await this.emailOtpRecoveryService.verifyEmailOtpUnlockProof(input);
  }

  async consumeEmailOtpGrant(
    input: RouterApiInput<'consumeEmailOtpGrant'>,
  ): Promise<RouterApiResult<'consumeEmailOtpGrant'>> {
    return await this.emailOtpRecoveryService.consumeEmailOtpGrant(input);
  }

  async consumeEmailOtpRecoveryKey(
    input: RouterApiInput<'consumeEmailOtpRecoveryKey'>,
  ): Promise<RouterApiResult<'consumeEmailOtpRecoveryKey'>> {
    return await this.emailOtpRecoveryService.consumeEmailOtpRecoveryKey(input);
  }

  async rotateEmailOtpRecoveryKeys(
    input: RouterApiInput<'rotateEmailOtpRecoveryKeys'>,
  ): Promise<RouterApiResult<'rotateEmailOtpRecoveryKeys'>> {
    return await this.emailOtpRecoveryService.rotateEmailOtpRecoveryKeys(input);
  }

  async recordEmailOtpRecoveryKeyAttemptFailure(
    input: RouterApiInput<'recordEmailOtpRecoveryKeyAttemptFailure'>,
  ): Promise<RouterApiResult<'recordEmailOtpRecoveryKeyAttemptFailure'>> {
    return await this.emailOtpRecoveryService.recordEmailOtpRecoveryKeyAttemptFailure(input);
  }

  async getRecoverySession(
    input: RouterApiInput<'getRecoverySession'>,
  ): Promise<RouterApiResult<'getRecoverySession'>> {
    return await this.sessionService.getRecoverySession(input);
  }

  async updateRecoverySessionStatus(
    input: RouterApiInput<'updateRecoverySessionStatus'>,
  ): Promise<RouterApiResult<'updateRecoverySessionStatus'>> {
    return await this.sessionService.updateRecoverySessionStatus(input);
  }

  async recordRecoveryExecution(
    input: RouterApiInput<'recordRecoveryExecution'>,
  ): Promise<RouterApiResult<'recordRecoveryExecution'>> {
    return await this.sessionService.recordRecoveryExecution(input);
  }

  async getOrCreateAppSessionVersion(
    input: RouterApiInput<'getOrCreateAppSessionVersion'>,
  ): Promise<RouterApiResult<'getOrCreateAppSessionVersion'>> {
    return await this.sessionService.getOrCreateAppSessionVersion(input);
  }

  async rotateAppSessionVersion(
    input: RouterApiInput<'rotateAppSessionVersion'>,
  ): Promise<RouterApiResult<'rotateAppSessionVersion'>> {
    return await this.sessionService.rotateAppSessionVersion(input);
  }

  async validateAppSessionVersion(
    input: RouterApiInput<'validateAppSessionVersion'>,
  ): Promise<RouterApiResult<'validateAppSessionVersion'>> {
    return await this.sessionService.validateAppSessionVersion(input);
  }

  async listWebAuthnAuthenticatorsForUser(
    input: RouterApiInput<'listWebAuthnAuthenticatorsForUser'>,
  ): Promise<RouterApiResult<'listWebAuthnAuthenticatorsForUser'>> {
    return await this.webAuthnAuthService.listWebAuthnAuthenticatorsForUser(input);
  }

  async createWebAuthnLoginOptions(
    input: RouterApiInput<'createWebAuthnLoginOptions'>,
  ): Promise<RouterApiResult<'createWebAuthnLoginOptions'>> {
    return await this.webAuthnAuthService.createWebAuthnLoginOptions(input);
  }

  async createWebAuthnSyncAccountOptions(
    input: RouterApiInput<'createWebAuthnSyncAccountOptions'>,
  ): Promise<RouterApiResult<'createWebAuthnSyncAccountOptions'>> {
    return await this.webAuthnAuthService.createWebAuthnSyncAccountOptions(input);
  }

  async verifyWebAuthnAuthenticationLite(
    input: RouterApiInput<'verifyWebAuthnAuthenticationLite'>,
  ): Promise<RouterApiResult<'verifyWebAuthnAuthenticationLite'>> {
    return await this.webAuthnAuthService.verifyWebAuthnAuthenticationLite(input);
  }

  async verifyWebAuthnLogin(
    input: RouterApiInput<'verifyWebAuthnLogin'>,
  ): Promise<RouterApiResult<'verifyWebAuthnLogin'>> {
    return await this.webAuthnAuthService.verifyWebAuthnLogin(input);
  }

  async verifyWebAuthnSyncAccount(
    input: RouterApiInput<'verifyWebAuthnSyncAccount'>,
  ): Promise<RouterApiResult<'verifyWebAuthnSyncAccount'>> {
    return await this.webAuthnAuthService.verifyWebAuthnSyncAccount(input);
  }

  async listNearPublicKeysForUser(
    input: RouterApiInput<'listNearPublicKeysForUser'>,
  ): Promise<RouterApiResult<'listNearPublicKeysForUser'>> {
    return await this.nearPublicKeys.listForRelayUser(input);
  }

  async listThresholdEcdsaKeyIdentityTargetsForUser(
    input: RouterApiInput<'listThresholdEcdsaKeyIdentityTargetsForUser'>,
  ): Promise<RouterApiResult<'listThresholdEcdsaKeyIdentityTargetsForUser'>> {
    return await this.thresholdSigning.listThresholdEcdsaKeyIdentityTargetsForUser(input);
  }

  async listWalletEcdsaKeyFactsInventory(
    input: RouterApiInput<'listWalletEcdsaKeyFactsInventory'>,
  ): Promise<RouterApiResult<'listWalletEcdsaKeyFactsInventory'>> {
    return await this.thresholdSigning.listWalletEcdsaKeyFactsInventory(input);
  }

  async fundImplicitNearAccount(
    input: RouterApiInput<'fundImplicitNearAccount'>,
  ): Promise<RouterApiResult<'fundImplicitNearAccount'>> {
    if (!this.options.implicitNearAccountTestFundingEnabled) {
      return {
        ok: false,
        code: 'not_configured',
        message: 'Implicit NEAR account test funding is not enabled on this server',
      };
    }
    const relayerAccount = this.options.relayerAccount;
    const relayerPrivateKey = this.options.relayerPrivateKey;
    const nearRpcUrl = this.options.nearRpcUrl;
    const fundedAmountYocto = this.options.accountInitialBalance;
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
      relayerPublicKey: this.options.relayerPublicKey,
      nearRpcUrl,
      fundedAmountYocto,
    });
  }

  private async createSponsoredNamedNearAccount(input: {
    readonly accountId: string;
    readonly publicKey: string;
  }): Promise<AccountCreationResult> {
    const relayerAccount = this.options.relayerAccount;
    const relayerPrivateKey = this.options.relayerPrivateKey;
    const nearRpcUrl = this.options.nearRpcUrl;
    const initialBalanceYocto = this.options.accountInitialBalance;
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
      relayerPublicKey: this.options.relayerPublicKey,
      nearRpcUrl,
      initialBalanceYocto,
    });
  }

  getConfiguredRelayerAccount(): RouterApiResult<'getConfiguredRelayerAccount'> {
    return this.thresholdSigning.getConfiguredRelayerAccount();
  }

  async getRelayerAccount(): Promise<RouterApiResult<'getRelayerAccount'>> {
    return await this.thresholdSigning.getRelayerAccount();
  }

  getThresholdSigningService(): RouterApiResult<'getThresholdSigningService'> {
    return this.thresholdSigning.getThresholdSigningService();
  }

  async ecdsaHssRoleLocalBootstrap(
    request: RouterApiInput<'ecdsaHssRoleLocalBootstrap'>,
  ): Promise<RouterApiResult<'ecdsaHssRoleLocalBootstrap'>> {
    return await this.thresholdSigning.ecdsaHssRoleLocalBootstrap(request);
  }

  async verifyEcdsaHssRoleLocalClientRootProofForExistingKey(
    request: RouterApiInput<'verifyEcdsaHssRoleLocalClientRootProofForExistingKey'>,
  ): Promise<RouterApiResult<'verifyEcdsaHssRoleLocalClientRootProofForExistingKey'>> {
    return await this.thresholdSigning.verifyEcdsaHssRoleLocalClientRootProofForExistingKey(
      request,
    );
  }

  async ecdsaHssRoleLocalExportShare(
    input: RouterApiInput<'ecdsaHssRoleLocalExportShare'>,
  ): Promise<RouterApiResult<'ecdsaHssRoleLocalExportShare'>> {
    return await this.thresholdSigning.ecdsaHssRoleLocalExportShare(input);
  }

  getGoogleOidcPublicConfig(): RouterApiResult<'getGoogleOidcPublicConfig'> {
    return this.oidcVerification.getGoogleOidcPublicConfig();
  }

  async verifyOidcJwtExchange(
    input: RouterApiInput<'verifyOidcJwtExchange'>,
  ): Promise<RouterApiResult<'verifyOidcJwtExchange'>> {
    return await this.oidcVerification.verifyOidcJwtExchange(input);
  }

  async verifyGoogleLogin(
    input: RouterApiInput<'verifyGoogleLogin'>,
  ): Promise<RouterApiResult<'verifyGoogleLogin'>> {
    return await this.oidcVerification.verifyGoogleLogin(input);
  }

  private getRegistrationCeremonyIntentStore(): CloudflareD1RegistrationCeremonyIntentStore | null {
    if (this.registrationCeremonyIntentStore) return this.registrationCeremonyIntentStore;
    const config = resolveRegistrationCeremonyDoConfig(this.options.thresholdStore);
    if (!config) return null;
    this.registrationCeremonyIntentStore = new CloudflareD1RegistrationCeremonyIntentStore(config);
    return this.registrationCeremonyIntentStore;
  }

  private getWalletAuthMethodStore(): WalletAuthMethodStore {
    if (this.walletAuthMethodStore) return this.walletAuthMethodStore;
    this.walletAuthMethodStore = new D1WalletAuthMethodStore({
      database: this.options.database,
      namespace: this.options.namespace,
      orgId: this.options.orgId,
      projectId: this.options.projectId,
      envId: this.options.envId,
      ensureSchema: false,
    });
    return this.walletAuthMethodStore;
  }

  private getWalletStore(): WalletStore {
    if (this.walletStore) return this.walletStore;
    this.walletStore = new D1WalletStore({
      database: this.options.database,
      namespace: this.options.namespace,
      orgId: this.options.orgId,
      projectId: this.options.projectId,
      envId: this.options.envId,
      ensureSchema: false,
    });
    return this.walletStore;
  }

  private scopePrepare(sql: string, values: readonly unknown[]): D1PreparedStatementLike {
    return this.options.database.prepare(sql).bind(...this.scopeValues(values));
  }

  private scopeValues(values: readonly unknown[]): readonly unknown[] {
    return [
      this.options.namespace,
      this.options.orgId,
      this.options.projectId,
      this.options.envId,
      ...values,
    ];
  }
}

export function createCloudflareD1RouterApiAuthService(
  input: CloudflareD1RouterApiAuthServiceOptions,
): RouterApiAuthService {
  return new CloudflareD1RouterApiAuthMetadataService(input);
}
