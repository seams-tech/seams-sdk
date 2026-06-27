import type { CloudflareRelayAuthService } from '../authServicePort';

const DEFAULT_DISABLED_RELAYER_ACCOUNT = 'cloudflare-disabled-relayer.local';
const DEFAULT_DISABLED_RELAYER_PUBLIC_KEY = 'disabled-relayer-public-key';

type DisabledRelayerAccount = Awaited<
  ReturnType<CloudflareRelayAuthService['getRelayerAccount']>
>;

type DisabledRelayReadinessService = Pick<
  CloudflareRelayAuthService,
  | 'emailRecovery'
  | 'getConfiguredRelayerAccount'
  | 'getGoogleOidcPublicConfig'
  | 'getRelayerAccount'
  | 'getThresholdSigningService'
>;

type DisabledSignerMethods = Omit<
  CloudflareRelayAuthService,
  keyof DisabledRelayReadinessService
>;

export interface DisabledCloudflareRelayAuthServiceInput {
  readonly relayerAccount?: string;
  readonly relayerPublicKey?: string;
}

function normalizeDisabledString(input: string | undefined, fallback: string): string {
  const normalized = String(input || '').trim();
  return normalized || fallback;
}

function disabledSignerServiceError(): Error {
  return new Error('Cloudflare D1/DO signer service is not configured for this Worker');
}

async function rejectDisabledSignerService(): Promise<never> {
  throw disabledSignerServiceError();
}

class DisabledRelayReadinessAuthService implements DisabledRelayReadinessService {
  readonly emailRecovery = null;

  private readonly relayerAccount: string;
  private readonly relayerPublicKey: string;

  constructor(input: DisabledCloudflareRelayAuthServiceInput) {
    this.relayerAccount = normalizeDisabledString(
      input.relayerAccount,
      DEFAULT_DISABLED_RELAYER_ACCOUNT,
    );
    this.relayerPublicKey = normalizeDisabledString(
      input.relayerPublicKey,
      DEFAULT_DISABLED_RELAYER_PUBLIC_KEY,
    );
  }

  getConfiguredRelayerAccount(): string {
    return this.relayerAccount;
  }

  async getRelayerAccount(): Promise<DisabledRelayerAccount> {
    return {
      accountId: this.relayerAccount,
      publicKey: this.relayerPublicKey,
    };
  }

  getGoogleOidcPublicConfig(): ReturnType<CloudflareRelayAuthService['getGoogleOidcPublicConfig']> {
    return { configured: false };
  }

  getThresholdSigningService(): ReturnType<
    CloudflareRelayAuthService['getThresholdSigningService']
  > {
    return null;
  }
}

const disabledSignerMethods: DisabledSignerMethods = {
  applyEmailOtpServerSeal: rejectDisabledSignerService,
  cleanupGoogleEmailOtpDevRegistrationState: rejectDisabledSignerService,
  consumeEmailOtpGrant: rejectDisabledSignerService,
  consumeGoogleEmailOtpRegistrationAttemptRateLimit: rejectDisabledSignerService,
  consumeEmailOtpRecoveryKey: rejectDisabledSignerService,
  createAddAuthMethodIntent: rejectDisabledSignerService,
  createAddSignerIntent: rejectDisabledSignerService,
  createEmailOtpChallenge: rejectDisabledSignerService,
  createEmailOtpDeviceRecoveryChallenge: rejectDisabledSignerService,
  createEmailOtpEnrollmentChallenge: rejectDisabledSignerService,
  createEmailOtpUnlockChallenge: rejectDisabledSignerService,
  createRegistrationIntent: rejectDisabledSignerService,
  createWebAuthnLoginOptions: rejectDisabledSignerService,
  createWebAuthnSyncAccountOptions: rejectDisabledSignerService,
  ecdsaHssRoleLocalBootstrap: rejectDisabledSignerService,
  ecdsaHssRoleLocalExportShare: rejectDisabledSignerService,
  executeSignedDelegate: rejectDisabledSignerService,
  finalizeWalletAddAuthMethod: rejectDisabledSignerService,
  finalizeWalletAddSigner: rejectDisabledSignerService,
  finalizeWalletRegistration: rejectDisabledSignerService,
  getEmailOtpRecoveryCodeStatus: rejectDisabledSignerService,
  getOrCreateAppSessionVersion: rejectDisabledSignerService,
  getRecoverySession: rejectDisabledSignerService,
  isEmailOtpStrongAuthRequired: rejectDisabledSignerService,
  linkIdentity: rejectDisabledSignerService,
  listIdentities: rejectDisabledSignerService,
  listNearPublicKeysForUser: rejectDisabledSignerService,
  listThresholdEcdsaKeyIdentityTargetsForUser: rejectDisabledSignerService,
  listWalletEcdsaKeyFactsInventory: rejectDisabledSignerService,
  listWebAuthnAuthenticatorsForUser: rejectDisabledSignerService,
  markEmailOtpStrongAuthSatisfied: rejectDisabledSignerService,
  prepareEmailRecovery: rejectDisabledSignerService,
  prepareWalletRegistration: rejectDisabledSignerService,
  readActiveEmailOtpEnrollment: rejectDisabledSignerService,
  readEmailOtpEnrollment: rejectDisabledSignerService,
  readEmailOtpOutboxEntry: rejectDisabledSignerService,
  recordEmailOtpRecoveryKeyAttemptFailure: rejectDisabledSignerService,
  recordRecoveryExecution: rejectDisabledSignerService,
  removeEmailOtpServerSeal: rejectDisabledSignerService,
  respondWalletAddSignerHss: rejectDisabledSignerService,
  respondWalletRegistrationHss: rejectDisabledSignerService,
  resolveGoogleEmailOtpSession: rejectDisabledSignerService,
  resolveOidcWalletId: rejectDisabledSignerService,
  respondEmailRecoveryEcdsa: rejectDisabledSignerService,
  revokeWalletAuthMethod: rejectDisabledSignerService,
  rotateEmailOtpRecoveryKeys: rejectDisabledSignerService,
  rotateAppSessionVersion: rejectDisabledSignerService,
  startWalletAddAuthMethod: rejectDisabledSignerService,
  startWalletAddSigner: rejectDisabledSignerService,
  startWalletRegistration: rejectDisabledSignerService,
  unlinkIdentity: rejectDisabledSignerService,
  updateRecoverySessionStatus: rejectDisabledSignerService,
  validateAppSessionVersion: rejectDisabledSignerService,
  verifyEmailOtpChallenge: rejectDisabledSignerService,
  verifyEmailOtpDeviceRecoveryChallenge: rejectDisabledSignerService,
  verifyEmailOtpEnrollment: rejectDisabledSignerService,
  verifyEmailOtpUnlockProof: rejectDisabledSignerService,
  verifyEcdsaHssRoleLocalClientRootProofForExistingKey: rejectDisabledSignerService,
  verifyGoogleLogin: rejectDisabledSignerService,
  verifyOidcJwtExchange: rejectDisabledSignerService,
  verifyWebAuthnAuthenticationLite: rejectDisabledSignerService,
  verifyWebAuthnLogin: rejectDisabledSignerService,
  verifyWebAuthnSyncAccount: rejectDisabledSignerService,
};

export function createDisabledCloudflareRelayAuthService(
  input: DisabledCloudflareRelayAuthServiceInput = {},
): CloudflareRelayAuthService {
  return Object.assign(new DisabledRelayReadinessAuthService(input), disabledSignerMethods);
}
