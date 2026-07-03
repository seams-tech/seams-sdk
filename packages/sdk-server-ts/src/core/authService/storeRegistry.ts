import type { AuthServiceConfig } from '../types';
import type { NormalizedLogger } from '../logger';
import {
  createEmailOtpAuthStateStore,
  createEmailOtpChallengeStore,
  createEmailOtpGrantStore,
  createEmailOtpRecoveryWrappedEnrollmentEscrowStore,
  createEmailOtpRegistrationAttemptStore,
  createEmailOtpUnlockChallengeStore,
  createEmailOtpWalletEnrollmentStore,
  type EmailOtpAuthStateStore,
  type EmailOtpChallengeStore,
  type EmailOtpGrantStore,
  type EmailOtpRecoveryWrappedEnrollmentEscrowStore,
  type EmailOtpRegistrationAttemptStore,
  type EmailOtpUnlockChallengeStore,
  type EmailOtpWalletEnrollmentStore,
} from '../EmailOtpStores';
import {
  createEmailRecoveryPreparationStore,
  type EmailRecoveryPreparationStore,
} from '../EmailRecoveryPreparationStore';
import { createIdentityStore, type IdentityStore } from '../IdentityStore';
import { createNearPublicKeyStore, type NearPublicKeyStore } from '../NearPublicKeyStore';
import {
  createRecoveryExecutionStore,
  type RecoveryExecutionStore,
} from '../RecoveryExecutionStore';
import {
  createRecoverySessionStore,
  type RecoverySessionStore,
} from '../RecoverySessionStore';
import {
  createRegistrationCeremonyStore,
  type RegistrationCeremonyStore,
} from '../RegistrationCeremonyStore';
import {
  createWalletAuthMethodStore,
  type WalletAuthMethodStore,
} from '../WalletAuthMethodStore';
import { createWalletStore, type WalletStore } from '../WalletStore';
import {
  createWebAuthnAuthenticatorStore,
  type WebAuthnAuthenticatorStore,
} from '../WebAuthnAuthenticatorStore';
import {
  createWebAuthnCredentialBindingStore,
  type WebAuthnCredentialBindingStore,
} from '../WebAuthnCredentialBindingStore';
import {
  createWebAuthnLoginChallengeStore,
  type WebAuthnLoginChallengeStore,
} from '../WebAuthnLoginChallengeStore';
import {
  createWebAuthnSyncChallengeStore,
  type WebAuthnSyncChallengeStore,
} from '../WebAuthnSyncChallengeStore';
import type { SigningSessionSealRateLimiter } from '../../threshold/session/signingSessionSeal';
import type { AuthServiceConfigSource } from './configValues';
import {
  createEmailOtpRateLimiter,
  createRegistrationPrepareRateLimiter,
} from './rateLimits';

type AuthServiceStoreRegistryInput = {
  readonly config: AuthServiceConfig;
  readonly logger: NormalizedLogger;
  readonly isNode: () => boolean;
};

type StoreFactoryInput = {
  readonly config: AuthServiceConfig['thresholdStore'] | null;
  readonly logger: NormalizedLogger;
  readonly isNode: boolean;
};

function createStoreFactoryInput(input: AuthServiceStoreRegistryInput): StoreFactoryInput {
  return {
    config: input.config.thresholdStore || null,
    logger: input.logger,
    isNode: input.isNode(),
  };
}

export class AuthServiceStoreRegistry {
  private webAuthnAuthenticatorStore: WebAuthnAuthenticatorStore | null = null;
  private webAuthnLoginChallengeStore: WebAuthnLoginChallengeStore | null = null;
  private webAuthnCredentialBindingStore: WebAuthnCredentialBindingStore | null = null;
  private webAuthnSyncChallengeStore: WebAuthnSyncChallengeStore | null = null;
  private emailOtpChallengeStore: EmailOtpChallengeStore | null = null;
  private emailOtpGrantStore: EmailOtpGrantStore | null = null;
  private emailOtpWalletEnrollmentStore: EmailOtpWalletEnrollmentStore | null = null;
  private emailOtpRecoveryWrappedEnrollmentEscrowStore:
    | EmailOtpRecoveryWrappedEnrollmentEscrowStore
    | null = null;
  private emailOtpAuthStateStore: EmailOtpAuthStateStore | null = null;
  private emailOtpUnlockChallengeStore: EmailOtpUnlockChallengeStore | null = null;
  private emailOtpRegistrationAttemptStore: EmailOtpRegistrationAttemptStore | null = null;
  private emailOtpRateLimiter: SigningSessionSealRateLimiter | null = null;
  private registrationPrepareRateLimiter: SigningSessionSealRateLimiter | null = null;
  private emailRecoveryPreparationStore: EmailRecoveryPreparationStore | null = null;
  private nearPublicKeyStore: NearPublicKeyStore | null = null;
  private recoverySessionStore: RecoverySessionStore | null = null;
  private recoveryExecutionStore: RecoveryExecutionStore | null = null;
  private identityStore: IdentityStore | null = null;
  private registrationCeremonyStore: RegistrationCeremonyStore | null = null;
  private walletStore: WalletStore | null = null;
  private walletAuthMethodStore: WalletAuthMethodStore | null = null;

  constructor(private readonly input: AuthServiceStoreRegistryInput) {}

  getWebAuthnAuthenticatorStore(): WebAuthnAuthenticatorStore {
    this.webAuthnAuthenticatorStore ??= createWebAuthnAuthenticatorStore(
      createStoreFactoryInput(this.input),
    );
    return this.webAuthnAuthenticatorStore;
  }

  getWebAuthnLoginChallengeStore(): WebAuthnLoginChallengeStore {
    this.webAuthnLoginChallengeStore ??= createWebAuthnLoginChallengeStore(
      createStoreFactoryInput(this.input),
    );
    return this.webAuthnLoginChallengeStore;
  }

  getWebAuthnCredentialBindingStore(): WebAuthnCredentialBindingStore {
    this.webAuthnCredentialBindingStore ??= createWebAuthnCredentialBindingStore(
      createStoreFactoryInput(this.input),
    );
    return this.webAuthnCredentialBindingStore;
  }

  getWebAuthnSyncChallengeStore(): WebAuthnSyncChallengeStore {
    this.webAuthnSyncChallengeStore ??= createWebAuthnSyncChallengeStore(
      createStoreFactoryInput(this.input),
    );
    return this.webAuthnSyncChallengeStore;
  }

  getRegistrationCeremonyStore(): RegistrationCeremonyStore {
    this.registrationCeremonyStore ??= createRegistrationCeremonyStore(
      createStoreFactoryInput(this.input),
    );
    return this.registrationCeremonyStore;
  }

  getWalletStore(): WalletStore {
    this.walletStore ??= createWalletStore(createStoreFactoryInput(this.input));
    return this.walletStore;
  }

  getWalletAuthMethodStore(): WalletAuthMethodStore {
    this.walletAuthMethodStore ??= createWalletAuthMethodStore(createStoreFactoryInput(this.input));
    return this.walletAuthMethodStore;
  }

  getEmailOtpChallengeStore(): EmailOtpChallengeStore {
    this.emailOtpChallengeStore ??= createEmailOtpChallengeStore(createStoreFactoryInput(this.input));
    return this.emailOtpChallengeStore;
  }

  getEmailOtpGrantStore(): EmailOtpGrantStore {
    this.emailOtpGrantStore ??= createEmailOtpGrantStore(createStoreFactoryInput(this.input));
    return this.emailOtpGrantStore;
  }

  getEmailOtpWalletEnrollmentStore(): EmailOtpWalletEnrollmentStore {
    this.emailOtpWalletEnrollmentStore ??= createEmailOtpWalletEnrollmentStore(
      createStoreFactoryInput(this.input),
    );
    return this.emailOtpWalletEnrollmentStore;
  }

  getEmailOtpRecoveryWrappedEnrollmentEscrowStore(): EmailOtpRecoveryWrappedEnrollmentEscrowStore {
    this.emailOtpRecoveryWrappedEnrollmentEscrowStore ??=
      createEmailOtpRecoveryWrappedEnrollmentEscrowStore(createStoreFactoryInput(this.input));
    return this.emailOtpRecoveryWrappedEnrollmentEscrowStore;
  }

  getEmailOtpAuthStateStore(): EmailOtpAuthStateStore {
    this.emailOtpAuthStateStore ??= createEmailOtpAuthStateStore(createStoreFactoryInput(this.input));
    return this.emailOtpAuthStateStore;
  }

  getEmailOtpUnlockChallengeStore(): EmailOtpUnlockChallengeStore {
    this.emailOtpUnlockChallengeStore ??= createEmailOtpUnlockChallengeStore(
      createStoreFactoryInput(this.input),
    );
    return this.emailOtpUnlockChallengeStore;
  }

  getEmailOtpRegistrationAttemptStore(): EmailOtpRegistrationAttemptStore {
    this.emailOtpRegistrationAttemptStore ??= createEmailOtpRegistrationAttemptStore(
      createStoreFactoryInput(this.input),
    );
    return this.emailOtpRegistrationAttemptStore;
  }

  getRegistrationPrepareRateLimiter(): SigningSessionSealRateLimiter {
    this.registrationPrepareRateLimiter ??= createRegistrationPrepareRateLimiter({
      thresholdStore: this.input.config.thresholdStore as AuthServiceConfigSource,
    });
    return this.registrationPrepareRateLimiter;
  }

  getEmailOtpRateLimiter(): SigningSessionSealRateLimiter {
    this.emailOtpRateLimiter ??= createEmailOtpRateLimiter({
      thresholdStore: this.input.config.thresholdStore as AuthServiceConfigSource,
    });
    return this.emailOtpRateLimiter;
  }

  getIdentityStore(): IdentityStore {
    this.identityStore ??= createIdentityStore(createStoreFactoryInput(this.input));
    return this.identityStore;
  }

  getEmailRecoveryPreparationStore(): EmailRecoveryPreparationStore {
    this.emailRecoveryPreparationStore ??= createEmailRecoveryPreparationStore(
      createStoreFactoryInput(this.input),
    );
    return this.emailRecoveryPreparationStore;
  }

  getNearPublicKeyStore(): NearPublicKeyStore {
    this.nearPublicKeyStore ??= createNearPublicKeyStore(createStoreFactoryInput(this.input));
    return this.nearPublicKeyStore;
  }

  getRecoverySessionStore(): RecoverySessionStore {
    this.recoverySessionStore ??= createRecoverySessionStore(createStoreFactoryInput(this.input));
    return this.recoverySessionStore;
  }

  getRecoveryExecutionStore(): RecoveryExecutionStore {
    this.recoveryExecutionStore ??= createRecoveryExecutionStore(createStoreFactoryInput(this.input));
    return this.recoveryExecutionStore;
  }
}
