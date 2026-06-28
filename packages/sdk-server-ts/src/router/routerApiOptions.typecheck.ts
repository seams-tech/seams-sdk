import type {
  RouterApiEd25519RegistrationPrepareOptions,
  RouterApiEmailRecoveryAuthService,
  RouterApiEmailRecoveryExecutionService,
  RouterApiOptions,
  RouterApiSignedDelegateAuthService,
} from './routerApi';
import type {
  CreateSigningSessionSealOptionsInput,
  SigningSessionSealService,
} from '../threshold/session/signingSessionSeal';

declare const emailRecoveryAuthService: RouterApiEmailRecoveryAuthService;
declare const emailRecoveryExecutionService: RouterApiEmailRecoveryExecutionService;
declare const registrationPrepareAuthService: RouterApiEd25519RegistrationPrepareOptions['authService'];
declare const signedDelegateAuthService: RouterApiSignedDelegateAuthService;
declare const signingSessionSealService: SigningSessionSealService;

const configuredEmailRecovery: RouterApiOptions = {
  emailRecovery: {
    kind: 'prepare_and_execute',
    authService: emailRecoveryAuthService,
    executionService: emailRecoveryExecutionService,
  },
};

const emailRecoveryPrepareOnly: RouterApiOptions = {
  emailRecovery: {
    kind: 'prepare_only',
    authService: emailRecoveryAuthService,
  },
};

const ed25519RegistrationPrepare: RouterApiOptions = {
  ed25519RegistrationPrepare: {
    authService: registrationPrepareAuthService,
  },
};

const signedDelegate: RouterApiOptions = {
  signedDelegate: {
    route: '/signed-delegate',
    authService: signedDelegateAuthService,
  },
};

const signingSessionSeal: RouterApiOptions = {
  signingSessionSeal: {
    service: signingSessionSealService,
  },
};

const oldEmailRecoveryFlag: RouterApiOptions = {
  // @ts-expect-error Email recovery route capability requires structural services.
  emailRecovery: { enabled: true },
};

const oldEd25519RegistrationPrepareFlag: RouterApiOptions = {
  // @ts-expect-error Ed25519 registration prepare requires its auth service.
  ed25519RegistrationPrepare: { enabled: true },
};

const configuredEmailRecoveryWithoutExecution: RouterApiOptions = {
  // @ts-expect-error Executable email recovery requires an execution service.
  emailRecovery: {
    kind: 'prepare_and_execute',
    authService: emailRecoveryAuthService,
  },
};

const prepareOnlyEmailRecoveryWithExecution: RouterApiOptions = {
  emailRecovery: {
    kind: 'prepare_only',
    authService: emailRecoveryAuthService,
    // @ts-expect-error Prepare-only email recovery cannot carry an execution service.
    executionService: emailRecoveryExecutionService,
  },
};

const signedDelegateWithoutAuthService: RouterApiOptions = {
  // @ts-expect-error Signed delegate route capability requires its auth service.
  signedDelegate: { route: '/signed-delegate' },
};

const oldSigningSessionSealFlag: RouterApiOptions = {
  signingSessionSeal: {
    // @ts-expect-error Signing-session seal route capability is selected by providing the service.
    enabled: true,
    service: signingSessionSealService,
  },
};

const oldSigningSessionSealOptionsFlag: CreateSigningSessionSealOptionsInput = {
  // @ts-expect-error Signing-session seal options are constructed only when the route is mounted.
  enabled: true,
  shamirPrimeB64u: 'prime',
  serverEncryptExponentB64u: 'encrypt',
  serverDecryptExponentB64u: 'decrypt',
  thresholdStoreConfig: {},
};

void configuredEmailRecovery;
void emailRecoveryPrepareOnly;
void ed25519RegistrationPrepare;
void signedDelegate;
void signingSessionSeal;
void oldEmailRecoveryFlag;
void oldEd25519RegistrationPrepareFlag;
void configuredEmailRecoveryWithoutExecution;
void prepareOnlyEmailRecoveryWithExecution;
void signedDelegateWithoutAuthService;
void oldSigningSessionSealFlag;
void oldSigningSessionSealOptionsFlag;

export {};
