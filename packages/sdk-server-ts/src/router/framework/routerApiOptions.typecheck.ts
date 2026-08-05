import type {
  RouterApiEmailRecoveryAuthService,
  RouterApiEmailRecoveryExecutionService,
  RouterApiOptions,
  RouterApiWebhookEmitter,
} from './routerApi';
import type {
  CreateSigningSessionSealOptionsInput,
  SigningSessionSealService,
} from '../threshold/session/signingSessionSeal';

declare const emailRecoveryAuthService: RouterApiEmailRecoveryAuthService;
declare const emailRecoveryExecutionService: RouterApiEmailRecoveryExecutionService;
declare const routerApiWebhookEmitter: RouterApiWebhookEmitter;
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

const signingSessionSeal: RouterApiOptions = {
  signingSessionSeal: {
    service: signingSessionSealService,
  },
};

const routerApiWebhookOptions: RouterApiOptions = {
  routerApiWebhooks: {
    emitter: routerApiWebhookEmitter,
  },
};

const oldEmailRecoveryFlag: RouterApiOptions = {
  // @ts-expect-error Email recovery route capability requires structural services.
  emailRecovery: { enabled: true },
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

const oldRouterApiWebhookServiceField: RouterApiOptions = {
  routerApiWebhooks: {
    emitter: routerApiWebhookEmitter,
    // @ts-expect-error Router API webhooks use the signer-owned emitter port.
    service: routerApiWebhookEmitter,
  },
};

void configuredEmailRecovery;
void emailRecoveryPrepareOnly;
void signingSessionSeal;
void routerApiWebhookOptions;
void oldEmailRecoveryFlag;
void configuredEmailRecoveryWithoutExecution;
void prepareOnlyEmailRecoveryWithExecution;
void oldSigningSessionSealFlag;
void oldSigningSessionSealOptionsFlag;
void oldRouterApiWebhookServiceField;

export {};
