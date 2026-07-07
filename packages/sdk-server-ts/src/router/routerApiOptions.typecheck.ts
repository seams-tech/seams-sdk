import type {
  RouterApiEmailRecoveryAuthService,
  RouterApiEmailRecoveryExecutionService,
  RouterApiOptions,
} from './routerApi';
import type { ConsoleRouterApiSignedDelegateRouteOptions } from '../console/router/routeExtensions';
import type { SignedDelegateRouterApiAuthService } from '../console/router/routerApiSignedDelegate';
import type {
  CreateSigningSessionSealOptionsInput,
  SigningSessionSealService,
} from '../threshold/session/signingSessionSeal';

declare const emailRecoveryAuthService: RouterApiEmailRecoveryAuthService;
declare const emailRecoveryExecutionService: RouterApiEmailRecoveryExecutionService;
declare const signedDelegateAuthService: SignedDelegateRouterApiAuthService;
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

const signedDelegateRoute: ConsoleRouterApiSignedDelegateRouteOptions = {
  route: '/signed-delegate',
  authService: signedDelegateAuthService,
  billing: null,
  ledger: null,
  runtimeSnapshots: null,
  publishableKeyAuth: null,
  observabilityIngestion: null,
  prepaidReservations: null,
  pricing: null,
  spendCaps: null,
  webhooks: null,
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

// @ts-expect-error Signed delegate extension route capability requires its auth service.
const signedDelegateRouteWithoutAuthService: ConsoleRouterApiSignedDelegateRouteOptions = {
  route: '/signed-delegate',
  billing: null,
  ledger: null,
  runtimeSnapshots: null,
  publishableKeyAuth: null,
  observabilityIngestion: null,
  prepaidReservations: null,
  pricing: null,
  spendCaps: null,
  webhooks: null,
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
void signedDelegateRoute;
void signingSessionSeal;
void oldEmailRecoveryFlag;
void configuredEmailRecoveryWithoutExecution;
void prepareOnlyEmailRecoveryWithExecution;
void signedDelegateRouteWithoutAuthService;
void oldSigningSessionSealFlag;
void oldSigningSessionSealOptionsFlag;

export {};
