import type {
  BootstrapWarmEcdsaCapabilityResult,
  NoPromptWarmSessionDeps,
  ReuseWarmEcdsaBootstrapResult,
} from './ecdsaWarmCapabilityBootstrap';

declare const getWarmSession: NoPromptWarmSessionDeps['getWarmSession'];
declare const restorePersistedSessionsForWallet: NonNullable<
  NoPromptWarmSessionDeps['restorePersistedSessionsForWallet']
>;
declare const claimEcdsaPasskeyPrfFirst: NoPromptWarmSessionDeps['claimEcdsaPasskeyPrfFirst'];
declare const reconnectWithThresholdSessionAuth: NoPromptWarmSessionDeps['reconnectWithThresholdSessionAuth'];
declare const ecdsaSessions: NoPromptWarmSessionDeps['ecdsaSessions'];

const noPromptDeps: NoPromptWarmSessionDeps = {
  getWarmSession,
  restorePersistedSessionsForWallet,
  claimEcdsaPasskeyPrfFirst,
  reconnectWithThresholdSessionAuth,
  ecdsaSessions,
};

void noPromptDeps;

const noPromptDepsWithTouchId: NoPromptWarmSessionDeps = {
  getWarmSession,
  restorePersistedSessionsForWallet,
  claimEcdsaPasskeyPrfFirst,
  reconnectWithThresholdSessionAuth,
  ecdsaSessions,
  // @ts-expect-error No-prompt reuse dependencies cannot carry TouchID ports.
  touchIdPrompt: {},
};

void noPromptDepsWithTouchId;

const noPromptDepsWithFreshBootstrap: NoPromptWarmSessionDeps = {
  getWarmSession,
  restorePersistedSessionsForWallet,
  claimEcdsaPasskeyPrfFirst,
  reconnectWithThresholdSessionAuth,
  ecdsaSessions,
  // @ts-expect-error No-prompt reuse dependencies cannot carry fresh bootstrap ports.
  freshBootstrap: {},
};

void noPromptDepsWithFreshBootstrap;

const reuseFailureWithPromptPayload: ReuseWarmEcdsaBootstrapResult = {
  ok: false,
  code: 'missing_exact_material',
  chainTargetKey: 'tempo:42431',
  // @ts-expect-error Reuse failures cannot carry prompt permission.
  promptAllowed: true,
};

void reuseFailureWithPromptPayload;

const reuseFailureWithAuthentication: ReuseWarmEcdsaBootstrapResult = {
  ok: false,
  code: 'sealed_restore_failed',
  chainTargetKey: 'tempo:42431',
  errorMessage: 'restore failed',
  // @ts-expect-error Reuse failures cannot carry WebAuthn authentication payloads.
  webauthnAuthentication: {},
};

void reuseFailureWithAuthentication;

const warmBootstrapFailureWithAuthentication: BootstrapWarmEcdsaCapabilityResult = {
  ok: false,
  kind: 'reuse_failed',
  failure: {
    ok: false,
    code: 'missing_exact_material',
    chainTargetKey: 'tempo:42431',
  },
  // @ts-expect-error Warm bootstrap failures cannot carry WebAuthn authentication payloads.
  webauthnAuthentication: {},
};

void warmBootstrapFailureWithAuthentication;

function assertNever(value: never): never {
  throw new Error(String(value));
}

function reuseWarmBootstrapResultLabel(result: ReuseWarmEcdsaBootstrapResult): string {
  if (result.ok) {
    switch (result.source) {
      case 'volatile_material':
      case 'sealed_restore':
        return result.source;
      default:
        return assertNever(result.source);
    }
  }
  switch (result.code) {
    case 'missing_exact_material':
    case 'sealed_restore_failed':
    case 'sealed_record_expired':
    case 'sealed_record_exhausted':
      return result.code;
    default:
      return assertNever(result.code);
  }
}

void reuseWarmBootstrapResultLabel;

function warmBootstrapResultLabel(result: BootstrapWarmEcdsaCapabilityResult): string {
  if (result.ok) return 'ready';
  switch (result.kind) {
    case 'reuse_failed':
      return reuseWarmBootstrapResultLabel(result.failure);
    default:
      return assertNever(result.kind);
  }
}

void warmBootstrapResultLabel;
