import type {
  BootstrapWarmEcdsaCapabilityResult,
  NoPromptWarmSessionDeps,
  ReuseWarmEcdsaBootstrapResult,
} from './ecdsaWarmCapabilityBootstrap';

declare const getWarmSession: NoPromptWarmSessionDeps['getWarmSession'];
declare const discoverPersistedSessionsForWallet: NonNullable<
  NoPromptWarmSessionDeps['discoverPersistedSessionsForWallet']
>;
const noPromptDeps: NoPromptWarmSessionDeps = {
  getWarmSession,
  discoverPersistedSessionsForWallet,
};

void noPromptDeps;

// No-prompt reuse resolves warm material through the capability reader and the
// durable sealed-session port alone: it holds no signing-session store and no
// reconnect port, so it cannot re-provision material behind the user's back.
const noPromptDepsWithSessionStore: NoPromptWarmSessionDeps = {
  getWarmSession,
  discoverPersistedSessionsForWallet,
  // @ts-expect-error No-prompt reuse dependencies cannot carry a signing-session store.
  ecdsaSessions: {},
};

void noPromptDepsWithSessionStore;

const noPromptDepsWithTouchId: NoPromptWarmSessionDeps = {
  getWarmSession,
  discoverPersistedSessionsForWallet,
  // @ts-expect-error No-prompt reuse dependencies cannot carry TouchID ports.
  touchIdPrompt: {},
};

void noPromptDepsWithTouchId;

const noPromptDepsWithFreshBootstrap: NoPromptWarmSessionDeps = {
  getWarmSession,
  discoverPersistedSessionsForWallet,
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
