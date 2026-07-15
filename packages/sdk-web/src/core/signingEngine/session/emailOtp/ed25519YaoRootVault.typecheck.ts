import type {
  EmailOtpEd25519YaoRootBinding,
  EmailOtpEd25519YaoRootHandle,
  EmailOtpEd25519YaoRootScope,
} from './ed25519YaoRootVault';

const registrationScope = {
  kind: 'email_otp_ed25519_yao_root_scope_v1',
  purpose: 'registration',
  walletId: 'wallet.testnet',
  providerSubject: 'google:subject',
  nearEd25519SigningKeyId: 'ed25519ks_registration',
  signingRootId: 'project:dev',
  signerSlot: 1,
  participantIds: [1, 2],
} as const satisfies EmailOtpEd25519YaoRootScope;

void registrationScope;

// @ts-expect-error provider subject is required at the worker boundary.
const missingProviderSubject: EmailOtpEd25519YaoRootScope = {
  kind: 'email_otp_ed25519_yao_root_scope_v1',
  purpose: 'registration',
  walletId: 'wallet.testnet',
  nearEd25519SigningKeyId: 'ed25519ks_registration',
  signingRootId: 'project:dev',
  signerSlot: 1,
  participantIds: [1, 2],
};

void missingProviderSubject;

const registrationBinding: EmailOtpEd25519YaoRootBinding = {
  kind: 'email_otp_ed25519_yao_root_binding_v1',
  lifecycleId: 'registration-ceremony',
  scope: registrationScope,
};

void registrationBinding;

const handleWithRawSecret: EmailOtpEd25519YaoRootHandle = {
  kind: 'email_otp_ed25519_yao_root_handle_v1',
  handleId: 'opaque-handle',
  purpose: 'registration',
  expiresAtMs: 1_800_000_060_000,
  // @ts-expect-error public handles cannot contain raw factor material.
  factorSecret32: new Uint8Array(32),
};

void handleWithRawSecret;
