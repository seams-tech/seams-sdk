import type { AccountId } from '@/core/types/accountIds';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../identity/laneIdentity';
import type {
  EmailOtpEcdsaReadyPersistInput,
  EmailOtpEd25519ReadyPersistInput,
  PasskeyEcdsaReadyPersistInput,
} from './persistencePorts';
import type {
  ThresholdEd25519SessionId,
  ThresholdEcdsaSessionId,
  WalletSigningSessionId,
} from '../operationState/types';

declare const walletId: WalletId;
declare const accountId: AccountId;
declare const walletSigningSessionId: WalletSigningSessionId;
declare const thresholdSessionId: ThresholdEcdsaSessionId;
declare const thresholdEd25519SessionId: ThresholdEd25519SessionId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;

void accountId;

void ({
  authMethod: 'email_otp',
  curve: 'ecdsa',
  walletId,
  walletSigningSessionId,
  thresholdSessionId,
  chainTarget,
  emailOtpAuthContext,
  material: {
    kind: 'worker_handle',
    workerSessionId: 'email-otp-worker-session',
  },
} satisfies EmailOtpEcdsaReadyPersistInput);

void ({
  authMethod: 'email_otp',
  curve: 'ed25519',
  walletId,
  walletSigningSessionId,
  thresholdSessionId: thresholdEd25519SessionId,
  accountId,
  material: {
    kind: 'inline',
    clientSecretB64u: 'ed25519-client-secret',
  },
} satisfies EmailOtpEd25519ReadyPersistInput);

void ({
  authMethod: 'passkey',
  curve: 'ecdsa',
  walletId,
  walletSigningSessionId,
  thresholdSessionId,
  chainTarget,
  persistenceSource: {
    kind: 'fresh_webauthn',
    credentialIdB64u: 'credential',
  },
  passkeyPrfSealMaterial: {
    kind: 'ecdsa_prf_first',
    passkeyPrfFirstB64u: 'passkey-prf-first',
    transport: {
      curve: 'ecdsa',
      chainTarget,
      relayerUrl: 'https://relay.example.test',
    },
  },
} satisfies PasskeyEcdsaReadyPersistInput);

void ({
  authMethod: 'passkey',
  curve: 'ecdsa',
  walletId,
  walletSigningSessionId,
  thresholdSessionId,
  chainTarget,
  persistenceSource: {
    kind: 'session_reconnect',
    restoredThresholdSessionId: thresholdSessionId,
  },
  passkeyPrfSealMaterial: {
    kind: 'ecdsa_prf_first',
    passkeyPrfFirstB64u: 'passkey-prf-first',
    transport: {
      curve: 'ecdsa',
      chainTarget,
      relayerUrl: 'https://relay.example.test',
    },
  },
} satisfies PasskeyEcdsaReadyPersistInput);

// @ts-expect-error Email OTP ECDSA persistence must carry a concrete chain target.
const emailOtpEcdsaMissingChainTarget: EmailOtpEcdsaReadyPersistInput = {
  authMethod: 'email_otp',
  curve: 'ecdsa',
  walletId,
  walletSigningSessionId,
  thresholdSessionId,
  emailOtpAuthContext,
  material: {
    kind: 'inline',
    clientSecretB64u: 'client-secret',
  },
};
void emailOtpEcdsaMissingChainTarget;

const emailOtpEcdsaWithPasskeyMaterial: EmailOtpEcdsaReadyPersistInput = {
  authMethod: 'email_otp',
  curve: 'ecdsa',
  walletId,
  walletSigningSessionId,
  thresholdSessionId,
  chainTarget,
  emailOtpAuthContext,
  material: {
    kind: 'worker_handle',
    workerSessionId: 'email-otp-worker-session',
  },
  // @ts-expect-error Email OTP persistence cannot carry passkey PRF seal material.
  passkeyPrfSealMaterial: {
    kind: 'ecdsa_prf_first',
    passkeyPrfFirstB64u: 'passkey-prf-first',
    transport: {
      curve: 'ecdsa',
      chainTarget,
      relayerUrl: 'https://relay.example.test',
    },
  },
};
void emailOtpEcdsaWithPasskeyMaterial;

const emailOtpEd25519WithEcdsaContext: EmailOtpEd25519ReadyPersistInput = {
  authMethod: 'email_otp',
  curve: 'ed25519',
  walletId,
  walletSigningSessionId,
  thresholdSessionId: thresholdEd25519SessionId,
  accountId,
  material: {
    kind: 'worker_handle',
    workerSessionId: 'email-otp-ed25519-worker-session',
  },
  // @ts-expect-error Email OTP Ed25519 persistence cannot carry ECDSA auth context.
  emailOtpAuthContext,
};
void emailOtpEd25519WithEcdsaContext;

const passkeyEcdsaWithEmailOtpContext: PasskeyEcdsaReadyPersistInput = {
  authMethod: 'passkey',
  curve: 'ecdsa',
  walletId,
  walletSigningSessionId,
  thresholdSessionId,
  chainTarget,
  persistenceSource: {
    kind: 'fresh_webauthn',
    credentialIdB64u: 'credential',
  },
  passkeyPrfSealMaterial: {
    kind: 'ecdsa_prf_first',
    passkeyPrfFirstB64u: 'passkey-prf-first',
    transport: {
      curve: 'ecdsa',
      chainTarget,
      relayerUrl: 'https://relay.example.test',
    },
  },
  // @ts-expect-error Passkey persistence cannot carry Email OTP auth context.
  emailOtpAuthContext,
};
void passkeyEcdsaWithEmailOtpContext;

const passkeyReconnectWithCredentialId: PasskeyEcdsaReadyPersistInput = {
  authMethod: 'passkey',
  curve: 'ecdsa',
  walletId,
  walletSigningSessionId,
  thresholdSessionId,
  chainTarget,
  // @ts-expect-error Reconnect persistence cannot invent a WebAuthn credential id.
  persistenceSource: {
    kind: 'session_reconnect',
    restoredThresholdSessionId: thresholdSessionId,
    credentialIdB64u: 'credential',
  },
  passkeyPrfSealMaterial: {
    kind: 'ecdsa_prf_first',
    passkeyPrfFirstB64u: 'passkey-prf-first',
    transport: {
      curve: 'ecdsa',
      chainTarget,
      relayerUrl: 'https://relay.example.test',
    },
  },
};
void passkeyReconnectWithCredentialId;

export {};
