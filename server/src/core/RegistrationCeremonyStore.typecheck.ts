import {
  registrationIntentGrantFromString,
  walletSubjectIdFromString,
  type RegistrationIntentV1,
} from '@shared/utils/registrationIntent';
import type {
  ConsumedRegistrationIntent,
  FailedRegistrationIntent,
  StoredEcdsaRegistrationCompleted,
  StoredEcdsaRegistrationPrepared,
  StoredEcdsaRegistrationResponded,
  StoredEd25519RegistrationCompleted,
  StoredEd25519RegistrationFinalizing,
  StoredEd25519RegistrationPrepared,
  StoredEd25519RegistrationResponded,
  StoredRegistrationIntent,
  StoredWalletRegistrationFailed,
  StoredWalletRegistrationCeremony,
} from './RegistrationCeremonyStore';
import type {
  EcdsaHssServerBootstrapResponse,
  WalletRegistrationEcdsaPreparePayload,
  WalletRegistrationEcdsaWalletKey,
} from './types';

const intent = {
  version: 'registration_intent_v1',
  walletSubjectId: walletSubjectIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  authMethod: { kind: 'passkey' },
  signerSelection: {
    mode: 'ed25519_only',
    ed25519: {
      nearAccountId: 'alice.testnet',
      signerSlot: 1,
      participantIds: [1, 2],
      keyPurpose: 'near_tx',
      keyVersion: 'threshold-ed25519-hss-v1',
      derivationVersion: 1,
      createNearAccount: true,
    },
  },
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1;

const preparedSession = {
  contextBindingB64u: 'context',
  evaluatorDriverStateB64u: 'driver',
};

const ecdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 1,
} as import('./thresholdEcdsaChainTarget').ThresholdEcdsaChainTarget;

const allocatedIntent = {
  kind: 'intent_allocated',
  grant: registrationIntentGrantFromString('rig_123'),
  intent,
  digestB64u: 'digest',
  orgId: 'org',
  expiresAtMs: 1,
} satisfies StoredRegistrationIntent;
void allocatedIntent;

const consumedIntent = {
  ...allocatedIntent,
  kind: 'intent_consumed',
  consumedAtMs: 2,
} satisfies ConsumedRegistrationIntent;
void consumedIntent;

const failedIntent = {
  ...allocatedIntent,
  kind: 'intent_failed',
  failedAtMs: 2,
  failure: {
    code: 'invalid_webauthn',
    message: 'invalid WebAuthn credential',
  },
} satisfies FailedRegistrationIntent;
void failedIntent;

const preparedEd25519 = {
  kind: 'ed25519_prepared',
  ceremonyHandle: 'hss-handle',
  preparedSession,
  clientOtOfferMessageB64u: 'ot-offer',
} satisfies StoredEd25519RegistrationPrepared;

const respondedEd25519 = {
  kind: 'ed25519_responded',
  ceremonyHandle: 'hss-handle',
  preparedSession,
  clientOtOfferMessageB64u: 'ot-offer',
  responded: {
    contextBindingB64u: 'context',
    serverInputDeliveryB64u: 'server-delivery',
  },
} satisfies StoredEd25519RegistrationResponded;

const finalizingEd25519 = {
  ...respondedEd25519,
  kind: 'ed25519_finalizing',
  finalizingAtMs: 2,
} satisfies StoredEd25519RegistrationFinalizing;

const completedEd25519 = {
  ...respondedEd25519,
  kind: 'ed25519_completed',
  completedAtMs: 3,
  walletSubjectId: intent.walletSubjectId,
} satisfies StoredEd25519RegistrationCompleted;

const failedRegistration = {
  kind: 'registration_failed',
  failedAtMs: 4,
  failure: {
    code: 'hss_finalize_failed',
    message: 'finalize failed',
  },
} satisfies StoredWalletRegistrationFailed;

const ecdsaPrepare = {
  kind: 'evm_family_ecdsa_keygen',
  chainTargets: [ecdsaChainTarget],
  prepare: {
    formatVersion: 'ecdsa-hss-role-local',
    walletId: String(intent.walletSubjectId),
    rpId: intent.rpId,
    ecdsaThresholdKeyId: 'ek_registration',
    signingRootId: 'project:env',
    signingRootVersion: 'default',
    keyScope: 'evm-family',
    relayerKeyId: 'rk_registration',
    requestId: 'ecdsa-registration-request',
    sessionId: 'threshold-session',
    walletSigningSessionId: 'wallet-signing-session',
    ttlMs: 300_000,
    remainingUses: 10,
    participantIds: [1, 2],
  },
} satisfies WalletRegistrationEcdsaPreparePayload;

const ecdsaBootstrap = {
  formatVersion: 'ecdsa-hss-role-local',
  walletId: String(intent.walletSubjectId),
  rpId: intent.rpId,
  ecdsaThresholdKeyId: 'ek_registration',
  relayerKeyId: 'rk_registration',
  contextBinding32B64u: 'context',
  publicIdentity: {
    clientPublicKey33B64u: 'client-public',
    relayerPublicKey33B64u: 'relayer-public',
    groupPublicKey33B64u: 'group-public',
    ethereumAddress: '0x0000000000000000000000000000000000000001',
  },
  publicTranscriptDigest32B64u: 'digest',
  keyHandle: 'key-handle',
  signingRootId: 'project:env',
  signingRootVersion: 'default',
  thresholdEcdsaPublicKeyB64u: 'group-public',
  ethereumAddress: '0x0000000000000000000000000000000000000001',
  relayerVerifyingShareB64u: 'relayer-public',
  participantIds: [1, 2],
  sessionId: 'threshold-session',
  walletSigningSessionId: 'wallet-signing-session',
  expiresAtMs: 300_000,
  expiresAt: '1970-01-01T00:05:00.000Z',
  remainingUses: 10,
} satisfies EcdsaHssServerBootstrapResponse;

const ecdsaWalletKey = {
  keyScope: 'evm-family',
  chainTarget: ecdsaChainTarget,
  walletId: String(intent.walletSubjectId),
  rpId: intent.rpId,
  keyHandle: 'key-handle',
  ecdsaThresholdKeyId: 'ek_registration',
  signingRootId: 'project:env',
  signingRootVersion: 'default',
  thresholdEcdsaPublicKeyB64u: 'group-public',
  thresholdOwnerAddress: '0x0000000000000000000000000000000000000001',
  relayerKeyId: 'rk_registration',
  relayerVerifyingShareB64u: 'relayer-public',
  participantIds: [1, 2],
} satisfies WalletRegistrationEcdsaWalletKey;

const preparedEcdsa = {
  ...ecdsaPrepare,
  hssKind: ecdsaPrepare.kind,
  kind: 'ecdsa_prepared',
} satisfies StoredEcdsaRegistrationPrepared;

const respondedEcdsa = {
  ...ecdsaPrepare,
  hssKind: ecdsaPrepare.kind,
  kind: 'ecdsa_responded',
  responded: {
    bootstrap: ecdsaBootstrap,
  },
} satisfies StoredEcdsaRegistrationResponded;

const completedEcdsa = {
  ...ecdsaPrepare,
  hssKind: ecdsaPrepare.kind,
  kind: 'ecdsa_completed',
  responded: respondedEcdsa.responded,
  completedAtMs: 3,
  walletSubjectId: intent.walletSubjectId,
  walletKeys: [ecdsaWalletKey],
} satisfies StoredEcdsaRegistrationCompleted;

void ({
  registrationCeremonyId: 'wrc_123',
  intent,
  digestB64u: 'digest',
  orgId: 'org',
  expiresAtMs: 1,
  webauthn: {
    credentialIdB64u: 'credential',
    credentialPublicKeyB64u: 'public-key',
    counter: 0,
  },
  signerState: preparedEd25519,
} satisfies StoredWalletRegistrationCeremony);

void ({
  registrationCeremonyId: 'wrc_123',
  intent,
  digestB64u: 'digest',
  orgId: 'org',
  expiresAtMs: 1,
  webauthn: {
    credentialIdB64u: 'credential',
    credentialPublicKeyB64u: 'public-key',
    counter: 0,
  },
  signerState: respondedEd25519,
} satisfies StoredWalletRegistrationCeremony);

for (const signerState of [finalizingEd25519, completedEd25519, failedRegistration]) {
  void ({
    registrationCeremonyId: 'wrc_123',
    intent,
    digestB64u: 'digest',
    orgId: 'org',
    expiresAtMs: 1,
    webauthn: {
      credentialIdB64u: 'credential',
      credentialPublicKeyB64u: 'public-key',
      counter: 0,
    },
    signerState,
  } satisfies StoredWalletRegistrationCeremony);
}

for (const signerState of [preparedEcdsa, respondedEcdsa, completedEcdsa]) {
  void ({
    registrationCeremonyId: 'wrc_ecdsa',
    intent,
    digestB64u: 'digest',
    orgId: 'org',
    expiresAtMs: 1,
    webauthn: {
      credentialIdB64u: 'credential',
      credentialPublicKeyB64u: 'public-key',
      counter: 0,
    },
    signerState,
  } satisfies StoredWalletRegistrationCeremony);
}

void ({
  ...allocatedIntent,
  // @ts-expect-error allocated intents reject consumed timestamps
  consumedAtMs: 2,
} satisfies StoredRegistrationIntent);

void ({
  ...consumedIntent,
  kind: 'intent_failed',
  failedAtMs: 3,
  // @ts-expect-error failed intents require structured failure data
} satisfies FailedRegistrationIntent);

void ({
  kind: 'ed25519_prepared',
  ceremonyHandle: 'hss-handle',
  preparedSession,
  clientOtOfferMessageB64u: 'ot-offer',
  // @ts-expect-error prepared Ed25519 registration state cannot carry a response
  responded: {
    contextBindingB64u: 'context',
    serverInputDeliveryB64u: 'server-delivery',
  },
} satisfies StoredEd25519RegistrationPrepared);

void ({
  kind: 'ed25519_responded',
  ceremonyHandle: 'hss-handle',
  preparedSession,
  clientOtOfferMessageB64u: 'ot-offer',
  // @ts-expect-error responded Ed25519 registration state requires delivery data
} satisfies StoredEd25519RegistrationResponded);

void ({
  ...respondedEd25519,
  kind: 'ed25519_finalizing',
  // @ts-expect-error finalizing Ed25519 registration state requires finalizingAtMs
} satisfies StoredEd25519RegistrationFinalizing);

void ({
  ...respondedEd25519,
  kind: 'ed25519_completed',
  completedAtMs: 3,
  // @ts-expect-error completed Ed25519 registration state requires walletSubjectId
} satisfies StoredEd25519RegistrationCompleted);

void ({
  ...failedRegistration,
  // @ts-expect-error failed registration state cannot carry server HSS ceremony handles
  ceremonyHandle: 'hss-handle',
} satisfies StoredWalletRegistrationFailed);

void ({
  ...preparedEcdsa,
  // @ts-expect-error prepared ECDSA registration state cannot carry bootstrap responses
  responded: {
    bootstrap: ecdsaBootstrap,
  },
} satisfies StoredEcdsaRegistrationPrepared);

void ({
  ...respondedEcdsa,
  kind: 'ecdsa_completed',
  completedAtMs: 3,
  walletSubjectId: intent.walletSubjectId,
  // @ts-expect-error completed ECDSA registration state requires complete wallet keys
} satisfies StoredEcdsaRegistrationCompleted);

void ({
  registrationCeremonyId: 'wrc_123',
  intent,
  digestB64u: 'digest',
  orgId: 'org',
  expiresAtMs: 1,
  webauthn: {
    credentialIdB64u: 'credential',
    credentialPublicKeyB64u: 'public-key',
    counter: 0,
  },
  signerState: {
    kind: 'ed25519_prepared',
    ceremonyHandle: 'hss-handle',
    preparedSession,
    clientOtOfferMessageB64u: 'ot-offer',
    // @ts-expect-error stored ceremony rejects impossible prepared/responded branch combinations
    responded: {
      contextBindingB64u: 'context',
      serverInputDeliveryB64u: 'server-delivery',
    },
  },
} satisfies StoredWalletRegistrationCeremony);

export {};
