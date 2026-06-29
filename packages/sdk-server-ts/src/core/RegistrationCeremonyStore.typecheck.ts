import {
  addAuthMethodIntentGrantFromString,
  nearEd25519SigningKeyIdFromWalletId,
  implicitNearAccountProvisioning,
  registrationEd25519AuthorityScope,
  registrationIntentGrantFromString,
  walletIdFromString,
  type AddAuthMethodIntentV1,
  type RegistrationIntentV1,
} from '@shared/utils/registrationIntent';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import type {
  ConsumedAddAuthMethodIntent,
  ConsumedRegistrationIntent,
  FailedRegistrationIntent,
  StoredAddAuthMethodIntent,
  StoredEcdsaRegistrationCompleted,
  StoredEcdsaRegistrationPrepared,
  StoredEcdsaRegistrationResponded,
  StoredEd25519RegistrationCompleted,
  StoredEd25519RegistrationFinalizing,
  StoredEd25519RegistrationPrepared,
  StoredEd25519RegistrationResponded,
  StoredRegistrationIntent,
  StoredWalletRegistrationHssPreparationBase,
  StoredWalletRegistrationHssPreparationFailed,
  StoredWalletRegistrationHssPreparationPrepared,
  StoredWalletRegistrationHssPreparationPreparing,
  StoredWalletAddAuthMethodCeremony,
  StoredWalletRegistrationFailed,
  StoredWalletRegistrationCeremony,
} from './RegistrationCeremonyStore';
import type {
  EcdsaHssServerBootstrapResponse,
  RegistrationPreparationId,
  WalletRegistrationEcdsaPreparePayload,
  WalletRegistrationEcdsaWalletKey,
} from './types';
import type {
  EcdsaHssClientSharePublicKey33B64u,
  EcdsaRelayerHssPublicKey33B64u,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';

function unwrapDomainId<T>(result: { ok: true; value: T } | { ok: false }): T {
  if (!result.ok) throw new Error('invalid type fixture domain id');
  return result.value;
}

const webAuthnRpId = unwrapDomainId(parseWebAuthnRpId('wallet.example.test'));

const intentNearEd25519Signer = {
  kind: 'near_ed25519',
  accountProvisioning: implicitNearAccountProvisioning(),
  signerSlot: 1,
  participantIds: [1, 2],
  derivationVersion: 1,
} as const;

const intent = {
  version: 'registration_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  authMethod: { kind: 'passkey', rpId: webAuthnRpId },
  signerSelection: {
    kind: 'signer_set',
    signers: [intentNearEd25519Signer],
  },
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1;

const passkeyAuthority = {
  kind: 'passkey',
  walletId: intent.walletId,
  rpId: webAuthnRpId,
  credentialIdB64u: 'credential',
  credentialPublicKeyB64u: 'public-key',
  counter: 0,
  registrationIntentDigestB64u: 'digest',
} as const;

const preparedSession = {
  contextBindingB64u: 'context',
  evaluatorDriverStateB64u: 'driver',
};

const preparedEd25519ServerState = {
  context: {
    applicationBindingDigestB64u: 'application-binding-digest',
    participantIds: [1, 2],
  },
  preparedServerSession: {
    evaluatorDriverStateB64u: 'evaluator-driver-state',
    garblerDriverStateB64u: 'garbler-driver-state',
  },
  serverInputs: {
    yRelayerB64u: 'y-relayer',
    tauRelayerB64u: 'tau-relayer',
  },
};

const respondedEd25519ServerState = {
  context: preparedEd25519ServerState.context,
  preparedServerSession: preparedEd25519ServerState.preparedServerSession,
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

const addAuthMethodIntent = {
  version: 'add_auth_method_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  authMethod: { kind: 'passkey', rpId: webAuthnRpId },
  nonceB64u: 'nonce',
} satisfies AddAuthMethodIntentV1;

const allocatedAddAuthMethodIntent = {
  kind: 'add_auth_method_intent_allocated',
  grant: addAuthMethodIntentGrantFromString('waig_123'),
  intent: addAuthMethodIntent,
  digestB64u: 'digest',
  orgId: 'org',
  expiresAtMs: 1,
} satisfies StoredAddAuthMethodIntent;
void allocatedAddAuthMethodIntent;

const consumedAddAuthMethodIntent = {
  ...allocatedAddAuthMethodIntent,
  kind: 'add_auth_method_intent_consumed',
  consumedAtMs: 2,
} satisfies ConsumedAddAuthMethodIntent;
void consumedAddAuthMethodIntent;

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
  serverState: preparedEd25519ServerState,
} satisfies StoredEd25519RegistrationPrepared;

const preparationBase = {
  registrationPreparationId: 'wrp_123' as RegistrationPreparationId,
  registrationIntentGrant: allocatedIntent.grant,
  registrationIntentDigestB64u: allocatedIntent.digestB64u,
  intent,
  orgId: allocatedIntent.orgId,
  expectedOrigin: 'https://wallet.example.test',
  signingRootId: 'project:env',
  signingRootVersion: 'default',
  ed25519Scope: {
    walletId: String(intent.walletId),
    authorityScope: registrationEd25519AuthorityScope(intent.authMethod),
    registrationIntentDigestB64u: allocatedIntent.digestB64u,
    expectedOrigin: 'https://wallet.example.test',
    orgId: allocatedIntent.orgId,
    signingRootId: 'project:env',
    signingRootVersion: 'default',
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromWalletId(intent.walletId),
    signerSlot: intentNearEd25519Signer.signerSlot,
    keyPurpose: 'near_tx',
    keyVersion: 'threshold-ed25519-hss-v1',
    derivationVersion: intentNearEd25519Signer.derivationVersion,
    participantIds: [...intentNearEd25519Signer.participantIds],
  },
  createdAtMs: 1,
  expiresAtMs: 2,
} satisfies StoredWalletRegistrationHssPreparationBase;

const preparedRegistrationHssPreparation = {
  ...preparationBase,
  kind: 'hss_prepare_prepared',
  prepared: preparedEd25519,
} satisfies StoredWalletRegistrationHssPreparationPrepared;
void preparedRegistrationHssPreparation;

const preparingRegistrationHssPreparation = {
  ...preparationBase,
  kind: 'hss_prepare_preparing',
} satisfies StoredWalletRegistrationHssPreparationPreparing;
void preparingRegistrationHssPreparation;

const failedRegistrationHssPreparation = {
  ...preparationBase,
  kind: 'hss_prepare_failed',
  failure: {
    code: 'hss_prepare_failed',
    message: 'prepare failed',
  },
} satisfies StoredWalletRegistrationHssPreparationFailed;
void failedRegistrationHssPreparation;

const respondedEd25519 = {
  kind: 'ed25519_responded',
  ceremonyHandle: 'hss-handle',
  preparedSession,
  clientOtOfferMessageB64u: 'ot-offer',
  serverState: respondedEd25519ServerState,
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
  walletId: intent.walletId,
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
    walletId: String(intent.walletId),
    walletKeyId: 'wallet-key-registration',
    ecdsaThresholdKeyId: 'ek_registration',
    signingRootId: 'project:env',
    signingRootVersion: 'default',
    keyScope: 'evm-family',
    relayerKeyId: 'rk_registration',
    requestId: 'ecdsa-registration-request',
    thresholdSessionId: 'threshold-session',
    signingGrantId: 'signing-grant',
    ttlMs: 300_000,
    remainingUses: 10,
    participantIds: [1, 2],
  },
} satisfies WalletRegistrationEcdsaPreparePayload;

const ecdsaBootstrap = {
  formatVersion: 'ecdsa-hss-role-local',
  walletId: String(intent.walletId),
  walletKeyId: 'wallet-key-registration',
  ecdsaThresholdKeyId: 'ek_registration',
  relayerKeyId: 'rk_registration',
  applicationBindingDigestB64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
  contextBinding32B64u: 'context',
  publicIdentity: {
    hssClientSharePublicKey33B64u: 'client-public' as EcdsaHssClientSharePublicKey33B64u,
    relayerPublicKey33B64u: 'relayer-public' as EcdsaRelayerHssPublicKey33B64u,
    groupPublicKey33B64u: 'group-public',
    ethereumAddress: '0x0000000000000000000000000000000000000001',
  },
  clientShareRetryCounter: 0,
  relayerShareRetryCounter: 0,
  publicTranscriptDigest32B64u: 'digest',
  keyHandle: 'key-handle',
  signingRootId: 'project:env',
  signingRootVersion: 'default',
  thresholdEcdsaPublicKeyB64u: 'group-public',
  ethereumAddress: '0x0000000000000000000000000000000000000001',
  relayerVerifyingShareB64u: 'relayer-public',
  participantIds: [1, 2],
  thresholdSessionId: 'threshold-session',
  signingGrantId: 'signing-grant',
  expiresAtMs: 300_000,
  expiresAt: '1970-01-01T00:05:00.000Z',
  remainingUses: 10,
} satisfies EcdsaHssServerBootstrapResponse;

const ecdsaWalletKey = {
  keyScope: 'evm-family',
  chainTarget: ecdsaChainTarget,
  walletId: String(intent.walletId),
  walletKeyId: 'wallet-key-registration',
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
  walletId: intent.walletId,
  walletKeys: [ecdsaWalletKey],
} satisfies StoredEcdsaRegistrationCompleted;

void ({
  registrationCeremonyId: 'wrc_123',
  intent,
  digestB64u: 'digest',
  orgId: 'org',
  expiresAtMs: 1,
  authority: passkeyAuthority,
  signerState: preparedEd25519,
} satisfies StoredWalletRegistrationCeremony);

void ({
  registrationCeremonyId: 'wrc_123',
  intent,
  digestB64u: 'digest',
  orgId: 'org',
  expiresAtMs: 1,
  authority: passkeyAuthority,
  signerState: respondedEd25519,
} satisfies StoredWalletRegistrationCeremony);

for (const signerState of [finalizingEd25519, completedEd25519, failedRegistration]) {
  void ({
    registrationCeremonyId: 'wrc_123',
    intent,
    digestB64u: 'digest',
    orgId: 'org',
    expiresAtMs: 1,
    authority: passkeyAuthority,
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
    authority: passkeyAuthority,
    signerState,
  } satisfies StoredWalletRegistrationCeremony);
}

void ({
  addAuthMethodCeremonyId: 'wauthc_123',
  intent: addAuthMethodIntent,
  digestB64u: 'digest',
  orgId: 'org',
  expiresAtMs: 1,
  auth: {
    kind: 'webauthn_assertion',
    rpId: webAuthnRpId,
    credentialIdB64u: 'credential',
  },
  authority: passkeyAuthority,
} satisfies StoredWalletAddAuthMethodCeremony);

void ({
  ...allocatedIntent,
  // @ts-expect-error allocated intents reject consumed timestamps
  consumedAtMs: 2,
} satisfies StoredRegistrationIntent);

void ({
  ...allocatedAddAuthMethodIntent,
  // @ts-expect-error allocated add-auth-method intents reject consumed timestamps
  consumedAtMs: 2,
} satisfies StoredAddAuthMethodIntent);

void ({
  ...preparationBase,
  // @ts-expect-error preparation ids must be normalized into branded ids at the boundary
  registrationPreparationId: 'wrp_raw_string',
} satisfies StoredWalletRegistrationHssPreparationBase);

void ({
  ...preparationBase,
  ed25519Scope: {
    ...preparationBase.ed25519Scope,
    // @ts-expect-error preparation scope requires wallet identity
    walletId: undefined,
  },
} satisfies StoredWalletRegistrationHssPreparationBase);

void ({
  ...preparationBase,
  kind: 'hss_prepare_preparing',
  // @ts-expect-error preparing records cannot carry prepared HSS payloads
  prepared: preparedEd25519,
} satisfies StoredWalletRegistrationHssPreparationPreparing);

void ({
  ...preparationBase,
  kind: 'hss_prepare_prepared',
  prepared: preparedEd25519,
  // @ts-expect-error prepared records cannot carry failure data
  failure: {
    code: 'mixed',
    message: 'mixed branch',
  },
} satisfies StoredWalletRegistrationHssPreparationPrepared);

void ({
  ...preparationBase,
  kind: 'hss_prepare_failed',
  failure: {
    code: 'hss_prepare_failed',
    message: 'prepare failed',
  },
  // @ts-expect-error failed records cannot carry prepared HSS payloads
  prepared: preparedEd25519,
} satisfies StoredWalletRegistrationHssPreparationFailed);

void ({
  ...preparedRegistrationHssPreparation,
  kind: 'hss_prepare_failed',
  failure: {
    code: 'spread_mixed',
    message: 'spread mixed lifecycle state',
  },
  // @ts-expect-error broad-spread construction cannot smuggle prepared payloads into failed records
} satisfies StoredWalletRegistrationHssPreparationFailed);

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
  // @ts-expect-error completed Ed25519 registration state requires walletId
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
  walletId: intent.walletId,
  // @ts-expect-error completed ECDSA registration state requires complete wallet keys
} satisfies StoredEcdsaRegistrationCompleted);

void ({
  registrationCeremonyId: 'wrc_123',
  intent,
  digestB64u: 'digest',
  orgId: 'org',
  expiresAtMs: 1,
  authority: passkeyAuthority,
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

void ({
  addAuthMethodCeremonyId: 'wauthc_123',
  intent: addAuthMethodIntent,
  digestB64u: 'digest',
  orgId: 'org',
  expiresAtMs: 1,
  auth: {
    kind: 'webauthn_assertion',
    rpId: webAuthnRpId,
    credentialIdB64u: 'credential',
  },
  // @ts-expect-error passkey add-auth-method ceremonies require a full authority branch
  authority: {
    kind: 'passkey',
    walletId: intent.walletId,
    rpId: webAuthnRpId,
    credentialIdB64u: 'credential',
  },
} satisfies StoredWalletAddAuthMethodCeremony);

export {};
