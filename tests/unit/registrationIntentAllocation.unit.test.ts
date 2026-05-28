import { expect, test } from '@playwright/test';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { AuthService } from '@server/core/AuthService';
import {
  serializeNearAccountOwnershipProofMessageV1,
  type AddAuthMethodIntentV1,
  walletIdFromString,
  type AddSignerIntentV1,
  type NearAccountOwnershipProofV1,
  type RegistrationAuthMethodInput,
  type RegistrationSignerSelection,
} from '@shared/utils/registrationIntent';
import { base58Encode, base64UrlEncode } from '@shared/utils/encoders';
import {
  EMAIL_OTP_RECOVERY_KEY_COUNT,
  EMAIL_OTP_RECOVERY_WRAP_ALG,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
  encodeEmailOtpRecoveryWrappedEnrollmentAad,
} from '@shared/utils/emailOtpRecoveryKey';
import { DEFAULT_TEST_CONFIG } from '../setup/config';

const ORG_ID = 'org_registration_intent_allocation_tests';
const RUNTIME_POLICY_SCOPE = {
  orgId: ORG_ID,
  projectId: 'project_registration_intent_allocation_tests',
  envId: 'dev',
  signingRootVersion: 'default',
} as const;

const EXISTING_PASSKEY_CREDENTIAL_ID = base64UrlEncode(
  new TextEncoder().encode('existing-credential-id'),
);
const NEW_PASSKEY_CREDENTIAL_ID = base64UrlEncode(new TextEncoder().encode('new-credential-id'));

function secp256k1BasePointB64u(): string {
  const hex = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
  return base64UrlEncode(Uint8Array.from(Buffer.from(hex, 'hex')));
}

function emailOtpEnrollmentMaterial(walletId: string, email: string) {
  const publicKey = secp256k1BasePointB64u();
  const enrollmentSealKeyVersion = 'email-otp-seal-v1';
  const nowMs = 1_700_000_000_000;
  return {
    recoveryWrappedEnrollmentEscrows: Array.from(
      { length: EMAIL_OTP_RECOVERY_KEY_COUNT },
      (_, index) => {
        const metadata = {
          walletId,
          userId: email,
          authSubjectId: email,
          authMethod: 'google_sso_email_otp',
          enrollmentId: `email-otp-device-enrollment-v1:${walletId}:${email}`,
          enrollmentVersion: '1',
          enrollmentSealKeyVersion,
          signingRootId: 'email_otp_default_signing_root',
          signingRootVersion: 'default',
          recoveryKeyId: `recovery-key-${index + 1}`,
        };
        return {
          version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
          alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
          secretKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
          escrowKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
          ...metadata,
          recoveryKeyStatus: 'active',
          nonceB64u: base64UrlEncode(
            Uint8Array.from(Array.from({ length: 12 }, (_, byteIndex) => byteIndex + index)),
          ),
          wrappedDeviceEnrollmentEscrowB64u: base64UrlEncode(
            Uint8Array.from(Array.from({ length: 48 }, (_, byteIndex) => byteIndex + index + 1)),
          ),
          aadHashB64u: base64UrlEncode(
            createHash('sha256').update(encodeEmailOtpRecoveryWrappedEnrollmentAad(metadata)).digest(),
          ),
          issuedAtMs: nowMs,
          updatedAtMs: nowMs,
        };
      },
    ),
    enrollmentSealKeyVersion,
    clientUnlockPublicKeyB64u: publicKey,
    unlockKeyVersion: 'email-otp-unlock-v1',
    thresholdEcdsaClientVerifyingShareB64u: publicKey,
  };
}

const SIGNER_SELECTION = {
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
} satisfies RegistrationSignerSelection;

const ECDSA_SIGNER_SELECTION = {
  mode: 'ecdsa_only',
  ecdsa: {
    chainTargets: [
      { kind: 'evm', namespace: 'eip155', chainId: 1 },
      { kind: 'tempo', chainId: 42431 },
    ],
    participantIds: [1, 2],
  },
} satisfies RegistrationSignerSelection;

const COMBINED_SIGNER_SELECTION = {
  mode: 'ed25519_and_ecdsa',
  ed25519: SIGNER_SELECTION.ed25519,
  ecdsa: ECDSA_SIGNER_SELECTION.ecdsa,
} satisfies RegistrationSignerSelection;

const ECDSA_ADD_SIGNER_INTENT = {
  version: 'add_signer_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  signerSelection: {
    mode: 'ecdsa',
    ecdsa: {
      chainTargets: ECDSA_SIGNER_SELECTION.ecdsa.chainTargets,
      participantIds: [1, 2],
    },
  },
  runtimePolicyScope: RUNTIME_POLICY_SCOPE,
  nonceB64u: 'add-signer-nonce',
} satisfies AddSignerIntentV1;

const ED25519_ADD_SIGNER_INTENT = {
  version: 'add_signer_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  signerSelection: {
    mode: 'ed25519',
    ed25519: {
      mode: 'create_near_account',
      nearAccountId: 'alice.testnet',
      signerSlot: 2,
      participantIds: [1, 2],
      keyPurpose: 'near_tx',
      keyVersion: 'threshold-ed25519-hss-v1',
      derivationVersion: 1,
    },
  },
  runtimePolicyScope: RUNTIME_POLICY_SCOPE,
  nonceB64u: 'add-signer-nonce',
} satisfies AddSignerIntentV1;

function makeService(): AuthService {
  return new AuthService({
    relayerAccount: 'relayer.testnet',
    relayerPrivateKey: 'ed25519:dummy',
    nearRpcUrl: DEFAULT_TEST_CONFIG.nearRpcUrl,
    networkId: DEFAULT_TEST_CONFIG.nearNetwork,
    accountInitialBalance: '1',
    createAccountAndRegisterGas: '1',
    logger: null,
  });
}

async function allocateIntent(
  service: AuthService,
  signerSelection: RegistrationSignerSelection = SIGNER_SELECTION,
  authMethod: RegistrationAuthMethodInput = { kind: 'passkey' },
) {
  return await service.createRegistrationIntent({
    request: {
      wallet: {
        kind: 'provided',
        walletId: walletIdFromString('wallet_alice'),
      },
      rpId: 'wallet.example.test',
      authMethod,
      signerSelection,
    },
    orgId: ORG_ID,
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    expectedOrigin: 'https://wallet.example.test',
  });
}

async function allocateEmailOtpIntent(service: AuthService) {
  return await allocateIntent(service, SIGNER_SELECTION, {
    kind: 'email_otp',
    email: 'Alice@Example.Test',
    otpCode: '123456',
    appSessionJwt: 'app-session.jwt',
  });
}

async function allocateAddSignerIntent(
  service: AuthService,
  signerSelection: AddSignerIntentV1['signerSelection'] = ECDSA_ADD_SIGNER_INTENT.signerSelection,
) {
  return await service.createAddSignerIntent({
    request: {
      walletId: walletIdFromString('wallet_alice'),
      rpId: 'wallet.example.test',
      signerSelection,
    },
    orgId: ORG_ID,
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    expectedOrigin: 'https://wallet.example.test',
  });
}

async function allocateAddAuthMethodIntent(
  service: AuthService,
  authMethod: AddAuthMethodIntentV1['authMethod'] = { kind: 'passkey' },
) {
  return await service.createAddAuthMethodIntent({
    request: {
      walletId: walletIdFromString('wallet_alice'),
      rpId: 'wallet.example.test',
      authMethod,
    },
    orgId: ORG_ID,
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    expectedOrigin: 'https://wallet.example.test',
  });
}

function activePasskeyAuthMethod(input: {
  walletId?: string;
  credentialIdB64u: string;
  credentialPublicKeyB64u?: string;
  counter?: number;
}) {
  const now = Date.now();
  return {
    version: 'wallet_auth_method_v1' as const,
    kind: 'passkey' as const,
    status: 'active' as const,
    walletId: walletIdFromString(input.walletId || 'wallet_alice'),
    rpId: 'wallet.example.test',
    credentialIdB64u: input.credentialIdB64u,
    credentialPublicKeyB64u: input.credentialPublicKeyB64u || 'existing-public-key',
    counter: input.counter ?? 0,
    createdAtMs: now,
    updatedAtMs: now,
  };
}

function activeEmailOtpAuthMethod(input: {
  walletId?: string;
  emailHashHex?: string;
  challengeId?: string;
}) {
  const now = Date.now();
  return {
    version: 'wallet_auth_method_v1' as const,
    kind: 'email_otp' as const,
    status: 'active' as const,
    walletId: walletIdFromString(input.walletId || 'wallet_alice'),
    rpId: 'wallet.example.test',
    emailHashHex: input.emailHashHex || 'email-hash-1',
    challengeId: input.challengeId || 'challenge-1',
    createdAtMs: now,
    updatedAtMs: now,
  };
}

function clientDataJsonB64u(input: { challenge: string }): string {
  return base64UrlEncode(
    new TextEncoder().encode(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: input.challenge,
        origin: 'https://wallet.example.test',
      }),
    ),
  );
}

function createNearAccountOwnershipProof(input: {
  walletId: ReturnType<typeof walletIdFromString>;
  rpId: string;
  nearAccountId: string;
  issuedAtMs?: number;
  expiresAtMs?: number;
}): NearAccountOwnershipProofV1 {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyDer = new Uint8Array(
    publicKey.export({ format: 'der', type: 'spki' }) as ArrayBuffer,
  );
  const publicKeyBytes = publicKeyDer.slice(-32);
  const message = {
    version: 'near_account_ownership_proof_message_v1' as const,
    walletId: input.walletId,
    rpId: input.rpId,
    nearAccountId: input.nearAccountId,
    publicKey: `ed25519:${base58Encode(publicKeyBytes)}`,
    nonceB64u: base64UrlEncode(new Uint8Array(16).fill(7)),
    issuedAtMs: input.issuedAtMs ?? Date.now() - 1_000,
    expiresAtMs: input.expiresAtMs ?? Date.now() + 60_000,
  };
  const signature = sign(
    null,
    Buffer.from(serializeNearAccountOwnershipProofMessageV1(message)),
    privateKey,
  );
  return {
    version: 'near_account_ownership_proof_v1',
    message,
    signatureB64u: base64UrlEncode(new Uint8Array(signature)),
  };
}

function ecdsaServerBootstrapValue(input: {
  request: Record<string, unknown>;
  keyHandle: string;
  ownerAddress: string;
  overrides?: Record<string, unknown>;
}): Record<string, unknown> {
  const expiresAtMs = Date.now() + 60_000;
  return {
    formatVersion: 'ecdsa-hss-role-local',
    walletId: input.request.walletId,
    walletSessionUserId: input.request.walletSessionUserId,
    rpId: input.request.rpId,
    subjectId: input.request.subjectId,
    ecdsaThresholdKeyId: input.request.ecdsaThresholdKeyId,
    relayerKeyId: input.request.relayerKeyId,
    contextBinding32B64u: input.request.contextBinding32B64u,
    publicIdentity: {
      clientPublicKey33B64u: input.request.clientPublicKey33B64u,
      relayerPublicKey33B64u: 'relayer-public-key',
      groupPublicKey33B64u: 'group-public-key',
      ethereumAddress: input.ownerAddress,
    },
    publicTranscriptDigest32B64u: 'transcript-digest',
    keyHandle: input.keyHandle,
    signingRootId: input.request.signingRootId,
    signingRootVersion: input.request.signingRootVersion,
    thresholdEcdsaPublicKeyB64u: 'group-public-key',
    ethereumAddress: input.ownerAddress,
    relayerVerifyingShareB64u: 'relayer-public-key',
    participantIds: input.request.participantIds,
    sessionId: input.request.sessionId,
    walletSigningSessionId: input.request.walletSigningSessionId,
    expiresAtMs,
    expiresAt: new Date(expiresAtMs).toISOString(),
    remainingUses: input.request.remainingUses,
    ...input.overrides,
  };
}

test.describe('registration intent allocation', () => {
  test('allocates distinct intent grants and nonce-bound digests', async () => {
    const service = makeService();
    const first = await allocateIntent(service);
    const second = await allocateIntent(service);

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    if (!first.ok) throw new Error(first.message);
    if (!second.ok) throw new Error(second.message);

    expect(first.registrationIntentGrant).toMatch(/^rig_/);
    expect(second.registrationIntentGrant).toMatch(/^rig_/);
    expect(first.registrationIntentGrant).not.toBe(second.registrationIntentGrant);
    expect(first.intent.nonceB64u).not.toBe(second.intent.nonceB64u);
    expect(first.registrationIntentDigestB64u).not.toBe(second.registrationIntentDigestB64u);
  });

  test('rejects replay after a registration intent grant is consumed', async () => {
    const service = makeService();
    const allocated = await allocateIntent(service);

    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    const startRequest = {
      registrationIntentGrant: allocated.registrationIntentGrant,
      registrationIntentDigestB64u: allocated.registrationIntentDigestB64u,
      intent: allocated.intent,
      authority: {
        kind: 'passkey' as const,
        webauthnRegistration: {
          response: {
            clientDataJSON: clientDataJsonB64u({ challenge: 'wrong-challenge' }),
          },
        },
      },
    };

    await expect(service.startWalletRegistration(startRequest)).resolves.toMatchObject({
      ok: false,
      code: 'challenge_mismatch',
    });
    await expect(service.startWalletRegistration(startRequest)).resolves.toMatchObject({
      ok: false,
      code: 'invalid_grant',
    });
  });

  test('rejects passkey registration when the WebAuthn challenge mismatches', async () => {
    const service = makeService();
    const allocated = await allocateIntent(service);

    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    await expect(
      service.startWalletRegistration({
        registrationIntentGrant: allocated.registrationIntentGrant,
        registrationIntentDigestB64u: allocated.registrationIntentDigestB64u,
        intent: allocated.intent,
        authority: {
          kind: 'passkey',
          webauthnRegistration: {
            response: {
              clientDataJSON: clientDataJsonB64u({ challenge: 'wrong-challenge' }),
            },
          },
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'challenge_mismatch',
      message: 'Registration challenge mismatch',
    });
  });

  test('runs passkey Ed25519-only registration through start, respond, and finalize', async () => {
    const service = makeService();
    (service as any).verifyRegistrationCredentialForIntent = async () => ({
      ok: true,
      credential: {
        credentialIdB64u: 'credential-id',
        credentialPublicKeyB64u: 'credential-public-key',
        counter: 0,
      },
    });
    let accountCreation: Record<string, unknown> | null = null;
    let bindingWrite: Record<string, unknown> | null = null;
    let authenticatorWrites = 0;
    let ed25519PrepareRequest: Record<string, unknown> | null = null;
    let ed25519RespondRequest: Record<string, unknown> | null = null;
    let ed25519FinalizeRequest: Record<string, unknown> | null = null;
    (service as any).createAccount = async (request: Record<string, unknown>) => {
      accountCreation = request;
      return { success: true };
    };
    (service as any).getWebAuthnAuthenticatorStore = () => ({
      put: async () => {
        authenticatorWrites += 1;
      },
    });
    (service as any).getWebAuthnCredentialBindingStore = () => ({
      put: async (record: Record<string, unknown>) => {
        bindingWrite = record;
      },
    });
    (service as any).getThresholdSigningService = () => ({
      ed25519Hss: {
        prepareForRegistration: async (request: Record<string, unknown>) => {
          ed25519PrepareRequest = request;
          return {
            ok: true,
            ceremonyHandle: 'passkey-ed25519-handle',
            preparedSession: { prepared: true },
            clientOtOfferMessageB64u: 'client-ot-offer',
          };
        },
        respondForRegistration: async (request: Record<string, unknown>) => {
          ed25519RespondRequest = request;
          return {
            ok: true,
            contextBindingB64u: 'context-binding',
            serverInputDeliveryB64u: 'server-input-delivery',
          };
        },
        finalizeForRegistration: async (request: Record<string, unknown>) => {
          ed25519FinalizeRequest = request;
          return {
            ok: true,
            publicKey: 'ed25519:public-key',
            relayerKeyId: 'relayer-key-ed25519',
          };
        },
      },
      getSchemeModule: () => ({
        schemeId: 'threshold-ed25519-frost-2p-v1',
        registration: {
          keygenFromRegistrationMaterial: async () => ({
            ok: true,
            publicKey: 'ed25519:public-key',
            relayerKeyId: 'relayer-key-ed25519',
            keyVersion: 'threshold-ed25519-hss-v1',
            recoveryExportCapable: true,
            clientParticipantId: 1,
            relayerParticipantId: 2,
            participantIds: [1, 2],
          }),
        },
      }),
    });

    const allocated = await allocateIntent(service);
    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    const started = await service.startWalletRegistration({
      registrationIntentGrant: allocated.registrationIntentGrant,
      registrationIntentDigestB64u: allocated.registrationIntentDigestB64u,
      intent: allocated.intent,
      authority: {
        kind: 'passkey' as const,
        webauthnRegistration: {
          response: {
            clientDataJSON: clientDataJsonB64u({
              challenge: allocated.registrationIntentDigestB64u,
            }),
          },
        },
      },
    });
    expect(started).toMatchObject({
      ok: true,
      ed25519: {
        ceremonyHandle: 'passkey-ed25519-handle',
      },
    });
    if (!started.ok || !started.ed25519) throw new Error('passkey Ed25519 start failed');
    expect(ed25519PrepareRequest).toMatchObject({
      orgId: ORG_ID,
      request: {
        new_account_id: 'alice.testnet',
        rp_id: 'wallet.example.test',
      },
    });

    const responded = await service.respondWalletRegistrationHss({
      registrationCeremonyId: started.registrationCeremonyId,
      ed25519: {
        clientRequest: { clientRequestMessageB64u: 'client-request' } as any,
      },
    });
    expect(responded).toMatchObject({
      ok: true,
      ed25519: {
        serverInputDeliveryB64u: 'server-input-delivery',
      },
    });
    expect(ed25519RespondRequest).toMatchObject({
      request: {
        ceremonyHandle: 'passkey-ed25519-handle',
      },
    });

    const finalized = await service.finalizeWalletRegistration({
      registrationCeremonyId: started.registrationCeremonyId,
      ed25519: {
        evaluationResult: { stagedEvaluatorArtifactB64u: 'evaluation-result' } as any,
      },
    });
    expect(finalized).toMatchObject({
      ok: true,
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
      ed25519: {
        nearAccountId: 'alice.testnet',
        publicKey: 'ed25519:public-key',
      },
    });
    expect(ed25519FinalizeRequest).toMatchObject({
      request: {
        ceremonyHandle: 'passkey-ed25519-handle',
      },
    });
    expect(accountCreation).toMatchObject({
      accountId: 'alice.testnet',
      publicKey: 'ed25519:public-key',
    });
    expect(authenticatorWrites).toBe(1);
    expect(bindingWrite).toMatchObject({
      userId: 'wallet_alice',
      signerSlot: 1,
      publicKey: 'ed25519:public-key',
    });
  });

  test('starts Email OTP registration with a digest-bound authority proof', async () => {
    const service = makeService();
    let challengeVerification: Record<string, unknown> | null = null;
    (service as any).verifyEmailOtpChallengeCode = async (request: Record<string, unknown>) => {
      challengeVerification = request;
      return {
        ok: true,
        challengeId: request.challengeId,
        userId: request.userId,
        walletId: request.walletId,
        orgId: request.orgId,
        email: 'alice@example.test',
        otpChannel: 'email_otp',
      };
    };
    (service as any).getThresholdSigningService = () => ({
      ed25519Hss: {
        prepareForRegistration: async () => ({
          ok: true,
          ceremonyHandle: 'email-otp-ed25519-handle',
          preparedSession: { prepared: true },
          clientOtOfferMessageB64u: 'client-ot-offer',
        }),
      },
    });

    const allocated = await allocateEmailOtpIntent(service);
    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    const started = await service.startWalletRegistration({
      registrationIntentGrant: allocated.registrationIntentGrant,
      registrationIntentDigestB64u: allocated.registrationIntentDigestB64u,
      intent: allocated.intent,
      authority: {
        kind: 'email_otp',
        emailOtpRegistrationProof: {
          version: 'email_otp_registration_proof_v1',
          email: 'alice@example.test',
          challengeId: 'email-otp-challenge-1',
          otpCode: '123456',
          otpChannel: 'email_otp',
          registrationIntentDigestB64u: allocated.registrationIntentDigestB64u,
          appSessionVersion: 'email-otp-registration-v1',
        },
      },
    });

    expect(started).toMatchObject({
      ok: true,
      ed25519: {
        ceremonyHandle: 'email-otp-ed25519-handle',
      },
    });
    expect(challengeVerification).toMatchObject({
      userId: 'alice@example.test',
      walletId: 'wallet_alice',
      orgId: ORG_ID,
      challengeId: 'email-otp-challenge-1',
      otpCode: '123456',
      otpChannel: 'email_otp',
      sessionHash: allocated.registrationIntentDigestB64u,
      appSessionVersion: 'email-otp-registration-v1',
      expectedAction: 'wallet_email_otp_registration',
      expectedOperation: 'registration',
    });

    if (!started.ok) throw new Error(started.message);
    const ceremony = await (service as any)
      .getRegistrationCeremonyStore()
      .getCeremony(started.registrationCeremonyId);
    expect(ceremony.authority).toMatchObject({
      kind: 'email_otp',
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
      challengeId: 'email-otp-challenge-1',
      registrationIntentDigestB64u: allocated.registrationIntentDigestB64u,
    });
    expect(ceremony.authority.emailHashHex).toMatch(/^[0-9a-f]{64}$/);
  });

  test('finalizes Email OTP Ed25519 registration with an Email OTP auth-method row', async () => {
    const service = makeService();
    (service as any).verifyEmailOtpChallengeCode = async () => ({
      ok: true,
      challengeId: 'email-otp-challenge-1',
      userId: 'alice@example.test',
      walletId: 'wallet_alice',
      orgId: ORG_ID,
      email: 'alice@example.test',
      otpChannel: 'email_otp',
    });
    let authenticatorWrites = 0;
    let credentialBindingWrites = 0;
    let walletAuthMethodWrite: Record<string, unknown> | null = null;
    (service as any).createAccount = async () => ({ success: true });
    (service as any).getWebAuthnAuthenticatorStore = () => ({
      put: async () => {
        authenticatorWrites += 1;
      },
    });
    (service as any).getWebAuthnCredentialBindingStore = () => ({
      put: async () => {
        credentialBindingWrites += 1;
      },
    });
    (service as any).getWalletAuthMethodStore = () => ({
      put: async (record: Record<string, unknown>) => {
        walletAuthMethodWrite = record;
      },
    });
    (service as any).getThresholdSigningService = () => ({
      ed25519Hss: {
        prepareForRegistration: async () => ({
          ok: true,
          ceremonyHandle: 'email-otp-ed25519-handle',
          preparedSession: { prepared: true },
          clientOtOfferMessageB64u: 'client-ot-offer',
        }),
        respondForRegistration: async () => ({
          ok: true,
          contextBindingB64u: 'context-binding',
          serverInputDeliveryB64u: 'server-input-delivery',
        }),
        finalizeForRegistration: async () => ({
          ok: true,
          publicKey: 'ed25519:public-key',
          relayerKeyId: 'relayer-key-ed25519',
        }),
      },
      getSchemeModule: () => ({
        schemeId: 'threshold-ed25519-frost-2p-v1',
        registration: {
          keygenFromRegistrationMaterial: async () => ({
            ok: true,
            publicKey: 'ed25519:public-key',
            relayerKeyId: 'relayer-key-ed25519',
            keyVersion: 'threshold-ed25519-hss-v1',
            recoveryExportCapable: true,
            clientParticipantId: 1,
            relayerParticipantId: 2,
            participantIds: [1, 2],
          }),
        },
      }),
    });

    const allocated = await allocateEmailOtpIntent(service);
    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    const started = await service.startWalletRegistration({
      registrationIntentGrant: allocated.registrationIntentGrant,
      registrationIntentDigestB64u: allocated.registrationIntentDigestB64u,
      intent: allocated.intent,
      authority: {
        kind: 'email_otp',
        emailOtpRegistrationProof: {
          version: 'email_otp_registration_proof_v1',
          email: 'alice@example.test',
          challengeId: 'email-otp-challenge-1',
          otpCode: '123456',
          otpChannel: 'email_otp',
          registrationIntentDigestB64u: allocated.registrationIntentDigestB64u,
          appSessionVersion: 'email-otp-registration-v1',
        },
      },
    });
    expect(started).toMatchObject({ ok: true });
    if (!started.ok) throw new Error('Email OTP start failed');

    await expect(
      service.respondWalletRegistrationHss({
        registrationCeremonyId: started.registrationCeremonyId,
        ed25519: {
          clientRequest: { clientRequestMessageB64u: 'client-request' } as any,
        },
      }),
    ).resolves.toMatchObject({ ok: true });

    await expect(
      service.finalizeWalletRegistration({
        registrationCeremonyId: started.registrationCeremonyId,
        ed25519: {
          evaluationResult: { stagedEvaluatorArtifactB64u: 'evaluation-result' } as any,
        },
        emailOtpEnrollment: emailOtpEnrollmentMaterial('wallet_alice', 'alice@example.test'),
      }),
    ).resolves.toMatchObject({
      ok: true,
      walletId: 'wallet_alice',
      ed25519: {
        nearAccountId: 'alice.testnet',
        publicKey: 'ed25519:public-key',
      },
    });

    expect(authenticatorWrites).toBe(0);
    expect(credentialBindingWrites).toBe(0);
    expect(walletAuthMethodWrite).toMatchObject({
      version: 'wallet_auth_method_v1',
      kind: 'email_otp',
      status: 'active',
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
      challengeId: 'email-otp-challenge-1',
    });
    expect(String((walletAuthMethodWrite as any)?.emailHashHex || '')).toMatch(/^[0-9a-f]{64}$/);
  });

  test('rejects Email OTP registration when challenge verification mismatches', async () => {
    const service = makeService();
    (service as any).verifyEmailOtpChallengeCode = async () => ({
      ok: false,
      code: 'challenge_mismatch',
      message: 'Email OTP challenge mismatch',
    });

    const allocated = await allocateEmailOtpIntent(service);
    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    await expect(
      service.startWalletRegistration({
        registrationIntentGrant: allocated.registrationIntentGrant,
        registrationIntentDigestB64u: allocated.registrationIntentDigestB64u,
        intent: allocated.intent,
        authority: {
          kind: 'email_otp',
          emailOtpRegistrationProof: {
            version: 'email_otp_registration_proof_v1',
            email: 'alice@example.test',
            challengeId: 'email-otp-challenge-1',
            otpCode: '123456',
            otpChannel: 'email_otp',
            registrationIntentDigestB64u: allocated.registrationIntentDigestB64u,
            appSessionVersion: 'email-otp-registration-v1',
          },
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'challenge_mismatch',
      message: 'Email OTP challenge mismatch',
    });
  });

  test('rejects Email OTP proof allocated for another wallet id', async () => {
    const service = makeService();
    let verificationCalls = 0;
    (service as any).verifyEmailOtpChallengeCode = async () => {
      verificationCalls += 1;
      return { ok: true };
    };

    const allocated = await allocateEmailOtpIntent(service);
    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    const otherWalletIntent = await service.createRegistrationIntent({
      request: {
        wallet: {
          kind: 'provided',
          walletId: walletIdFromString('wallet_bob'),
        },
        rpId: 'wallet.example.test',
        authMethod: {
          kind: 'email_otp',
          email: 'alice@example.test',
          otpCode: '123456',
          appSessionJwt: 'app-session.jwt',
        },
        signerSelection: SIGNER_SELECTION,
      },
      orgId: ORG_ID,
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      expectedOrigin: 'https://wallet.example.test',
    });
    expect(otherWalletIntent.ok).toBe(true);
    if (!otherWalletIntent.ok) throw new Error(otherWalletIntent.message);

    await expect(
      service.startWalletRegistration({
        registrationIntentGrant: allocated.registrationIntentGrant,
        registrationIntentDigestB64u: allocated.registrationIntentDigestB64u,
        intent: allocated.intent,
        authority: {
          kind: 'email_otp',
          emailOtpRegistrationProof: {
            version: 'email_otp_registration_proof_v1',
            email: 'alice@example.test',
            challengeId: 'email-otp-challenge-1',
            otpCode: '123456',
            otpChannel: 'email_otp',
            registrationIntentDigestB64u: otherWalletIntent.registrationIntentDigestB64u,
            appSessionVersion: 'email-otp-registration-v1',
          },
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'registration_intent_digest_mismatch',
    });
    expect(verificationCalls).toBe(0);
  });

  test('rejects Email OTP proof allocated for another signer selection', async () => {
    const service = makeService();
    let verificationCalls = 0;
    (service as any).verifyEmailOtpChallengeCode = async () => {
      verificationCalls += 1;
      return { ok: true };
    };

    const allocated = await allocateEmailOtpIntent(service);
    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    const otherSelectionIntent = await allocateIntent(
      service,
      COMBINED_SIGNER_SELECTION,
      {
        kind: 'email_otp',
        email: 'alice@example.test',
        otpCode: '123456',
        appSessionJwt: 'app-session.jwt',
      },
    );
    expect(otherSelectionIntent.ok).toBe(true);
    if (!otherSelectionIntent.ok) throw new Error(otherSelectionIntent.message);

    await expect(
      service.startWalletRegistration({
        registrationIntentGrant: allocated.registrationIntentGrant,
        registrationIntentDigestB64u: allocated.registrationIntentDigestB64u,
        intent: allocated.intent,
        authority: {
          kind: 'email_otp',
          emailOtpRegistrationProof: {
            version: 'email_otp_registration_proof_v1',
            email: 'alice@example.test',
            challengeId: 'email-otp-challenge-1',
            otpCode: '123456',
            otpChannel: 'email_otp',
            registrationIntentDigestB64u: otherSelectionIntent.registrationIntentDigestB64u,
            appSessionVersion: 'email-otp-registration-v1',
          },
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'registration_intent_digest_mismatch',
    });
    expect(verificationCalls).toBe(0);
  });

  test('runs combined Ed25519 and ECDSA registration through one ceremony', async () => {
    const service = makeService();
    let webAuthnCreateVerifications = 0;
    (service as any).verifyRegistrationCredentialForIntent = async () => {
      webAuthnCreateVerifications += 1;
      return {
        ok: true,
        credential: {
          credentialIdB64u: 'credential-id',
          credentialPublicKeyB64u: 'credential-public-key',
          counter: 0,
        },
      };
    };
    let accountCreation: Record<string, unknown> | null = null;
    let bindingWrite: Record<string, unknown> | null = null;
    let authenticatorWrites = 0;
    let ed25519PrepareRequest: Record<string, unknown> | null = null;
    let ed25519RespondRequest: Record<string, unknown> | null = null;
    let ed25519FinalizeRequest: Record<string, unknown> | null = null;
    let ecdsaBootstrapRequest: Record<string, unknown> | null = null;
    (service as any).createAccount = async (request: Record<string, unknown>) => {
      accountCreation = request;
      return { success: true };
    };
    (service as any).getWebAuthnAuthenticatorStore = () => ({
      put: async () => {
        authenticatorWrites += 1;
      },
    });
    (service as any).getWebAuthnCredentialBindingStore = () => ({
      put: async (record: Record<string, unknown>) => {
        bindingWrite = record;
      },
    });
    (service as any).getThresholdSigningService = () => ({
      ed25519Hss: {
        prepareForRegistration: async (request: Record<string, unknown>) => {
          ed25519PrepareRequest = request;
          return {
            ok: true,
            ceremonyHandle: 'combined-ed25519-handle',
            preparedSession: { prepared: true },
            clientOtOfferMessageB64u: 'client-ot-offer',
          };
        },
        respondForRegistration: async (request: Record<string, unknown>) => {
          ed25519RespondRequest = request;
          return {
            ok: true,
            contextBindingB64u: 'context-binding',
            serverInputDeliveryB64u: 'server-input-delivery',
          };
        },
        finalizeForRegistration: async (request: Record<string, unknown>) => {
          ed25519FinalizeRequest = request;
          return {
            ok: true,
            publicKey: 'ed25519:public-key',
            relayerKeyId: 'relayer-key-ed25519',
          };
        },
      },
      ecdsaHssRoleLocalBootstrap: async (request: Record<string, unknown>) => {
        ecdsaBootstrapRequest = request;
        return {
          ok: true,
          value: ecdsaServerBootstrapValue({
            request,
            keyHandle: 'ehss-combined-key-alice',
            ownerAddress: '0x3333333333333333333333333333333333333333',
          }),
        };
      },
      getSchemeModule: () => ({
        schemeId: 'threshold-ed25519-frost-2p-v1',
        registration: {
          keygenFromRegistrationMaterial: async () => ({
            ok: true,
            publicKey: 'ed25519:public-key',
            relayerKeyId: 'relayer-key-ed25519',
            keyVersion: 'threshold-ed25519-hss-v1',
            recoveryExportCapable: true,
            clientParticipantId: 1,
            relayerParticipantId: 2,
            participantIds: [1, 2],
          }),
        },
      }),
    });

    const allocated = await allocateIntent(service, COMBINED_SIGNER_SELECTION);

    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    const startRequest = {
      registrationIntentGrant: allocated.registrationIntentGrant,
      registrationIntentDigestB64u: allocated.registrationIntentDigestB64u,
      intent: allocated.intent,
      authority: {
        kind: 'passkey' as const,
        webauthnRegistration: {
          response: {
            clientDataJSON: clientDataJsonB64u({
              challenge: allocated.registrationIntentDigestB64u,
            }),
          },
        },
      },
    };

    const started = await service.startWalletRegistration(startRequest);
    expect(started).toMatchObject({
      ok: true,
      ed25519: {
        ceremonyHandle: 'combined-ed25519-handle',
      },
      ecdsa: {
        kind: 'evm_family_ecdsa_keygen',
        chainTargets: ECDSA_SIGNER_SELECTION.ecdsa.chainTargets,
      },
    });
    if (!started.ok || !started.ed25519 || !started.ecdsa) {
      throw new Error('combined registration start failed');
    }
    expect(webAuthnCreateVerifications).toBe(1);
    expect(ed25519PrepareRequest).toMatchObject({
      orgId: ORG_ID,
      request: {
        new_account_id: 'alice.testnet',
        rp_id: 'wallet.example.test',
      },
    });

    const clientBootstrap = {
      ...started.ecdsa.prepare,
      runtimePolicyScope: {
        signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
        envId: RUNTIME_POLICY_SCOPE.envId,
        projectId: RUNTIME_POLICY_SCOPE.projectId,
        orgId: RUNTIME_POLICY_SCOPE.orgId,
      },
      clientPublicKey33B64u: 'client-public-key',
      clientShareRetryCounter: 0,
      contextBinding32B64u: 'context-binding',
    };
    const responded = await service.respondWalletRegistrationHss({
      registrationCeremonyId: started.registrationCeremonyId,
      ed25519: {
        clientRequest: { clientRequestMessageB64u: 'client-request' } as any,
      },
      ecdsa: {
        clientBootstrap,
      },
    });
    expect(responded).toMatchObject({
      ok: true,
      ed25519: {
        serverInputDeliveryB64u: 'server-input-delivery',
      },
      ecdsa: {
        bootstrap: {
          keyHandle: 'ehss-combined-key-alice',
        },
      },
    });
    expect(ed25519RespondRequest).toMatchObject({
      request: {
        ceremonyHandle: 'combined-ed25519-handle',
      },
    });
    expect(ecdsaBootstrapRequest).toMatchObject(clientBootstrap);

    const finalized = await service.finalizeWalletRegistration({
      registrationCeremonyId: started.registrationCeremonyId,
      ed25519: {
        evaluationResult: { stagedEvaluatorArtifactB64u: 'evaluation-result' } as any,
      },
      ecdsa: {
        expectedKeyHandles: ['ehss-combined-key-alice'],
      },
    });
    expect(finalized).toMatchObject({
      ok: true,
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
      ed25519: {
        nearAccountId: 'alice.testnet',
        publicKey: 'ed25519:public-key',
      },
    });
    expect(finalized.ok && finalized.ecdsa?.walletKeys).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          chainTarget: COMBINED_SIGNER_SELECTION.ecdsa.chainTargets[0],
          keyHandle: 'ehss-combined-key-alice',
          thresholdOwnerAddress: '0x3333333333333333333333333333333333333333',
        }),
        expect.objectContaining({
          chainTarget: COMBINED_SIGNER_SELECTION.ecdsa.chainTargets[1],
          keyHandle: 'ehss-combined-key-alice',
          thresholdOwnerAddress: '0x3333333333333333333333333333333333333333',
        }),
      ]),
    );
    expect(finalized.ok && finalized.ecdsa?.walletKeys).toHaveLength(2);
    expect(ed25519FinalizeRequest).toMatchObject({
      request: {
        ceremonyHandle: 'combined-ed25519-handle',
      },
    });
    expect(accountCreation).toMatchObject({
      accountId: 'alice.testnet',
      publicKey: 'ed25519:public-key',
    });
    expect(authenticatorWrites).toBe(1);
    expect(bindingWrite).toMatchObject({
      userId: 'wallet_alice',
      signerSlot: 1,
      publicKey: 'ed25519:public-key',
    });
  });

  test('runs ECDSA-only registration through start, respond, and finalize', async () => {
    const service = makeService();
    (service as any).verifyRegistrationCredentialForIntent = async () => ({
      ok: true,
      credential: {
        credentialIdB64u: 'credential-id',
        credentialPublicKeyB64u: 'credential-public-key',
        counter: 0,
      },
    });

    let bootstrapRequest: Record<string, unknown> | null = null;
    let accountCreationCalls = 0;
    (service as any).createAccount = async () => {
      accountCreationCalls += 1;
      return { success: true };
    };
    (service as any).getThresholdSigningService = () => ({
      ecdsaHssRoleLocalBootstrap: async (request: Record<string, unknown>) => {
        bootstrapRequest = request;
        return {
          ok: true,
          value: ecdsaServerBootstrapValue({
            request,
            keyHandle: 'ehss-key-alice',
            ownerAddress: '0x1111111111111111111111111111111111111111',
          }),
        };
      },
    });

    const allocated = await allocateIntent(service, ECDSA_SIGNER_SELECTION);
    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    const started = await service.startWalletRegistration({
      registrationIntentGrant: allocated.registrationIntentGrant,
      registrationIntentDigestB64u: allocated.registrationIntentDigestB64u,
      intent: allocated.intent,
      authority: {
        kind: 'passkey',
        webauthnRegistration: {
          response: {
            clientDataJSON: clientDataJsonB64u({
              challenge: allocated.registrationIntentDigestB64u,
            }),
          },
        },
      },
    });

    expect(started).toMatchObject({
      ok: true,
      ecdsa: {
        kind: 'evm_family_ecdsa_keygen',
        chainTargets: ECDSA_SIGNER_SELECTION.ecdsa.chainTargets,
      },
    });
    if (!started.ok || !started.ecdsa) throw new Error('ECDSA start failed');

    const clientBootstrap = {
      ...started.ecdsa.prepare,
      clientPublicKey33B64u: 'client-public-key',
      clientShareRetryCounter: 0,
      contextBinding32B64u: 'context-binding',
    };
    const responded = await service.respondWalletRegistrationHss({
      registrationCeremonyId: started.registrationCeremonyId,
      ecdsa: {
        clientBootstrap,
      },
    });

    expect(responded).toMatchObject({
      ok: true,
      ecdsa: {
        bootstrap: {
          keyHandle: 'ehss-key-alice',
        },
      },
    });
    expect(bootstrapRequest).toMatchObject(clientBootstrap);

    const finalized = await service.finalizeWalletRegistration({
      registrationCeremonyId: started.registrationCeremonyId,
      ecdsa: {
        expectedKeyHandles: ['ehss-key-alice'],
      },
    });

    expect(finalized).toMatchObject({
      ok: true,
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
      ecdsa: {
        walletKeys: [
          {
            keyHandle: 'ehss-key-alice',
            chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 1 },
            thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
          },
          {
            keyHandle: 'ehss-key-alice',
            chainTarget: { kind: 'tempo', chainId: 42431 },
            thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
          },
        ],
      },
    });
    if (!finalized.ok || !finalized.ecdsa) throw new Error('ECDSA finalize failed');
    const [evmWalletKey, tempoWalletKey] = finalized.ecdsa.walletKeys;
    expect(evmWalletKey).toMatchObject({
      keyHandle: 'ehss-key-alice',
      ecdsaThresholdKeyId: tempoWalletKey.ecdsaThresholdKeyId,
      signingRootId: tempoWalletKey.signingRootId,
      signingRootVersion: tempoWalletKey.signingRootVersion,
      thresholdEcdsaPublicKeyB64u: tempoWalletKey.thresholdEcdsaPublicKeyB64u,
      thresholdOwnerAddress: tempoWalletKey.thresholdOwnerAddress,
      relayerKeyId: tempoWalletKey.relayerKeyId,
      relayerVerifyingShareB64u: tempoWalletKey.relayerVerifyingShareB64u,
      participantIds: tempoWalletKey.participantIds,
    });
    expect(accountCreationCalls).toBe(0);
  });

  test('rejects ECDSA-only registration finalize when bootstrap key facts are incomplete', async () => {
    const service = makeService();
    (service as any).verifyRegistrationCredentialForIntent = async () => ({
      ok: true,
      credential: {
        credentialIdB64u: 'credential-id',
        credentialPublicKeyB64u: 'credential-public-key',
        counter: 0,
      },
    });
    let authenticatorWrites = 0;
    let credentialBindingWrites = 0;
    let walletAuthMethodWrites = 0;
    let walletWrites = 0;
    let walletSignerWrites = 0;
    (service as any).getWebAuthnAuthenticatorStore = () => ({
      put: async () => {
        authenticatorWrites += 1;
      },
    });
    (service as any).getWebAuthnCredentialBindingStore = () => ({
      put: async () => {
        credentialBindingWrites += 1;
      },
    });
    (service as any).getWalletAuthMethodStore = () => ({
      put: async () => {
        walletAuthMethodWrites += 1;
      },
    });
    (service as any).getWalletStore = () => ({
      putSubject: async () => {
        walletWrites += 1;
      },
      putSigner: async () => {
        walletSignerWrites += 1;
      },
      putSigners: async () => {
        walletSignerWrites += 1;
      },
    });
    (service as any).getThresholdSigningService = () => ({
      ecdsaHssRoleLocalBootstrap: async (request: Record<string, unknown>) => ({
        ok: true,
        value: ecdsaServerBootstrapValue({
          request,
          keyHandle: '',
          ownerAddress: '0x1111111111111111111111111111111111111111',
        }),
      }),
    });

    const allocated = await allocateIntent(service, ECDSA_SIGNER_SELECTION);
    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    const started = await service.startWalletRegistration({
      registrationIntentGrant: allocated.registrationIntentGrant,
      registrationIntentDigestB64u: allocated.registrationIntentDigestB64u,
      intent: allocated.intent,
      authority: {
        kind: 'passkey',
        webauthnRegistration: {
          response: {
            clientDataJSON: clientDataJsonB64u({
              challenge: allocated.registrationIntentDigestB64u,
            }),
          },
        },
      },
    });
    expect(started.ok).toBe(true);
    if (!started.ok || !started.ecdsa) throw new Error('ECDSA start failed');

    const responded = await service.respondWalletRegistrationHss({
      registrationCeremonyId: started.registrationCeremonyId,
      ecdsa: {
        clientBootstrap: {
          ...started.ecdsa.prepare,
          clientPublicKey33B64u: 'client-public-key',
          clientShareRetryCounter: 0,
          contextBinding32B64u: 'context-binding',
        },
      },
    });
    expect(responded.ok).toBe(true);

    await expect(
      service.finalizeWalletRegistration({
        registrationCeremonyId: started.registrationCeremonyId,
        ecdsa: {
          expectedKeyHandles: [],
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message: expect.stringContaining('keyHandle'),
    });
    expect(authenticatorWrites).toBe(0);
    expect(credentialBindingWrites).toBe(0);
    expect(walletAuthMethodWrites).toBe(0);
    expect(walletWrites).toBe(0);
    expect(walletSignerWrites).toBe(0);
  });

  test('starts and finalizes passkey add-auth-method for an existing wallet', async () => {
    const service = makeService();
    const authMethodStore = (service as any).getWalletAuthMethodStore();
    let walletWrites = 0;
    let walletSignerWrites = 0;
    (service as any).getWalletStore = () => ({
      putSubject: async () => {
        walletWrites += 1;
      },
      putSigner: async () => {
        walletSignerWrites += 1;
      },
      putSigners: async () => {
        walletSignerWrites += 1;
      },
    });
    await authMethodStore.put(
      activePasskeyAuthMethod({
        credentialIdB64u: EXISTING_PASSKEY_CREDENTIAL_ID,
      }),
    );
    (service as any).verifyRegistrationCredentialForIntent = async () => ({
      ok: true,
      credential: {
        credentialIdB64u: NEW_PASSKEY_CREDENTIAL_ID,
        credentialPublicKeyB64u: 'new-credential-public-key',
        counter: 7,
      },
    });

    const allocated = await allocateAddAuthMethodIntent(service);
    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    const started = await service.startWalletAddAuthMethod({
      walletId: allocated.intent.walletId,
      addAuthMethodIntentGrant: allocated.addAuthMethodIntentGrant,
      addAuthMethodIntentDigestB64u: allocated.addAuthMethodIntentDigestB64u,
      intent: allocated.intent,
      auth: {
        kind: 'webauthn_assertion',
        credential: {
          id: EXISTING_PASSKEY_CREDENTIAL_ID,
          rawId: EXISTING_PASSKEY_CREDENTIAL_ID,
          type: 'public-key',
          authenticatorAttachment: null,
          response: {
            clientDataJSON: 'client-data-json',
            authenticatorData: 'authenticator-data',
            signature: 'signature',
            userHandle: null,
          },
          clientExtensionResults: null,
        },
        expectedChallengeDigestB64u: allocated.addAuthMethodIntentDigestB64u,
      },
      authority: {
        kind: 'passkey',
        webauthnRegistration: {
          response: {
            clientDataJSON: clientDataJsonB64u({
              challenge: allocated.addAuthMethodIntentDigestB64u,
            }),
          },
        },
      },
    });

    expect(started).toMatchObject({
      ok: true,
      intent: allocated.intent,
    });
    if (!started.ok) throw new Error(started.message);

    const ceremony = await (service as any)
      .getRegistrationCeremonyStore()
      .getAddAuthMethodCeremony(started.addAuthMethodCeremonyId);
    expect(ceremony).toMatchObject({
      addAuthMethodCeremonyId: started.addAuthMethodCeremonyId,
      authority: {
        kind: 'passkey',
        credentialIdB64u: NEW_PASSKEY_CREDENTIAL_ID,
        credentialPublicKeyB64u: 'new-credential-public-key',
        counter: 7,
      },
    });

    const finalized = await service.finalizeWalletAddAuthMethod({
      addAuthMethodCeremonyId: started.addAuthMethodCeremonyId,
    });
    expect(finalized).toMatchObject({
      ok: true,
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
      authMethod: {
        kind: 'passkey',
        status: 'active',
      },
    });

    const walletMethods = await authMethodStore.listForWallet({
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
    });
    expect(walletMethods).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'passkey',
          credentialIdB64u: EXISTING_PASSKEY_CREDENTIAL_ID,
        }),
        expect.objectContaining({
          kind: 'passkey',
          credentialIdB64u: NEW_PASSKEY_CREDENTIAL_ID,
          credentialPublicKeyB64u: 'new-credential-public-key',
          counter: 7,
        }),
      ]),
    );
    const authenticator = await (service as any)
      .getWebAuthnAuthenticatorStore()
      .get('wallet_alice', NEW_PASSKEY_CREDENTIAL_ID);
    expect(authenticator).toMatchObject({
      credentialIdB64u: NEW_PASSKEY_CREDENTIAL_ID,
      credentialPublicKeyB64u: 'new-credential-public-key',
      counter: 7,
    });
    expect(walletWrites).toBe(0);
    expect(walletSignerWrites).toBe(0);
  });

  test('rejects passkey add-auth-method when the new credential already exists', async () => {
    const service = makeService();
    const authMethodStore = (service as any).getWalletAuthMethodStore();
    await authMethodStore.put(
      activePasskeyAuthMethod({
        credentialIdB64u: EXISTING_PASSKEY_CREDENTIAL_ID,
      }),
    );
    await authMethodStore.put(
      activePasskeyAuthMethod({
        walletId: 'wallet_other',
        credentialIdB64u: NEW_PASSKEY_CREDENTIAL_ID,
      }),
    );
    (service as any).verifyRegistrationCredentialForIntent = async () => ({
      ok: true,
      credential: {
        credentialIdB64u: NEW_PASSKEY_CREDENTIAL_ID,
        credentialPublicKeyB64u: 'new-credential-public-key',
        counter: 0,
      },
    });

    const allocated = await allocateAddAuthMethodIntent(service);
    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    await expect(
      service.startWalletAddAuthMethod({
        walletId: allocated.intent.walletId,
        addAuthMethodIntentGrant: allocated.addAuthMethodIntentGrant,
        addAuthMethodIntentDigestB64u: allocated.addAuthMethodIntentDigestB64u,
        intent: allocated.intent,
        auth: {
          kind: 'webauthn_assertion',
          credential: {
            id: EXISTING_PASSKEY_CREDENTIAL_ID,
            rawId: EXISTING_PASSKEY_CREDENTIAL_ID,
            type: 'public-key',
            authenticatorAttachment: null,
            response: {
              clientDataJSON: 'client-data-json',
              authenticatorData: 'authenticator-data',
              signature: 'signature',
              userHandle: null,
            },
            clientExtensionResults: null,
          },
          expectedChallengeDigestB64u: allocated.addAuthMethodIntentDigestB64u,
        },
        authority: {
          kind: 'passkey',
          webauthnRegistration: {
            response: {
              clientDataJSON: clientDataJsonB64u({
                challenge: allocated.addAuthMethodIntentDigestB64u,
              }),
            },
          },
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'duplicate_auth_method',
    });
  });

  test('starts and finalizes Email OTP add-auth-method for an existing wallet', async () => {
    const service = makeService();
    const authMethodStore = (service as any).getWalletAuthMethodStore();
    await authMethodStore.put(
      activePasskeyAuthMethod({
        credentialIdB64u: EXISTING_PASSKEY_CREDENTIAL_ID,
      }),
    );
    let verifyRequest: Record<string, unknown> | null = null;
    (service as any).verifyEmailOtpChallengeCode = async (request: Record<string, unknown>) => {
      verifyRequest = request;
      return {
        ok: true,
        challengeId: 'challenge-email-1',
        userId: 'alice@example.test',
        walletId: 'wallet_alice',
        orgId: ORG_ID,
        email: 'alice@example.test',
        otpChannel: 'email_otp',
      };
    };

    const allocated = await allocateAddAuthMethodIntent(service, {
      kind: 'email_otp',
      email: 'Alice@Example.Test',
    });
    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    const started = await service.startWalletAddAuthMethod({
      walletId: allocated.intent.walletId,
      addAuthMethodIntentGrant: allocated.addAuthMethodIntentGrant,
      addAuthMethodIntentDigestB64u: allocated.addAuthMethodIntentDigestB64u,
      intent: allocated.intent,
      auth: {
        kind: 'app_session',
        policy: {
          permission: 'wallet_auth_method_provision',
          walletId: allocated.intent.walletId,
          authMethod: allocated.intent.authMethod,
          runtimePolicyScope: RUNTIME_POLICY_SCOPE,
          expiresAtMs: Date.now() + 60_000,
        },
      },
      authority: {
        kind: 'email_otp',
        emailOtpRegistrationProof: {
          version: 'email_otp_registration_proof_v1',
          email: 'alice@example.test',
          challengeId: 'challenge-email-1',
          otpCode: '123456',
          otpChannel: 'email_otp',
          registrationIntentDigestB64u: allocated.addAuthMethodIntentDigestB64u,
          appSessionVersion: 'v1',
        },
      },
    });

    expect(started).toMatchObject({
      ok: true,
      intent: allocated.intent,
    });
    if (!started.ok) throw new Error(started.message);
    expect(verifyRequest).toMatchObject({
      userId: 'alice@example.test',
      walletId: 'wallet_alice',
      orgId: ORG_ID,
      challengeId: 'challenge-email-1',
      otpCode: '123456',
      otpChannel: 'email_otp',
      sessionHash: allocated.addAuthMethodIntentDigestB64u,
      appSessionVersion: 'v1',
      expectedAction: 'wallet_email_otp_registration',
      expectedOperation: 'registration',
    });

    const ceremony = await (service as any)
      .getRegistrationCeremonyStore()
      .getAddAuthMethodCeremony(started.addAuthMethodCeremonyId);
    expect(ceremony).toMatchObject({
      authority: {
        kind: 'email_otp',
        challengeId: 'challenge-email-1',
      },
    });

    const finalized = await service.finalizeWalletAddAuthMethod({
      addAuthMethodCeremonyId: started.addAuthMethodCeremonyId,
    });
    expect(finalized).toMatchObject({
      ok: true,
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
      authMethod: {
        kind: 'email_otp',
        status: 'active',
      },
    });

    const walletMethods = await authMethodStore.listForWallet({
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
    });
    expect(walletMethods).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'passkey',
          credentialIdB64u: EXISTING_PASSKEY_CREDENTIAL_ID,
        }),
        expect.objectContaining({
          kind: 'email_otp',
          challengeId: 'challenge-email-1',
          status: 'active',
        }),
      ]),
    );
  });

  test('rejects add-auth-method when the wallet has no active auth methods', async () => {
    const service = makeService();
    const allocated = await allocateAddAuthMethodIntent(service);
    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    await expect(
      service.startWalletAddAuthMethod({
        walletId: allocated.intent.walletId,
        addAuthMethodIntentGrant: allocated.addAuthMethodIntentGrant,
        addAuthMethodIntentDigestB64u: allocated.addAuthMethodIntentDigestB64u,
        intent: allocated.intent,
        auth: {
          kind: 'app_session',
          policy: {
            permission: 'wallet_auth_method_provision',
            walletId: allocated.intent.walletId,
            authMethod: allocated.intent.authMethod,
            runtimePolicyScope: RUNTIME_POLICY_SCOPE,
            expiresAtMs: Date.now() + 60_000,
          },
        },
        authority: {
          kind: 'passkey',
          webauthnRegistration: {
            response: {
              clientDataJSON: clientDataJsonB64u({
                challenge: allocated.addAuthMethodIntentDigestB64u,
              }),
            },
          },
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'not_found',
    });
  });

  test('revokes one auth method while preserving another active auth method', async () => {
    const service = makeService();
    const authMethodStore = (service as any).getWalletAuthMethodStore();
    await authMethodStore.put(
      activePasskeyAuthMethod({
        credentialIdB64u: EXISTING_PASSKEY_CREDENTIAL_ID,
      }),
    );
    await authMethodStore.put(
      activeEmailOtpAuthMethod({
        emailHashHex: 'email-hash-2',
        challengeId: 'challenge-email-2',
      }),
    );

    const revoked = await service.revokeWalletAuthMethod({
      walletId: walletIdFromString('wallet_alice'),
      rpId: 'wallet.example.test',
      auth: {
        kind: 'app_session',
        policy: {
          permission: 'wallet_auth_method_revoke',
          walletId: walletIdFromString('wallet_alice'),
          target: {
            kind: 'passkey',
            credentialIdB64u: EXISTING_PASSKEY_CREDENTIAL_ID,
          },
          runtimePolicyScope: RUNTIME_POLICY_SCOPE,
          expiresAtMs: Date.now() + 60_000,
        },
      },
      target: {
        kind: 'passkey',
        credentialIdB64u: EXISTING_PASSKEY_CREDENTIAL_ID,
      },
    });

    expect(revoked).toMatchObject({
      ok: true,
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
      authMethod: {
        kind: 'passkey',
        status: 'revoked',
      },
    });
    const walletMethods = await authMethodStore.listForWallet({
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
    });
    expect(walletMethods).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'passkey',
          credentialIdB64u: EXISTING_PASSKEY_CREDENTIAL_ID,
          status: 'revoked',
        }),
        expect.objectContaining({
          kind: 'email_otp',
          challengeId: 'challenge-email-2',
          status: 'active',
        }),
      ]),
    );
  });

  test('rejects revoking the last active auth method', async () => {
    const service = makeService();
    const authMethodStore = (service as any).getWalletAuthMethodStore();
    await authMethodStore.put(
      activePasskeyAuthMethod({
        credentialIdB64u: EXISTING_PASSKEY_CREDENTIAL_ID,
      }),
    );

    await expect(
      service.revokeWalletAuthMethod({
        walletId: walletIdFromString('wallet_alice'),
        rpId: 'wallet.example.test',
        auth: {
          kind: 'app_session',
          policy: {
            permission: 'wallet_auth_method_revoke',
            walletId: walletIdFromString('wallet_alice'),
            target: {
              kind: 'passkey',
              credentialIdB64u: EXISTING_PASSKEY_CREDENTIAL_ID,
            },
            runtimePolicyScope: RUNTIME_POLICY_SCOPE,
            expiresAtMs: Date.now() + 60_000,
          },
        },
        target: {
          kind: 'passkey',
          credentialIdB64u: EXISTING_PASSKEY_CREDENTIAL_ID,
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_state',
      message: 'wallet must retain at least one active auth method',
    });
  });

  test('runs Ed25519 add-signer through start, respond, and finalize without re-registering authenticator', async () => {
    const service = makeService();
    let accountCreation: Record<string, unknown> | null = null;
    let bindingWrite: Record<string, unknown> | null = null;
    let authenticatorWrites = 0;
    let prepareRequest: Record<string, unknown> | null = null;
    let respondRequest: Record<string, unknown> | null = null;
    let finalizeRequest: Record<string, unknown> | null = null;
    let keygenRequest: Record<string, unknown> | null = null;

    (service as any).createAccount = async (request: Record<string, unknown>) => {
      accountCreation = request;
      return { success: true };
    };
    (service as any).getWebAuthnAuthenticatorStore = () => ({
      put: async () => {
        authenticatorWrites += 1;
      },
    });
    (service as any).getWebAuthnCredentialBindingStore = () => ({
      put: async (record: Record<string, unknown>) => {
        bindingWrite = record;
      },
    });
    (service as any).getThresholdSigningService = () => ({
      ed25519Hss: {
        prepareForRegistration: async (request: Record<string, unknown>) => {
          prepareRequest = request;
          return {
            ok: true,
            ceremonyHandle: 'ed25519-add-signer-handle',
            preparedSession: { prepared: true },
            clientOtOfferMessageB64u: 'client-ot-offer',
          };
        },
        respondForRegistration: async (request: Record<string, unknown>) => {
          respondRequest = request;
          return {
            ok: true,
            contextBindingB64u: 'context-binding',
            serverInputDeliveryB64u: 'server-input-delivery',
          };
        },
        finalizeForRegistration: async (request: Record<string, unknown>) => {
          finalizeRequest = request;
          return {
            ok: true,
            publicKey: 'ed25519:public-key',
            relayerKeyId: 'relayer-key-ed25519',
          };
        },
      },
      getSchemeModule: () => ({
        schemeId: 'threshold-ed25519-frost-2p-v1',
        registration: {
          keygenFromRegistrationMaterial: async (request: Record<string, unknown>) => {
            keygenRequest = request;
            return {
              ok: true,
              publicKey: 'ed25519:public-key',
              relayerKeyId: 'relayer-key-ed25519',
              keyVersion: 'threshold-ed25519-hss-v1',
              recoveryExportCapable: true,
              clientParticipantId: 1,
              relayerParticipantId: 2,
              participantIds: [1, 2],
            };
          },
        },
      }),
    });

    const allocated = await allocateAddSignerIntent(
      service,
      ED25519_ADD_SIGNER_INTENT.signerSelection,
    );
    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    const started = await service.startWalletAddSigner({
      walletId: allocated.intent.walletId,
      addSignerIntentGrant: allocated.addSignerIntentGrant,
      addSignerIntentDigestB64u: allocated.addSignerIntentDigestB64u,
      intent: allocated.intent,
      auth: {
        kind: 'webauthn_assertion',
        credential: {
          id: 'Y3JlZGVudGlhbC1pZA',
          rawId: 'Y3JlZGVudGlhbC1pZA',
          type: 'public-key',
          authenticatorAttachment: null,
          response: {
            clientDataJSON: 'client-data-json',
            authenticatorData: 'authenticator-data',
            signature: 'signature',
            userHandle: null,
          },
          clientExtensionResults: null,
        },
        expectedChallengeDigestB64u: allocated.addSignerIntentDigestB64u,
      },
    });

    expect(started).toMatchObject({
      ok: true,
      ed25519: {
        ceremonyHandle: 'ed25519-add-signer-handle',
        clientOtOfferMessageB64u: 'client-ot-offer',
      },
    });
    if (!started.ok || !started.ed25519) throw new Error('Ed25519 add-signer start failed');
    expect(prepareRequest).toMatchObject({
      orgId: ORG_ID,
      request: {
        new_account_id: 'alice.testnet',
        rp_id: 'wallet.example.test',
        context: {
          nearAccountId: 'alice.testnet',
          keyPurpose: 'near_tx',
          keyVersion: 'threshold-ed25519-hss-v1',
          participantIds: [1, 2],
          derivationVersion: 1,
        },
      },
    });

    const responded = await service.respondWalletAddSignerHss({
      addSignerCeremonyId: started.addSignerCeremonyId,
      ed25519: {
        clientRequest: { clientRequestMessageB64u: 'client-request' } as any,
      },
    });

    expect(responded).toMatchObject({
      ok: true,
      ed25519: {
        contextBindingB64u: 'context-binding',
        serverInputDeliveryB64u: 'server-input-delivery',
      },
    });
    expect(respondRequest).toMatchObject({
      orgId: ORG_ID,
      request: {
        new_account_id: 'alice.testnet',
        rp_id: 'wallet.example.test',
        ceremonyHandle: 'ed25519-add-signer-handle',
      },
    });

    const finalized = await service.finalizeWalletAddSigner({
      addSignerCeremonyId: started.addSignerCeremonyId,
      ed25519: {
        evaluationResult: { stagedEvaluatorArtifactB64u: 'evaluation-result' } as any,
      },
    });

    expect(finalized).toMatchObject({
      ok: true,
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
      ed25519: {
        nearAccountId: 'alice.testnet',
        publicKey: 'ed25519:public-key',
        relayerKeyId: 'relayer-key-ed25519',
        keyVersion: 'threshold-ed25519-hss-v1',
      },
    });
    expect(finalizeRequest).toMatchObject({
      request: {
        new_account_id: 'alice.testnet',
        rp_id: 'wallet.example.test',
        ceremonyHandle: 'ed25519-add-signer-handle',
      },
    });
    expect(keygenRequest).toMatchObject({
      nearAccountId: 'alice.testnet',
      rpId: 'wallet.example.test',
      keyVersion: 'threshold-ed25519-hss-v1',
      publicKey: 'ed25519:public-key',
      relayerKeyId: 'relayer-key-ed25519',
    });
    expect(accountCreation).toEqual({
      accountId: 'alice.testnet',
      publicKey: 'ed25519:public-key',
    });
    expect(bindingWrite).toMatchObject({
      rpId: 'wallet.example.test',
      credentialIdB64u: 'Y3JlZGVudGlhbC1pZA',
      userId: 'wallet_alice',
      signerSlot: 2,
      publicKey: 'ed25519:public-key',
      relayerKeyId: 'relayer-key-ed25519',
      keyVersion: 'threshold-ed25519-hss-v1',
      recoveryExportCapable: true,
      participantIds: [1, 2],
    });
    expect(authenticatorWrites).toBe(0);
  });

  test('does not consume existing-account Ed25519 add-signer grants when ownership proof verification fails', async () => {
    const service = makeService();
    const proof = createNearAccountOwnershipProof({
      walletId: walletIdFromString('wallet_alice'),
      rpId: 'wallet.example.test',
      nearAccountId: 'alice.testnet',
    });
    (service as any).nearClient = {
      ...(service as any).nearClient,
      viewAccessKey: async () => ({ nonce: 1, permission: 'FullAccess' }),
    };
    const allocated = await allocateAddSignerIntent(service, {
      mode: 'ed25519',
      ed25519: {
        mode: 'link_existing_near_account',
        nearAccountId: 'alice.testnet',
        signerSlot: 2,
        participantIds: [1, 2],
        keyPurpose: 'near_tx',
        keyVersion: 'threshold-ed25519-hss-v1',
        derivationVersion: 1,
        accountOwnershipProof: {
          ...proof,
          signatureB64u: base64UrlEncode(new Uint8Array(64).fill(1)),
        },
      },
    });
    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    const startRequest = {
      walletId: allocated.intent.walletId,
      addSignerIntentGrant: allocated.addSignerIntentGrant,
      addSignerIntentDigestB64u: allocated.addSignerIntentDigestB64u,
      intent: allocated.intent,
      auth: {
        kind: 'app_session' as const,
        policy: {
          permission: 'wallet_signer_provision' as const,
          walletId: allocated.intent.walletId,
          signerSelection: allocated.intent.signerSelection,
          runtimePolicyScope: RUNTIME_POLICY_SCOPE,
          expiresAtMs: Date.now() + 60_000,
        },
      },
    };

    await expect(service.startWalletAddSigner(startRequest)).resolves.toMatchObject({
      ok: false,
      code: 'invalid_account_ownership_proof',
    });
    await expect(service.startWalletAddSigner(startRequest)).resolves.toMatchObject({
      ok: false,
      code: 'invalid_account_ownership_proof',
    });
  });

  test('starts existing-account Ed25519 add-signer after verifying account ownership proof', async () => {
    const service = makeService();
    const proof = createNearAccountOwnershipProof({
      walletId: walletIdFromString('wallet_alice'),
      rpId: 'wallet.example.test',
      nearAccountId: 'alice.testnet',
    });
    let viewedAccessKey: Record<string, unknown> | null = null;
    let prepareRequest: Record<string, unknown> | null = null;
    (service as any).nearClient = {
      ...(service as any).nearClient,
      viewAccessKey: async (
        accountId: string,
        publicKey: string,
        finalityQuery: Record<string, unknown>,
      ) => {
        viewedAccessKey = { accountId, publicKey, finalityQuery };
        return { nonce: 1, permission: 'FullAccess' };
      },
    };
    (service as any).getThresholdSigningService = () => ({
      ed25519Hss: {
        prepareForRegistration: async (request: Record<string, unknown>) => {
          prepareRequest = request;
          return {
            ok: true,
            ceremonyHandle: 'ed25519-link-signer-handle',
            preparedSession: { prepared: true },
            clientOtOfferMessageB64u: 'client-ot-offer',
          };
        },
      },
    });

    const allocated = await allocateAddSignerIntent(service, {
      mode: 'ed25519',
      ed25519: {
        mode: 'link_existing_near_account',
        nearAccountId: 'alice.testnet',
        signerSlot: 2,
        participantIds: [1, 2],
        keyPurpose: 'near_tx',
        keyVersion: 'threshold-ed25519-hss-v1',
        derivationVersion: 1,
        accountOwnershipProof: proof,
      },
    });
    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    await expect(
      service.startWalletAddSigner({
        walletId: allocated.intent.walletId,
        addSignerIntentGrant: allocated.addSignerIntentGrant,
        addSignerIntentDigestB64u: allocated.addSignerIntentDigestB64u,
        intent: allocated.intent,
        auth: {
          kind: 'app_session',
          policy: {
            permission: 'wallet_signer_provision',
            walletId: allocated.intent.walletId,
            signerSelection: allocated.intent.signerSelection,
            runtimePolicyScope: RUNTIME_POLICY_SCOPE,
            expiresAtMs: Date.now() + 60_000,
          },
        },
      }),
    ).resolves.toMatchObject({
      ok: true,
      ed25519: {
        ceremonyHandle: 'ed25519-link-signer-handle',
        clientOtOfferMessageB64u: 'client-ot-offer',
      },
    });
    expect(viewedAccessKey).toEqual({
      accountId: 'alice.testnet',
      publicKey: proof.message.publicKey,
      finalityQuery: { finality: 'final' },
    });
    expect(prepareRequest).toMatchObject({
      request: {
        new_account_id: 'alice.testnet',
        rp_id: 'wallet.example.test',
      },
    });
  });

  test('runs ECDSA add-signer through start, respond, and finalize without re-registering authenticator', async () => {
    const service = makeService();
    let authenticatorWrites = 0;
    (service as any).getWebAuthnAuthenticatorStore = () => ({
      put: async () => {
        authenticatorWrites += 1;
      },
    });

    let bootstrapRequest: Record<string, unknown> | null = null;
    (service as any).getThresholdSigningService = () => ({
      ecdsaHssRoleLocalBootstrap: async (request: Record<string, unknown>) => {
        bootstrapRequest = request;
        return {
          ok: true,
          value: ecdsaServerBootstrapValue({
            request,
            keyHandle: 'ehss-add-signer-key-alice',
            ownerAddress: '0x2222222222222222222222222222222222222222',
          }),
        };
      },
    });

    const allocated = await allocateAddSignerIntent(service);
    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);
    const started = await service.startWalletAddSigner({
      walletId: allocated.intent.walletId,
      addSignerIntentGrant: allocated.addSignerIntentGrant,
      addSignerIntentDigestB64u: allocated.addSignerIntentDigestB64u,
      intent: allocated.intent,
      auth: {
        kind: 'webauthn_assertion',
        credential: {
          id: 'Y3JlZGVudGlhbC1pZA',
          rawId: 'Y3JlZGVudGlhbC1pZA',
          type: 'public-key',
          authenticatorAttachment: null,
          response: {
            clientDataJSON: 'client-data-json',
            authenticatorData: 'authenticator-data',
            signature: 'signature',
            userHandle: null,
          },
          clientExtensionResults: null,
        },
        expectedChallengeDigestB64u: allocated.addSignerIntentDigestB64u,
      },
    });

    expect(started).toMatchObject({
      ok: true,
      ecdsa: {
        kind: 'evm_family_ecdsa_keygen',
        chainTargets: ECDSA_SIGNER_SELECTION.ecdsa.chainTargets,
      },
    });
    if (!started.ok || !started.ecdsa) throw new Error('ECDSA add-signer start failed');

    const clientBootstrap = {
      ...started.ecdsa.prepare,
      clientPublicKey33B64u: 'client-public-key',
      clientShareRetryCounter: 0,
      contextBinding32B64u: 'context-binding',
    };
    const responded = await service.respondWalletAddSignerHss({
      addSignerCeremonyId: started.addSignerCeremonyId,
      ecdsa: {
        clientBootstrap,
      },
    });

    expect(responded).toMatchObject({
      ok: true,
      ecdsa: {
        bootstrap: {
          keyHandle: 'ehss-add-signer-key-alice',
        },
      },
    });
    expect(bootstrapRequest).toMatchObject(clientBootstrap);

    const finalized = await service.finalizeWalletAddSigner({
      addSignerCeremonyId: started.addSignerCeremonyId,
      ecdsa: {
        expectedKeyHandles: ['ehss-add-signer-key-alice'],
      },
    });

    expect(finalized).toMatchObject({
      ok: true,
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
      ecdsa: {
        walletKeys: [
          {
            keyHandle: 'ehss-add-signer-key-alice',
            chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 1 },
            thresholdOwnerAddress: '0x2222222222222222222222222222222222222222',
          },
          {
            keyHandle: 'ehss-add-signer-key-alice',
            chainTarget: { kind: 'tempo', chainId: 42431 },
            thresholdOwnerAddress: '0x2222222222222222222222222222222222222222',
          },
        ],
      },
    });
    expect(authenticatorWrites).toBe(0);
  });

  test('rejects ECDSA add-signer finalize when bootstrap key facts are incomplete', async () => {
    const service = makeService();
    (service as any).getThresholdSigningService = () => ({
      ecdsaHssRoleLocalBootstrap: async (request: Record<string, unknown>) => ({
        ok: true,
        value: ecdsaServerBootstrapValue({
          request,
          keyHandle: 'ehss-add-signer-key-alice',
          ownerAddress: '0x2222222222222222222222222222222222222222',
          overrides: {
            thresholdEcdsaPublicKeyB64u: '',
          },
        }),
      }),
    });

    const allocated = await allocateAddSignerIntent(service);
    expect(allocated.ok).toBe(true);
    if (!allocated.ok) throw new Error(allocated.message);

    const started = await service.startWalletAddSigner({
      walletId: allocated.intent.walletId,
      addSignerIntentGrant: allocated.addSignerIntentGrant,
      addSignerIntentDigestB64u: allocated.addSignerIntentDigestB64u,
      intent: allocated.intent,
      auth: {
        kind: 'webauthn_assertion',
        credential: {
          id: 'Y3JlZGVudGlhbC1pZA',
          rawId: 'Y3JlZGVudGlhbC1pZA',
          type: 'public-key',
          authenticatorAttachment: null,
          response: {
            clientDataJSON: 'client-data-json',
            authenticatorData: 'authenticator-data',
            signature: 'signature',
            userHandle: null,
          },
          clientExtensionResults: null,
        },
        expectedChallengeDigestB64u: allocated.addSignerIntentDigestB64u,
      },
    });
    expect(started.ok).toBe(true);
    if (!started.ok || !started.ecdsa) throw new Error('ECDSA add-signer start failed');

    const responded = await service.respondWalletAddSignerHss({
      addSignerCeremonyId: started.addSignerCeremonyId,
      ecdsa: {
        clientBootstrap: {
          ...started.ecdsa.prepare,
          clientPublicKey33B64u: 'client-public-key',
          clientShareRetryCounter: 0,
          contextBinding32B64u: 'context-binding',
        },
      },
    });
    expect(responded.ok).toBe(true);

    await expect(
      service.finalizeWalletAddSigner({
        addSignerCeremonyId: started.addSignerCeremonyId,
        ecdsa: {
          expectedKeyHandles: [],
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message: expect.stringContaining('thresholdEcdsaPublicKeyB64u'),
    });
  });
});
