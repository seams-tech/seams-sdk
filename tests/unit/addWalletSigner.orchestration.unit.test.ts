import { expect, test } from '@playwright/test';
import {
  addWalletSigner,
  registerWallet,
} from '../../packages/sdk-web/src/SeamsWeb/operations/registration/registration';
import { createEvmSignerCapability } from '../../packages/sdk-web/src/SeamsWeb/publicApi/evm';
import { IndexedDBManager } from '../../packages/sdk-web/src/core/indexedDB';
import { finalizeWalletRegistrationEcdsaSessions as finalizeWalletRegistrationEcdsaSessionsOperation } from '../../packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions';
import { UserVerificationPolicy } from '../../packages/sdk-web/src/core/types/authenticatorOptions';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  clearAllThresholdEcdsaSessionRecords,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/records';
import { emailOtpRecoveryCodeBackupRepository } from '../../packages/sdk-web/src/core/indexedDB/seamsWalletDB/emailOtpRecoveryCodeBackups';
import {
  computeAddSignerNearEd25519SigningKeyId,
  computeAddSignerIntentDigestB64u,
  computeRegistrationIntentDigestB64u,
  normalizeRegistrationSignerPlan,
  registrationNearEd25519BranchKey,
  registrationSignerSetSelectionFromPlan,
  walletIdFromString,
  type RegistrationSignerRequest,
  type RegistrationSignerSetSelection,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import { base58Encode } from '../../packages/shared-ts/src/utils/base58';
import { sha256HexUtf8 } from '../../packages/shared-ts/src/utils/digests';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
} from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND } from '../../packages/shared-ts/src/utils/sessionTokens';
import { deriveEvmFamilySigningKeySlotIdFromRuntimePolicyScope } from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  computeSdkEcdsaDerivationApplicationBindingDigestB64u,
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
  parseSdkEcdsaDerivationThresholdKeyId,
  type DerivationClientSharePublicKey33B64u,
  type EcdsaDerivationRelayerPublicKey33B64u,
} from '../../packages/shared-ts/src/threshold/ecdsaDerivationRoleLocalBootstrap';
import {
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaRoleLocalMaterialHandle,
} from '../../packages/sdk-web/src/core/signingEngine/session/keyMaterialBrands';
import { parseRouterAbEcdsaDerivationPublicCapabilityV1 } from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
const RELAYER_URL = 'https://relay.example.test';
const WALLET_SUBJECT_ID = walletIdFromString('wallet-matrix.testnet');

function unwrapFixture<T>(result: { ok: true; value: T } | { ok: false }): T {
  if (!result.ok) throw new Error('invalid fixture value');
  return result.value;
}

const RP_ID = unwrapFixture(parseWebAuthnRpId('wallet.example.test'));
const AUTHENTICATION_PRF_FIRST_B64U = Buffer.alloc(32, 11).toString('base64url');
const REGISTRATION_PRF_FIRST_B64U = Buffer.alloc(32, 12).toString('base64url');
const CLIENT_PUBLIC_KEY_B64U =
  'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' as DerivationClientSharePublicKey33B64u;
const MISMATCHED_CLIENT_PUBLIC_KEY_B64U =
  'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' as DerivationClientSharePublicKey33B64u;
const RELAYER_PUBLIC_KEY_33_B64U =
  'AwEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB' as EcdsaDerivationRelayerPublicKey33B64u;
const GROUP_PUBLIC_KEY_33_B64U = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC';
const CONTEXT_BINDING_32_B64U = 'DQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0';
const EMAIL_OTP_PROVIDER_SUBJECT = 'google:registration-subject';
const EMAIL_OTP_ED25519_PUBLIC_KEY_BYTES = new Uint8Array(32);
const EMAIL_OTP_ED25519_PUBLIC_KEY = `ed25519:${base58Encode(EMAIL_OTP_ED25519_PUBLIC_KEY_BYTES)}`;
const RUNTIME_POLICY_SCOPE = {
  orgId: 'org_matrix',
  projectId: 'project_matrix',
  envId: 'dev',
  signingRootVersion: 'root_v1',
} as const;
const ECDSA_THRESHOLD_KEY_ID = parseSdkEcdsaDerivationThresholdKeyId('ecdsa-threshold-key-id');
const ECDSA_SIGNING_ROOT_ID = parseSdkEcdsaDerivationSigningRootId('project_matrix:dev');
const ECDSA_SIGNING_ROOT_VERSION = parseSdkEcdsaDerivationSigningRootVersion(
  RUNTIME_POLICY_SCOPE.signingRootVersion,
);

function captureEmailOtpRegistrationAfterCall(
  captures: Record<string, unknown>,
  success: boolean,
): void {
  captures.emailOtpAppSessionRememberedBeforeAfterCall =
    success && captures.rememberedEmailOtpAppSession !== undefined;
}

async function ecdsaApplicationBindingDigestB64u(walletId: unknown): Promise<string> {
  return await computeSdkEcdsaDerivationApplicationBindingDigestB64u({
    walletId: walletIdFromString(String(walletId)),
    ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
    signingRootId: ECDSA_SIGNING_ROOT_ID,
    signingRootVersion: ECDSA_SIGNING_ROOT_VERSION,
  });
}

async function mockedEcdsaFinalizeResponse(
  captures: Record<string, unknown>,
  walletId: string,
): Promise<Record<string, unknown>> {
  const intentAuthMethod = (captures.intent as any)?.authMethod;
  switch (intentAuthMethod?.kind) {
    case 'email_otp':
      return {
        ok: true,
        walletId,
        kind: 'evm_family_ecdsa',
        authority: buildEmailOtpWalletAuthAuthority({
          walletId,
          provider: 'google',
          providerUserId: EMAIL_OTP_PROVIDER_SUBJECT,
          emailHashHex: await sha256HexUtf8('alice@example.com'),
        }),
        authMethod: {
          kind: 'email_otp',
          registrationAuthorityId: 'registration-attempt-1',
        },
        appSessionJwt: String(intentAuthMethod.appSessionJwt || ''),
      };
    case 'passkey':
      return {
        ok: true,
        walletId,
        kind: 'evm_family_ecdsa',
        rpId: RP_ID,
        authority: buildPasskeyWalletAuthAuthority({
          walletId,
          rpId: RP_ID,
          credentialIdB64u: 'registration-credential-id',
        }),
        authMethod: {
          kind: 'passkey',
          credentialIdB64u: 'registration-credential-id',
          credentialPublicKeyB64u: 'registration-credential-public-key',
        },
      };
    default:
      throw new Error('registration fixture requires an exact auth method');
  }
}

function attachMockedEcdsaFinalizeWalletKeys(
  captures: Record<string, unknown>,
  responseWalletId: string,
  responseBody: Record<string, unknown>,
): void {
  const ecdsaFacts = captures.ecdsaRegistrationFacts as Record<string, any> | undefined;
  if (!ecdsaFacts) throw new Error('ECDSA finalize fixture is missing strict registration facts');
  const chainTargets = mockedRegistrationEvmFamilyEcdsaSigner(
    (captures.intent as any)?.signerSelection,
  )?.chainTargets || [{ kind: 'evm', namespace: 'eip155', chainId: 1 }];
  const patchRegistrationWalletKey = captures.patchRegistrationWalletKey as
    | ((walletKey: Record<string, unknown>) => Record<string, unknown>)
    | undefined;
  responseBody.ecdsa = {
    walletKeys: chainTargets.map((chainTarget: unknown) => {
      const walletKey = {
        keyScope: 'evm-family',
        chainTarget,
        walletId: responseWalletId,
        evmFamilySigningKeySlotId: plannedEcdsaWalletKeyId(responseWalletId),
        keyHandle: 'ederivation-registration-key',
        ecdsaThresholdKeyId: 'ecdsa-threshold-key-id',
        signingRootId: 'project_matrix:dev',
        signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
        thresholdOwnerAddress: '0x3333333333333333333333333333333333333333',
        relayerKeyId: 'relayer-ecdsa',
        relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
        contextBinding32B64u: CONTEXT_BINDING_32_B64U,
        derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
        clientShareRetryCounter: 0,
        relayerShareRetryCounter: 1,
        participantIds: [1, 2],
        publicCapability: mockedEcdsaPublicCapability(ecdsaFacts),
      };
      return patchRegistrationWalletKey ? patchRegistrationWalletKey(walletKey) : walletKey;
    }),
  };
}

function mockedRegistrationIntentSignerSelection(raw: unknown) {
  const plan = normalizeRegistrationSignerPlan(raw);
  if (!plan.ok) throw new Error(plan.message);
  const selection = registrationSignerSetSelectionFromPlan(plan.value);
  if (!selection.ok) throw new Error(selection.message);
  return selection.value;
}
function mockedRegistrationEvmFamilyEcdsaSigner(selection: any): any | null {
  const signers = Array.isArray(selection?.signers) ? selection.signers : [];
  return signers.find((signer: any) => signer?.kind === 'evm_family_ecdsa') || null;
}
function mockedRegistrationNearEd25519Signer(selection: any): any | null {
  const signers = Array.isArray(selection?.signers) ? selection.signers : [];
  for (const signer of signers) {
    if (signer?.kind === 'near_ed25519') return signer;
  }
  return null;
}
function evmFamilyRegistrationSigner(chainTargets: readonly unknown[]): RegistrationSignerRequest {
  return {
    kind: 'evm_family_ecdsa' as const,
    chainTargets: [...chainTargets],
    participantIds: [1, 2],
  };
}

function nearEd25519RegistrationSigner(): RegistrationSignerRequest {
  return {
    kind: 'near_ed25519' as const,
    accountProvisioning: {
      kind: 'implicit_account' as const,
      accountIdSource: 'ed25519_public_key' as const,
    },
    signerSlot: 1,
    participantIds: [1, 2],
    derivationVersion: 1,
  };
}

function registrationSignerSet(
  ...signers: readonly RegistrationSignerRequest[]
): RegistrationSignerSetSelection {
  return {
    kind: 'signer_set' as const,
    signers,
  };
}

function mockedRegistrationWalletId(body: any): ReturnType<typeof walletIdFromString> {
  if (body.wallet?.kind === 'provided') return walletIdFromString(String(body.wallet.walletId));
  return WALLET_SUBJECT_ID;
}

async function mockedRegistrationEcdsaStart(
  body: Record<string, any>,
  ecdsaSigner: Record<string, any>,
): Promise<Record<string, unknown>> {
  const registrationEcdsaBindingDigestB64u = await ecdsaApplicationBindingDigestB64u(
    body.intent.walletId,
  );
  const [firstChainTarget] = ecdsaSigner.chainTargets as unknown[];
  if (!firstChainTarget) throw new Error('ECDSA registration fixture requires a chain target');
  const mixedRegistration = mockedRegistrationNearEd25519Signer(body.intent.signerSelection) !== null;
  const prepare = {
    formatVersion: 'ecdsa-derivation-role-local',
    walletSessionUserId: String(body.intent.walletId),
    walletId: String(body.intent.walletId),
    evmFamilySigningKeySlotId: plannedEcdsaWalletKeyId(body.intent.walletId),
    rpId: RP_ID,
    subjectId: String(body.intent.walletId),
    ecdsaThresholdKeyId: 'ecdsa-threshold-key-id',
    signingRootId: 'project_matrix:dev',
    signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
    applicationBindingDigestB64u: registrationEcdsaBindingDigestB64u,
    keyScope: 'evm-family',
    relayerKeyId: 'relayer-ecdsa',
    registrationPreparationId: body.registrationPreparationId,
    requestId: 'request-ecdsa',
    thresholdSessionId: 'session-ecdsa',
    signingGrantId: mixedRegistration
      ? 'email-otp-ed25519-signing-grant'
      : 'wallet-session-ecdsa',
    ttlMs: 600_000,
    remainingUses: mixedRegistration ? 3 : 1,
    participantIds: [1, 2],
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
  };
  const registrationPurpose = 'wallet_registration';
  const strictRegistration = await mockedEcdsaStrictRegistrationFacts({
    body,
    registrationPurpose,
  });
  return {
    kind: 'evm_family_ecdsa_keygen',
    chainTargets: ecdsaSigner.chainTargets,
    prepare,
    strictRegistration,
  };
}

async function mockedEcdsaStrictRegistrationFacts(args: {
  body: Record<string, any>;
  registrationPurpose: 'wallet_registration' | 'wallet_add_signer';
}): Promise<Record<string, unknown>> {
  const walletId = String(args.body.intent.walletId);
  const applicationBindingDigestB64u = await ecdsaApplicationBindingDigestB64u(walletId);
  const signerSetId = `${args.registrationPurpose}-signer-set`;
  return {
    registration_purpose: args.registrationPurpose,
    context: { application_binding_digest_b64u: applicationBindingDigestB64u },
    lifecycle: {
      lifecycle_id: args.registrationPurpose,
      work_kind: 'registration_prepare',
      primitive_request_kind: 'registration',
      root_share_epoch: RUNTIME_POLICY_SCOPE.signingRootVersion,
      account_id: walletId,
      session_id: 'session-ecdsa',
      signer_set_id: signerSetId,
      selected_server_id: 'signing-worker-test',
    },
    signer_set: {
      signer_set_id: signerSetId,
      policy: 'all_2',
      signer_a: {
        role: 'signer_a',
        signer_id: 'signer-a-test',
        key_epoch: 'epoch-test',
      },
      signer_b: {
        role: 'signer_b',
        signer_id: 'signer-b-test',
        key_epoch: 'epoch-test',
      },
      selected_server: {
        server_id: 'signing-worker-test',
        key_epoch: 'worker-epoch-test',
        recipient_encryption_key:
          'x25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      },
    },
    router_id: 'router-registration-test',
    client_id: walletId,
    replay_nonce: 'registration-replay-nonce',
    expires_at_ms: Date.now() + 60_000,
    deriver_recipient_keys: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-test',
        public_key:
          'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-test',
        public_key:
          'x25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      },
    },
  };
}

function mockedEcdsaRegistrationRequest(facts: Record<string, any>): Record<string, unknown> {
  const digest = { bytes: new Array<number>(32).fill(0) };
  return {
    ...facts,
    client_ephemeral_public_key:
      'x25519:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    deriver_a_envelope: {
      recipient_role: 'signer_a',
      header_digest: digest,
      aad_digest: digest,
      ciphertext: { bytes: [1] },
    },
    deriver_b_envelope: {
      recipient_role: 'signer_b',
      header_digest: digest,
      aad_digest: digest,
      ciphertext: { bytes: [2] },
    },
  };
}

function mockedEcdsaPublicIdentity(): Record<string, unknown> {
  return {
    context_binding_b64u: CONTEXT_BINDING_32_B64U,
    derivation_client_share_public_key33_b64u: CLIENT_PUBLIC_KEY_B64U,
    server_public_key33_b64u: RELAYER_PUBLIC_KEY_33_B64U,
    threshold_public_key33_b64u: GROUP_PUBLIC_KEY_33_B64U,
    ethereum_address20_b64u: ethereumAddress20B64u(
      '0x3333333333333333333333333333333333333333',
    ),
    client_share_retry_counter: 0,
    server_share_retry_counter: 1,
  };
}

function mockedEcdsaPublicCapability(
  facts: Record<string, any>,
): Record<string, unknown> {
  return {
    kind: 'router_ab_ecdsa_derivation_public_capability_v1',
    context: facts.context,
    public_identity: mockedEcdsaPublicIdentity(),
    signer_set: facts.signer_set,
    deriver_recipient_keys: facts.deriver_recipient_keys,
    router_id: facts.router_id,
    client_id: facts.client_id,
    activation_epoch: facts.lifecycle.root_share_epoch,
    registration_request_digest_b64u: CONTEXT_BINDING_32_B64U,
    proof_transcript_digest_b64u: CONTEXT_BINDING_32_B64U,
  };
}

function mockedEcdsaServerBootstrap(
  facts: Record<string, any>,
  prepare: Record<string, any>,
): Record<string, unknown> {
  const walletId = String(prepare.walletId);
  const expiresAtMs = Date.now() + 60_000;
  const bootstrap: Record<string, unknown> = {
    formatVersion: 'ecdsa-derivation-role-local',
    walletId,
    evmFamilySigningKeySlotId: prepare.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: prepare.ecdsaThresholdKeyId,
    relayerKeyId: prepare.relayerKeyId,
    applicationBindingDigestB64u: facts.context.application_binding_digest_b64u,
    contextBinding32B64u: CONTEXT_BINDING_32_B64U,
    publicIdentity: {
      derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
      relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
      groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
      ethereumAddress: '0x3333333333333333333333333333333333333333',
    },
    clientShareRetryCounter: 0,
    relayerShareRetryCounter: 1,
    publicTranscriptDigest32B64u: CONTEXT_BINDING_32_B64U,
    keyHandle:
      facts.registration_purpose === 'wallet_add_signer'
        ? 'ederivation-key-matrix'
        : 'ederivation-registration-key',
    signingRootId: prepare.signingRootId,
    signingRootVersion: prepare.signingRootVersion,
    thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
    ethereumAddress: '0x3333333333333333333333333333333333333333',
    relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
    participantIds: [1, 2],
    thresholdSessionId: prepare.thresholdSessionId,
    activationEpoch: facts.lifecycle.root_share_epoch,
    signingGrantId: prepare.signingGrantId,
    expiresAtMs,
    expiresAt: new Date(expiresAtMs).toISOString(),
    remainingUses: prepare.remainingUses,
  };
  bootstrap.jwt = ecdsaWalletSessionJwtForBootstrap(bootstrap);
  return bootstrap;
}

function mockedEcdsaActivationReceipt(facts: Record<string, any>): Record<string, unknown> {
  return {
    ecdsa_activation: {
      context: facts.context,
      public_identity: {
        ...mockedEcdsaPublicIdentity(),
      },
      signing_worker: facts.signer_set.selected_server,
      activation_epoch: facts.lifecycle.root_share_epoch,
      activation_digest_b64u: CONTEXT_BINDING_32_B64U,
      activated_at_ms: Date.now(),
    },
    lifecycle_id: facts.lifecycle.lifecycle_id,
    transcript_digest: { bytes: new Array<number>(32).fill(0) },
    activated: true,
  };
}

function createLocalEvmCapability(deps: { getContext: () => any }) {
  const context = deps.getContext();
  return createEvmSignerCapability({
    signingEngine: context.signingEngine,
    nearClient: context.nearClient ?? {},
    configs: context.configs,
    getTheme: () => context.theme ?? 'light',
    getWalletIframe: () =>
      ({
        shouldUseWalletIframe: () => false,
        requireRouter: async () => {
          throw new Error('local EVM capability test should not require wallet iframe router');
        },
      }) as any,
  } as any);
}
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function jsonB64u(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function jwtWithPayload(payload: Record<string, unknown>): string {
  return `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u(payload)}.sig`;
}

function ed25519WalletSessionJwt(args: {
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  thresholdSessionId: string;
  signingGrantId: string;
}): string {
  return jwtWithPayload({
    kind: 'router_ab_ed25519_wallet_session_v1',
    sub: args.walletId,
    walletId: args.walletId,
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    relayerKeyId: 'signing-worker-test',
    rpId: RP_ID,
    participantIds: [1, 2],
  });
}

function ethereumAddress20B64u(address: string): string {
  return Buffer.from(address.replace(/^0x/i, ''), 'hex').toString('base64url');
}

function ecdsaWalletSessionJwtForBootstrap(bootstrap: Record<string, unknown>): string {
  const publicIdentity = bootstrap.publicIdentity as Record<string, unknown>;
  const sessionId = String(bootstrap.sessionId || bootstrap.thresholdSessionId || '').trim();
  const signingGrantId = String(bootstrap.signingGrantId || '').trim();
  const walletId = String(bootstrap.walletId || '').trim();
  const evmFamilySigningKeySlotId = String(bootstrap.evmFamilySigningKeySlotId || '').trim();
  const applicationBindingDigestB64u = String(bootstrap.applicationBindingDigestB64u || '').trim();
  const ecdsaThresholdKeyId = String(bootstrap.ecdsaThresholdKeyId || '').trim();
  const signingRootId = String(bootstrap.signingRootId || '').trim();
  const signingRootVersion = String(bootstrap.signingRootVersion || '').trim();
  const keyHandle = String(bootstrap.keyHandle || '').trim();
  const relayerKeyId = String(bootstrap.relayerKeyId || '').trim();
  const expiresAtMs = Number(bootstrap.expiresAtMs);
  const participantIds = Array.isArray(bootstrap.participantIds) ? bootstrap.participantIds : [];
  return jwtWithPayload({
    kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
    sub: walletId,
    walletId,
    evmFamilySigningKeySlotId,
    thresholdSessionId: sessionId,
    signingGrantId,
    keyScope: 'evm-family',
    keyHandle,
    relayerKeyId,
    rpId: RP_ID,
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    thresholdExpiresAtMs: expiresAtMs,
    participantIds,
    routerAbEcdsaDerivationNormalSigning: {
      kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
      scope: {
        wallet_id: walletId,
        wallet_key_id: evmFamilySigningKeySlotId,
        ecdsa_threshold_key_id: ecdsaThresholdKeyId,
        signing_root_id: signingRootId,
        signing_root_version: signingRootVersion,
        context: {
          application_binding_digest_b64u: applicationBindingDigestB64u,
        },
        public_identity: {
          context_binding_b64u: String(bootstrap.contextBinding32B64u || '').trim(),
          derivation_client_share_public_key33_b64u: String(
            publicIdentity.derivationClientSharePublicKey33B64u || '',
          ).trim(),
          server_public_key33_b64u: String(publicIdentity.relayerPublicKey33B64u || '').trim(),
          threshold_public_key33_b64u: String(publicIdentity.groupPublicKey33B64u || '').trim(),
          ethereum_address20_b64u: ethereumAddress20B64u(
            String(publicIdentity.ethereumAddress || bootstrap.ethereumAddress || ''),
          ),
          client_share_retry_counter: Number(bootstrap.clientShareRetryCounter),
          server_share_retry_counter: Number(bootstrap.relayerShareRetryCounter),
        },
        signing_worker: {
          server_id: 'signing-worker-test',
          key_epoch: 'worker-epoch-test',
        recipient_encryption_key:
            'x25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        },
        activation_epoch: String(bootstrap.activationEpoch || sessionId),
      },
    },
  });
}

function plannedEcdsaWalletKeyId(walletId: unknown): string {
  return String(
    deriveEvmFamilySigningKeySlotIdFromRuntimePolicyScope({
      walletId,
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    }),
  );
}
function credentialWithPrf() {
  return {
    id: 'credential-id',
    rawId: 'credential-id',
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: 'client-data-json',
      authenticatorData: 'authenticator-data',
      signature: 'signature',
      userHandle: null,
    },
    clientExtensionResults: {
      prf: {
        results: {
          first: AUTHENTICATION_PRF_FIRST_B64U,
        },
      },
    },
  };
}

function registrationCredentialWithPrf() {
  return {
    id: 'registration-credential-id',
    rawId: 'registration-credential-id',
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: 'client-data-json',
      attestationObject: 'attestation-object',
      transports: ['internal'],
    },
    clientExtensionResults: {
      prf: {
        results: {
          first: REGISTRATION_PRF_FIRST_B64U,
        },
      },
    },
  };
}

function incrementCaptureCounter(captures: Record<string, unknown>, key: string): void {
  captures[key] = Number(captures[key] || 0) + 1;
}

function expectSingleRegistrationTouchIdPrompt(captures: Record<string, unknown>): void {
  expect(captures.registrationCredentialPrompts).toBe(1);
  expect(captures.authenticationCredentialPrompts || 0).toBe(0);
}

function expectRegistrationSuccess(result: { success: boolean; error?: unknown }): void {
  if (!result.success) {
    throw new Error(String(result.error || 'registration returned success:false'));
  }
}

async function emptyWorkerWarmupDiagnostics() {
  return {
    kind: 'worker_resource_warmup_diagnostics_v1' as const,
    authenticatedWalletStateMs: 0,
    noncePrefetchMs: 0,
    keyMaterialReadMs: 0,
    uiConfirmPrewarmMs: 0,
    signerWorkerPrewarmMs: 0,
  };
}

type DeferredPromise<T> = {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(error: unknown): void;
};

function createDeferredPromise<T>(): DeferredPromise<T> {
  let resolve: (value: T) => void = () => undefined;
  let reject: (error: unknown) => void = () => undefined;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, resolve, reject };
}

async function waitForTestCondition(input: { label: string; predicate(): boolean }): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (input.predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error(`Timed out waiting for ${input.label}`);
}

function registrationEvents(captures: Record<string, unknown>): string[] | null {
  return Array.isArray(captures.registrationEvents)
    ? (captures.registrationEvents as string[])
    : null;
}

function registrationEventCount(events: readonly string[], event: string): number {
  let count = 0;
  for (const value of events) {
    if (value === event) count += 1;
  }
  return count;
}

function emailOtpRegistrationEnrollmentMaterial(args: {
  walletId: string;
  userId: string;
  ecdsaRootRequested?: boolean;
  ed25519YaoFactorRequested?: boolean;
}): Record<string, unknown> {
  const ecdsaRootRequested = args.ecdsaRootRequested !== false;
  const ed25519YaoFactorRequested = args.ed25519YaoFactorRequested === true;
  return {
    thresholdEcdsaClientVerifyingShareB64u: CLIENT_PUBLIC_KEY_B64U,

    recoveryKeys: [
      '0123456789ABCDEFGHJKMNPQRSTVWXYZ',
      '123456789ABCDEFGHJKMNPQRSTVWXYZ0',
      '23456789ABCDEFGHJKMNPQRSTVWXYZ01',
      '3456789ABCDEFGHJKMNPQRSTVWXYZ012',
      '456789ABCDEFGHJKMNPQRSTVWXYZ0123',
      '56789ABCDEFGHJKMNPQRSTVWXYZ01234',
      '6789ABCDEFGHJKMNPQRSTVWXYZ012345',
      '789ABCDEFGHJKMNPQRSTVWXYZ0123456',
      '89ABCDEFGHJKMNPQRSTVWXYZ01234567',
      '9ABCDEFGHJKMNPQRSTVWXYZ012345678',
    ],
    recoveryCodesIssuedAtMs: 1_700_000_000_000,
    otpChannel: 'email_otp',
    enrollmentId: `email-otp-enrollment-${args.walletId}`,
    enrollmentSealKeyVersion: 'email-otp-v1',
    clientUnlockPublicKeyB64u: 'email-otp-client-unlock-public-key',
    unlockKeyVersion: 'email-otp-unlock-v1',
    clientRootShareHandle: ecdsaRootRequested
      ? {
          kind: 'available',
          handles: [
            {
              kind: 'email_otp_worker_session_handle_v1',
              sessionId: `email-otp-client-root-${args.walletId}`,
              walletId: args.walletId,
              evmFamilySigningKeySlotId: plannedEcdsaWalletKeyId(args.walletId),
              authSubjectId: args.userId,
              action: 'wallet_registration_ecdsa_prepare',
              operation: 'registration',
              keyScope: 'evm-family',
              chainTarget: {
                kind: 'evm',
                namespace: 'eip155',
                chainId: 1,
                networkSlug: 'ethereum',
              },
            },
          ],
        }
      : { kind: 'not_requested' },
    ed25519YaoFactor: ed25519YaoFactorRequested
      ? {
          kind: 'issued',
          pendingFactorHandle: {
            kind: 'email_otp_ed25519_yao_pending_factor_handle_v1',
            handleId: `pending-factor-${args.walletId}`,
            purpose: 'registration',
            expiresAtMs: Date.now() + 60_000,
          },
        }
      : { kind: 'not_requested' },
    emailOtpEnrollment: {
      recoveryWrappedEnrollmentEscrows: [
        {
          enrollmentId: `email-otp-enrollment-${args.walletId}`,
        },
      ],
      enrollmentSealKeyVersion: 'email-otp-v1',
      clientUnlockPublicKeyB64u: 'email-otp-client-unlock-public-key',
      unlockKeyVersion: 'email-otp-unlock-v1',
      thresholdEcdsaClientVerifyingShareB64u: CLIENT_PUBLIC_KEY_B64U,
    },
  };
}

class EmailOtpEd25519YaoWorkerContextCapture {
  constructor(private readonly captures: Record<string, unknown>) {}

  async requestWorkerOperation(args: any): Promise<any> {
    const request = args.request as { type: string; payload: Record<string, any> };
    const operations = (this.captures.emailOtpYaoWorkerOperations ||= []) as string[];
    operations.push(request.type);
    switch (request.type) {
      case 'bindEmailOtpEd25519YaoRoot': {
        this.captures.emailOtpYaoRootScope = request.payload.scope;
        return {
          rootHandle: {
            kind: 'email_otp_ed25519_yao_root_handle_v1',
            handleId: 'email-otp-ed25519-root-1',
            purpose: 'registration',
            expiresAtMs: Date.now() + 60_000,
          },
        };
      }
      case 'startEmailOtpEd25519YaoRegistration': {
        this.captures.emailOtpYaoStart = request.payload;
        registrationEvents(this.captures)?.push('emailOtpYaoStartCalled');
        const deferred = this.captures.deferredEmailOtpYaoStart as
          | DeferredPromise<void>
          | undefined;
        if (deferred) {
          await deferred.promise;
          registrationEvents(this.captures)?.push('emailOtpYaoStartResolved');
        }
        if (this.captures.emailOtpYaoStartFailure === true) {
          throw new Error('Email OTP Yao start fixture failure');
        }
        const admission = request.payload.admissionRequest;
        return {
          pendingHandle: 'email-otp-ed25519-pending-1',
          operationalPublicKey: EMAIL_OTP_ED25519_PUBLIC_KEY,
          activationReference: {
            kind: 'router_ab_ed25519_yao_activation_reference_v1',
            lifecycle_id: admission.scope.lifecycle_id,
            session_id: new Array<number>(32).fill(7),
          },
        };
      }
      case 'commitEmailOtpEd25519YaoRegistration': {
        this.captures.emailOtpYaoCommit = request.payload;
        registrationEvents(this.captures)?.push('emailOtpYaoCommitCalled');
        const scope = this.captures.emailOtpYaoRootScope as Record<string, any>;
        return {
          activeClientHandle: 'email-otp-ed25519-active-1',
          metadata: {
            kind: 'router_ab_ed25519_yao_active_client_v1',
            scope: {
              lifecycle_id: 'registration-ceremony',
              root_share_epoch: RUNTIME_POLICY_SCOPE.signingRootVersion,
              account_id: scope.walletId,
              wallet_session_id: 'registration-ceremony',
              signer_set_id: registrationNearEd25519BranchKey(scope.signerSlot),
              signing_worker_id: 'signing-worker-test',
            },
            applicationBinding: {
              wallet_id: scope.walletId,
              near_ed25519_signing_key_id: scope.nearEd25519SigningKeyId,
              signing_root_id: scope.signingRootId,
              key_creation_signer_slot: scope.signerSlot,
            },
            participantIds: [scope.participantIds[0], scope.participantIds[1]],
            registeredPublicKey: EMAIL_OTP_ED25519_PUBLIC_KEY_BYTES,
            signingWorkerVerifyingShare: new Uint8Array(32),
            stateEpoch: 1n,
            transcript: new Uint8Array(32),
            activeCapabilityBinding: new Array<number>(32).fill(7),
          },
        };
      }
      case 'disposeEmailOtpEd25519YaoRegistration':
        this.captures.emailOtpYaoDisposed = request.payload;
        registrationEvents(this.captures)?.push('emailOtpYaoDisposed');
        return { removed: true };
      case 'disposeEmailOtpEd25519YaoActiveClient':
        return { removed: true };
      default:
        throw new Error(`unexpected Email OTP Yao worker operation: ${request.type}`);
    }
  }
}

class EmailOtpRecoveryCodeBackupCapture {
  private readonly repository = emailOtpRecoveryCodeBackupRepository as unknown as {
    write: (input: Record<string, unknown>) => Promise<Record<string, unknown>>;
    readMatching: (input: Record<string, unknown>) => Promise<Record<string, unknown> | null>;
  };
  private readonly originalWrite = this.repository.write;
  private readonly originalReadMatching = this.repository.readMatching;

  constructor(private readonly captures: Record<string, unknown>) {}

  install(): void {
    this.repository.write = this.write.bind(this);
    this.repository.readMatching = this.readMatching.bind(this);
  }

  restore(): void {
    this.repository.write = this.originalWrite;
    this.repository.readMatching = this.originalReadMatching;
  }

  private async write(input: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.captures.recoveryCodeBackupWrite = input;
    const record = {
      v: 1,
      secretKind: 'email_otp_recovery_codes_backup',
      storageScope: input.storageScope,
      status: 'stored',
      walletId: input.walletId,
      enrollmentId: input.enrollmentId,
      enrollmentSealKeyVersion: input.enrollmentSealKeyVersion,
      recoveryCodesIssuedAtMs: input.recoveryCodesIssuedAtMs,
      recoveryKeys: input.recoveryKeys,
      createdAtMs: 1_700_000_000_100,
      lastDisplayedAtMs: null,
      lastDownloadedAtMs: null,
    };
    this.captures.recoveryCodeBackupRecord = record;
    return record;
  }

  private async readMatching(): Promise<Record<string, unknown> | null> {
    return (this.captures.recoveryCodeBackupRecord as Record<string, unknown> | undefined) || null;
  }
}

function readEmailOtpYaoWorkerContext(
  context: EmailOtpEd25519YaoWorkerContextCapture,
): EmailOtpEd25519YaoWorkerContextCapture {
  return context;
}

async function captureEmailOtpEd25519Registration(
  captures: Record<string, unknown>,
  input: Record<string, unknown>,
): Promise<{ signerSlot: unknown }> {
  captures.storedEmailOtpEd25519Registration = input;
  return { signerSlot: input.signerSlot };
}

async function captureActivatedEmailOtpEd25519YaoCapability(
  captures: Record<string, unknown>,
  input: Record<string, unknown>,
): Promise<{ kind: string; identityKey: string }> {
  captures.activatedEmailOtpEd25519YaoCapability = input;
  return {
    kind: 'ed25519_yao_active_client_identity_v1',
    identityKey: 'email-otp-ed25519-active-identity-1',
  };
}

async function prepareEmailOtpEcdsaBootstrapFixture(
  captures: Record<string, unknown>,
  args: Record<string, unknown>,
) {
  registrationEvents(captures)?.push('ecdsaClientBootstrapStarted');
  captures.ecdsaClientBootstrapArgs = args;
  return {
    materialSource: 'email_otp_worker_handle' as const,
    clientBootstrap: {
      ...(args.prepare as Record<string, unknown>),
      derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
      clientShareRetryCounter: 0,
      contextBinding32B64u: CONTEXT_BINDING_32_B64U,
    },
    pendingStateBlob: {
      kind: 'ecdsa_role_local_pending_state_blob_v1' as const,
      curve: 'secp256k1' as const,
      encoding: 'base64url' as const,
      producer: 'signer_core' as const,
      stateBlobB64u: 'pending-state',
    },
    preparePublicFacts: {
      derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
      clientVerifyingShareB64u: CLIENT_PUBLIC_KEY_B64U,
    },
    retainedClientRootShareHandle: args.clientRootShareHandle,
  };
}

function createContext(captures: Record<string, unknown>): any {
  const prepareWalletRegistrationEcdsaPreparedClientBootstrap = async (
    args: Record<string, unknown>,
  ) => {
    registrationEvents(captures)?.push('ecdsaClientBootstrapStarted');
    captures.ecdsaClientBootstrapArgs = args;
    const clientBootstrap = {
      ...(args.prepare as Record<string, unknown>),
      derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
      clientShareRetryCounter: 0,
      contextBinding32B64u: CONTEXT_BINDING_32_B64U,
    };
    return {
      materialSource: 'passkey_prf_first',
      clientBootstrap,
      pendingStateBlob: {
        kind: 'ecdsa_role_local_pending_state_blob_v1',
        curve: 'secp256k1',
        encoding: 'base64url',
        producer: 'signer_core',
        stateBlobB64u: 'pending-state',
      },
      preparePublicFacts: {
        derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
        clientVerifyingShareB64u: CLIENT_PUBLIC_KEY_B64U,
      },
      passkeyPrfFirstB64u: String(args.passkeyPrfFirstB64u || ''),
      credentialIdB64u: String(args.credentialIdB64u || ''),
    };
  };
  const prepareEmailOtpRegistrationEnrollmentMaterialInternal = async (
    args: Record<string, unknown>,
  ) => {
    registrationEvents(captures)?.push('emailOtpEnrollmentMaterialStarted');
    captures.emailOtpEnrollmentMaterialArgs = args;
    const deferred = captures.deferredEmailOtpEnrollmentMaterial as
      | DeferredPromise<Record<string, unknown>>
      | undefined;
    const material = deferred
      ? await deferred.promise
      : emailOtpRegistrationEnrollmentMaterial({
          walletId: String(args.walletId),
          userId: String(args.userId),
          ecdsaRootRequested: args.kind === 'ecdsa_root_requested',
          ed25519YaoFactorRequested:
            (args.ed25519YaoFactor as { kind?: unknown } | undefined)?.kind ===
            'ed25519_yao_factor_requested',
        });
    registrationEvents(captures)?.push('emailOtpEnrollmentMaterialResolved');
    return material;
  };
  const thresholdEcdsaSessionStore = { recordsByLane: new Map() };
  const emailOtpYaoWorkerContext = new EmailOtpEd25519YaoWorkerContextCapture(captures);
  const ecdsaRegistrationBootstrap = {
    preparePasskeyClientBootstrap: prepareWalletRegistrationEcdsaPreparedClientBootstrap,
    finalizeClientBootstrap: async () => ({
      stateBlob: {
        kind: 'ecdsa_role_local_state_blob_v1' as const,
        curve: 'secp256k1' as const,
        encoding: 'base64url' as const,
        producer: 'signer_core' as const,
        stateBlobB64u: 'ready-state',
      },
      publicFacts: {
        contextBinding32B64u: CONTEXT_BINDING_32_B64U,
        derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
        clientVerifyingShareB64u: CLIENT_PUBLIC_KEY_B64U,
        relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
        groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
        ethereumAddress: '0x3333333333333333333333333333333333333333' as `0x${string}`,
      },
    }),
    storeClientSigningMaterial: async () => ({
      handle: {
        kind: 'ecdsa_role_local_worker_handle_v1' as const,
        materialHandle: parseEcdsaRoleLocalMaterialHandle('registration-ecdsa-role-local-material'),
        bindingDigest: parseEcdsaRoleLocalBindingDigest('registration-ecdsa-role-local-binding'),
      },
    }),
  };
  const hydrateSigningSession = async (input: Record<string, unknown>) => {
    captures.hydratedSession = input;
  };
  const finalizeWalletRegistrationEcdsaSessionsForTest = async (input: Record<string, unknown>) => {
    await finalizeWalletRegistrationEcdsaSessionsOperation(
      {
        registrationBootstrap: ecdsaRegistrationBootstrap,
        bootstrapStore: {
          upsertProfile: async () => undefined,
          activateAccountSigner: async (activationInput: any) => ({
            signer: activationInput.signer,
            signerSlot: 1,
          }),
        },
        sessionStore: thresholdEcdsaSessionStore,
        persistEcdsaRoleLocalReadyRecord: async (input: Record<string, unknown>) => {
          captures.persistedEcdsaRoleLocalReadyRecord = input;
          return { ok: true, value: { kind: 'persisted' as const } };
        },
        warmSessions: { hydrateSigningSession },
        commitEmailOtpEcdsaSession: async (input: Record<string, unknown>) => {
          captures.committedEmailOtpEcdsaSession = input;
          return undefined;
        },
        commitEmailOtpEcdsaRegistrationWarmMaterial: async (input) => {
          captures.committedEmailOtpEcdsaRegistrationWarmMaterial = input;
        },
        persistActivePasskeyEcdsaReauthAnchor: async (input: unknown) => {
          captures.persistedActivePasskeyEcdsaReauthAnchor = input;
        },
      persistEmailOtpEcdsaRegistrationReauthAnchor: async (input: unknown) => {
          captures.persistedEmailOtpEcdsaRegistrationReauthAnchor = input;
        },
        signingSessionSeal: {},
      },
      input as any,
    );
    captures.persistedEcdsaSessions = input;
  };
  return {
    configs: {
      network: {
        chains: [
          {
            network: 'tempo-testnet',
            rpcUrl: 'https://tempo.example.test',
            explorerUrl: 'https://tempo.explorer.test',
            chainId: 42431,
          },
          {
            network: 'arc-testnet',
            rpcUrl: 'https://arc.example.test',
            explorerUrl: 'https://arc.explorer.test',
            chainId: 5042002,
          },
        ],
        relayer: {
          url: RELAYER_URL,
        },
      },
      registration: {
        mode: 'managed',
        projectEnvironmentId: 'project_matrix:dev',
        publishableKey: 'pk_matrix',
      },
      signing: {
        emailOtp: {
          authPolicy: 'session',
        },
        routerAb: {
          normalSigning: { mode: 'enabled', signingWorkerId: 'signing-worker-test' },
        },
        sessionDefaults: {
          ttlMs: 600_000,
          remainingUses: 1,
        },
        thresholdEcdsa: {
          provisioningDefaults: {
            tempo: {
              enabled: true,
              signingSession: { kind: 'jwt', ttlMs: 600_000, remainingUses: 1 },
            },
            evm: {
              enabled: true,
              signingSession: { kind: 'jwt', ttlMs: 600_000, remainingUses: 1 },
            },
          },
        },
      },
      webauthn: {
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      },
    },
    signingRuntime: {
      services: {
        ecdsaRegistrationBootstrap,
        ecdsaWalletRecords: {
          storeWalletEcdsaSignerRecords: async (input: Record<string, unknown>) => {
            captures.storedEcdsa = input;
            return { storedSigners: [] };
          },
          storeWalletEmailOtpEcdsaSignerRecords: async (input: Record<string, unknown>) => {
            captures.storedEcdsa = input;
            return { storedSigners: [] };
          },
          finalizeWalletEcdsaRegistration: async (input: Record<string, unknown>) => {
            captures.storedEcdsaRegistration = input;
            return { storedSigners: [] };
          },
          storeWalletEmailOtpEcdsaRegistrationData: async (input: Record<string, unknown>) => {
            captures.storedEcdsaRegistration = input;
            return { storedSigners: [] };
          },
        },
        ecdsaRegistrationSessions: {
          finalizeWalletRegistrationEcdsaSessions: finalizeWalletRegistrationEcdsaSessionsForTest,
        },
        warmSessions: {
          hydrateSigningSession,
        },
        registrationAccounts: {
          getUserBySignerSlot: async (nearAccountId: unknown, signerSlot: unknown) => ({
            nearAccountId,
            signerSlot,
          }),
          activateAuthenticatedWalletState: async () => undefined,
          rollbackUserRegistration: async () => undefined,
        },
      },
    },
    signingEngine: {
      getRpId: () => RP_ID,
      getSignerWorkerContext: readEmailOtpYaoWorkerContext.bind(
        undefined,
        emailOtpYaoWorkerContext,
      ),
      warmCriticalResources: emptyWorkerWarmupDiagnostics,
      openRegistrationPreparationModal: () => undefined,
      prewarmEmailOtpYao: async () => {
        incrementCaptureCounter(captures, 'emailOtpYaoPrewarmCalls');
        if (captures.emailOtpYaoPrewarmFailure === true) {
          return {
            kind: 'failed' as const,
            elapsedMs: 7,
            workerPrewarmMs: 3,
            yaoWasmInitMs: 4,
            failureStage: 'yao_wasm_init' as const,
          };
        }
        return {
          kind: 'succeeded' as const,
          elapsedMs: 0,
          workerPrewarmMs: 0,
          yaoWasmInitMs: 0,
        };
      },
      requestRegistrationCredentialConfirmation: async (args: Record<string, unknown>) => {
        incrementCaptureCounter(captures, 'registrationCredentialPrompts');
        captures.registrationCredentialArgs = args;
        return {
          credential: registrationCredentialWithPrf(),
        };
      },
      getAuthenticationCredentialsSerialized: async (args: Record<string, unknown>) => {
        incrementCaptureCounter(captures, 'authenticationCredentialPrompts');
        captures.authenticationArgs = args;
        return credentialWithPrf();
      },

      preparePasskeyEcdsaBootstrap: prepareWalletRegistrationEcdsaPreparedClientBootstrap,
      prepareEmailOtpEcdsaBootstrap: prepareEmailOtpEcdsaBootstrapFixture.bind(undefined, captures),
      prepareEmailOtpRegistrationEnrollmentMaterialInternal,
      rememberEmailOtpAppSessionBinding: (input: Record<string, unknown>) => {
        captures.rememberedEmailOtpAppSession = input;
      },
      finalizeWalletRegistrationEcdsaSessions: finalizeWalletRegistrationEcdsaSessionsForTest,
      finalizeWalletEcdsaRegistration: async (input: Record<string, unknown>) => {
        captures.storedEcdsaRegistration = input;
        return { storedSigners: [] };
      },
      storeWalletEmailOtpEcdsaRegistrationData: async (input: Record<string, unknown>) => {
        captures.storedEcdsaRegistration = input;
        return { storedSigners: [] };
      },
      storeWalletEmailOtpMixedRegistrationData: async (input: Record<string, unknown>) => {
        captures.storedEmailOtpMixedRegistration = input;
        return {
          signerSlot: 1,
          storedSigners: [{}],
        };
      },
      storeWalletEmailOtpEd25519RegistrationData: captureEmailOtpEd25519Registration.bind(
        undefined,
        captures,
      ),
      persistEmailOtpEd25519YaoSessionForRefreshInternal: async (input: unknown) => {
        captures.persistedEmailOtpEd25519YaoSessionForRefresh = input;
      },
      storeWalletEcdsaSignerRecords: async (input: Record<string, unknown>) => {
        captures.storedEcdsa = input;
        return { storedSigners: [] };
      },
      storeWalletEmailOtpEcdsaSignerRecords: async (input: Record<string, unknown>) => {
        captures.storedEcdsa = input;
        return { storedSigners: [] };
      },

      hydrateSigningSession,
      persistSigningSessionSealForThresholdSession: async (input: Record<string, unknown>) => {
        captures.persistedSigningSessionSeal = input;
        return {
          ok: true,
          sealedSecretB64u: 'sealed-registration-session',
          keyVersion: 'test-signing-session-seal-key',
          remainingUses: 1,
          expiresAtMs: Date.now() + 60_000,
        };
      },
      getUserBySignerSlot: async (nearAccountId: unknown, signerSlot: unknown) => ({
        nearAccountId,
        signerSlot,
      }),
      activateAuthenticatedWalletState: async () => undefined,
      activateVerifiedNearEd25519YaoSigningCapability:
        captureActivatedEmailOtpEd25519YaoCapability.bind(undefined, captures),
      createRouterAbEcdsaRegistrationCeremony: async (args: Record<string, any>) => {
        captures.ecdsaRegistrationFacts = args.registration;
        registrationEvents(captures)?.push('ecdsaCeremonyStarted');
        const deferred = captures.deferredEcdsaCeremony as DeferredPromise<void> | undefined;
        if (deferred) {
          await deferred.promise;
          registrationEvents(captures)?.push('ecdsaCeremonyResolved');
        }
        if (captures.ecdsaCeremonyFailure === true) {
          throw new Error('parallel ECDSA ceremony fixture failure');
        }
        return {
          kind: 'router_ab_ecdsa_registration_ceremony_created_v1',
          ceremonyId: args.ceremonyId,
          registrationRequest: mockedEcdsaRegistrationRequest(args.registration),
        };
      },
      verifyRouterAbEcdsaRegistrationClientProofs: async (args: Record<string, any>) => ({
        kind: 'router_ab_ecdsa_registration_client_proofs_verified_v1',
        ceremonyId: args.ceremonyId,
        clientBootstrap: {
          derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
          clientShareRetryCounter: 0,
          contextBinding32B64u: CONTEXT_BINDING_32_B64U,
        },
        publicFacts: {
          registrationRequestDigestB64u: CONTEXT_BINDING_32_B64U,
          proofTranscriptDigestB64u: CONTEXT_BINDING_32_B64U,
          contextBinding32B64u: CONTEXT_BINDING_32_B64U,
          derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
          clientShareRetryCounter: 0,
          participantId: 1,
        },
      }),
      finalizeRouterAbEcdsaRegistrationActivation: async (args: Record<string, any>) => {
        const ecdsaFacts = captures.ecdsaRegistrationFacts as Record<string, any>;
        const publicCapability = parseRouterAbEcdsaDerivationPublicCapabilityV1(
          mockedEcdsaPublicCapability(ecdsaFacts),
        );
        return {
          kind: 'router_ab_ecdsa_registration_activation_finalized_v1',
          ceremonyId: args.ceremonyId,
          roleLocalMaterial: {
            kind: 'ecdsa_role_local_worker_handle_v1',
            materialHandle: parseEcdsaRoleLocalMaterialHandle(
              'registration-ecdsa-role-local-material',
            ),
            bindingDigest: parseEcdsaRoleLocalBindingDigest(CONTEXT_BINDING_32_B64U),
            durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef(
              'registration-ecdsa-role-local-material',
            ),
          },
          publicFacts: {
            contextBinding32B64u: CONTEXT_BINDING_32_B64U,
            derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
            relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
            groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
            ethereumAddress: '0x3333333333333333333333333333333333333333',
          },
          publicCapability,
        };
      },
      closeRouterAbEcdsaRegistrationCeremony: async () => undefined,
      closeRegistrationPreparationModal: () => undefined,
    },
    nearClient: {
      viewAccount: async () => {
        throw new Error('does not exist');
      },
    },
  };
}

function installRegisterWalletFetch(captures: Record<string, unknown>) {
  const originalFetch = globalThis.fetch;
  const paths: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const path = url.pathname;
    paths.push(path);
    registrationEvents(captures)?.push(`fetch:${path}`);
    const body = init?.body ? JSON.parse(String(init.body)) : {};
    if (path === '/router-ab/keyset') {
      return jsonResponse({
        keyset_version: 'router_ab_keyset_v2',
        signer_envelope_hpke: {
          current: {
            deriver_a: {
              role: 'signer_a',
              key_epoch: 'epoch-a',
              public_key: 'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            },
            deriver_b: {
              role: 'signer_b',
              key_epoch: 'epoch-b',
              public_key: 'x25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            },
          },
        },
        signer_peer_verifying_keys: {
          deriver_a: {
            role: 'signer_a',
            verifying_key_hex: '1111111111111111111111111111111111111111111111111111111111111111',
          },
          deriver_b: {
            role: 'signer_b',
            verifying_key_hex: '2222222222222222222222222222222222222222222222222222222222222222',
          },
        },
        signing_worker_server_output_hpke: {
          key_epoch: 'epoch-signing-worker',
          public_key: 'x25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        },
      });
    }
    if (path === '/v1/registration/bootstrap-grants') {
      captures.bootstrapGrantBody = body;
      return jsonResponse({
        ok: true,
        grant: {
          token: 'bootstrap-grant',
          orgId: RUNTIME_POLICY_SCOPE.orgId,
          projectId: RUNTIME_POLICY_SCOPE.projectId,
          envId: RUNTIME_POLICY_SCOPE.envId,
          signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        },
      });
    }
    if (path === '/wallets/register/intent') {
      captures.intentRequestBody = body;
      const selection = mockedRegistrationIntentSignerSelection(body.signerSelection);
      const walletId = mockedRegistrationWalletId(body);
      const intent = {
        version: 'registration_intent_v1' as const,
        walletId,
        authMethod: body.authMethod,
        signerSelection: selection,
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
        nonceB64u: 'registration-nonce',
      };
      const digest = await computeRegistrationIntentDigestB64u(intent);
      captures.intent = intent;
      captures.digest = digest;
      return jsonResponse({
        ok: true,
        intent,
        registrationIntentDigestB64u: digest,
        registrationIntentGrant: 'registration-grant',
        expiresAtMs: Date.now() + 60_000,
      });
    }
    if (path === '/wallets/register/start') {
      captures.startBody = body;
      const ecdsaSigner = mockedRegistrationEvmFamilyEcdsaSigner(body.intent.signerSelection);
      const ed25519Signer = mockedRegistrationNearEd25519Signer(body.intent.signerSelection);
      if (ed25519Signer) {
        const nearEd25519SigningKeyId = String(body.intent.walletId);
        captures.nearEd25519SigningKeyId = nearEd25519SigningKeyId;
        return jsonResponse({
          ok: true,
          registrationCeremonyId: 'registration-ceremony',
          intent: body.intent,
          kind: ecdsaSigner ? 'near_ed25519_and_evm_family_ecdsa' : 'near_ed25519',
          ed25519: {
            admissionRequest: {
              scope: {
                lifecycle_id: 'registration-ceremony',
                root_share_epoch: RUNTIME_POLICY_SCOPE.signingRootVersion,
                account_id: String(body.intent.walletId),
                wallet_session_id: 'registration-ceremony',
                signer_set_id: registrationNearEd25519BranchKey(ed25519Signer.signerSlot),
                signing_worker_id: 'signing-worker-test',
              },
              application_binding: {
                wallet_id: String(body.intent.walletId),
                near_ed25519_signing_key_id: nearEd25519SigningKeyId,
                signing_root_id: 'project_matrix:dev',
                key_creation_signer_slot: ed25519Signer.signerSlot,
              },
              participant_ids: ed25519Signer.participantIds,
            },
          },
          ...(ecdsaSigner
            ? {
          ecdsa: await mockedRegistrationEcdsaStart(body, ecdsaSigner).then((ecdsa) => {
            captures.ecdsaPrepare = ecdsa.prepare;
            return ecdsa;
                }),
              }
            : {}),
        });
      }
      return jsonResponse({
        ok: true,
        registrationCeremonyId: 'registration-ceremony',
        intent: body.intent,
        kind: 'evm_family_ecdsa',

        ...(ecdsaSigner
          ? {
              ecdsa: await mockedRegistrationEcdsaStart(body, ecdsaSigner).then((ecdsa) => {
                captures.ecdsaPrepare = ecdsa.prepare;
                return ecdsa;
              }),
            }
          : {}),
      });
    }
    if (path === '/wallets/register/derivation/respond') {
      captures.respondBody = body;
      if (body.ecdsa?.strictRegistration) {
        return jsonResponse({
          ok: true,
          registrationCeremonyId: body.registrationCeremonyId,
          ecdsa: {
            kind: 'router_ab_ecdsa_registration_forwarded_v1',
            strictResult: {
              result: 'forwarded',
              response: {
                replay: { request_id: 'request-ecdsa', reserved: true },
                lifecycle: { lifecycle_id: 'wallet_registration', stored: true },
                bundles: {
                  signerA: {
                    kind: 'recipient_proof_bundle',
                    transcriptDigestB64u: CONTEXT_BINDING_32_B64U,
                    payloadB64u: 'proof-a',
                  },
                  signerB: {
                    kind: 'recipient_proof_bundle',
                    transcriptDigestB64u: CONTEXT_BINDING_32_B64U,
                    payloadB64u: 'proof-b',
                  },
                },
              },
            },
          },
        });
      }
      const deferred = captures.deferredEcdsaRespond as DeferredPromise<void> | undefined;
      if (deferred) {
        registrationEvents(captures)?.push('ecdsaRespondCalled');
        await deferred.promise;
        registrationEvents(captures)?.push('ecdsaRespondResolved');
      }
      const registrationEcdsaExpiresAtMs = Date.now() + 60_000;
      const patchRegistrationBootstrap = captures.patchRegistrationBootstrap as
        | ((bootstrap: Record<string, unknown>) => Record<string, unknown>)
        | undefined;
      // Current protocol shape: the request carries clientBootstraps[] (one per
      // chain target) and the response returns bootstraps[] matched by chainTarget.
      const ecdsaBootstraps = Array.isArray(body.ecdsa?.clientBootstraps)
        ? (
            body.ecdsa.clientBootstraps as {
              chainTarget: unknown;
              clientBootstrap: Record<string, unknown>;
            }[]
          ).map((entry) => {
            let bootstrap = {
              ...entry.clientBootstrap,
              publicIdentity: {
                derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
                relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
                groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
                ethereumAddress: '0x3333333333333333333333333333333333333333',
              },
              publicTranscriptDigest32B64u: 'transcript-digest',
              keyHandle: 'ederivation-registration-key',
              relayerShareRetryCounter: 1,
              thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
              ethereumAddress: '0x3333333333333333333333333333333333333333',
              relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
              thresholdSessionId: String(entry.clientBootstrap.thresholdSessionId || ''),
              expiresAtMs: registrationEcdsaExpiresAtMs,
              expiresAt: new Date(registrationEcdsaExpiresAtMs).toISOString(),
            } as Record<string, unknown>;
            const sessionJwt = ecdsaWalletSessionJwtForBootstrap(bootstrap);
            if (patchRegistrationBootstrap) {
              bootstrap = patchRegistrationBootstrap(bootstrap);
            }
            bootstrap.jwt = sessionJwt;
            return { chainTarget: entry.chainTarget, bootstrap };
          })
        : null;
      return jsonResponse({
        ok: true,
        registrationCeremonyId: body.registrationCeremonyId,

        ...(ecdsaBootstraps
          ? {
              ecdsa: {
                bootstraps: ecdsaBootstraps,
              },
            }
          : {}),
      });
    }
    if (path === '/wallets/register/derivation/activate') {
      const ecdsaFacts = captures.ecdsaRegistrationFacts as Record<string, any>;
      const prepare = captures.ecdsaPrepare as Record<string, any>;
      let bootstrap = mockedEcdsaServerBootstrap(ecdsaFacts, prepare);
      captures.sharedRegistrationExpiresAtMs = bootstrap.expiresAtMs;
      const sessionJwt = ecdsaWalletSessionJwtForBootstrap(bootstrap);
      const patchRegistrationBootstrap = captures.patchRegistrationBootstrap as
        | ((value: Record<string, unknown>) => Record<string, unknown>)
        | undefined;
      if (patchRegistrationBootstrap) {
        bootstrap = patchRegistrationBootstrap(bootstrap);
      }
      bootstrap.jwt = sessionJwt;
      return jsonResponse({
        ok: true,
        registrationCeremonyId: body.registrationCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_activated_v1',
          activation: mockedEcdsaActivationReceipt(ecdsaFacts),
          bootstrap,
        },
      });
    }
    if (path === '/wallets/register/finalize') {
      captures.finalizeBody = body;
      const responseWalletId = String((captures.intent as any)?.walletId || WALLET_SUBJECT_ID);
      const intentAuthMethod = (captures.intent as any)?.authMethod;
      if (body.ed25519) {
        const ed25519Signer = mockedRegistrationNearEd25519Signer(
          (captures.intent as any)?.signerSelection,
        );
        if (!ed25519Signer) {
          return jsonResponse({ ok: false, message: 'missing Ed25519 signer fixture' }, 400);
        }
        const nearEd25519SigningKeyId = String(captures.nearEd25519SigningKeyId || '');
        const providerSubject = EMAIL_OTP_PROVIDER_SUBJECT;
        const authorityScope = {
          kind: 'email_otp',
          provider: 'google',
          providerUserId: providerSubject,
        };
        const emailHashHex = await sha256HexUtf8('alice@example.com');
        const publicKey = String(
          captures.emailOtpEd25519FinalizePublicKey || EMAIL_OTP_ED25519_PUBLIC_KEY,
        );
        const responseBody: Record<string, unknown> = {
          ok: true,
          walletId: responseWalletId,
          kind: body.ecdsa ? 'near_ed25519_and_evm_family_ecdsa' : 'near_ed25519',
          authority: buildEmailOtpWalletAuthAuthority({
            walletId: responseWalletId,
            provider: 'google',
            providerUserId: providerSubject,
            emailHashHex,
          }),
          authMethod: {
            kind: 'email_otp',
            registrationAuthorityId: 'registration-attempt-1',
          },
          appSessionJwt: String(intentAuthMethod?.appSessionJwt || ''),
          authorityScope,
          accountProvisioning: {
            kind: 'implicit_account',
            accountIdSource: 'ed25519_public_key',
          },
          resolvedAccount: {
            kind: 'implicit_account',
            nearAccountId: 'ab'.repeat(32),
            nearEd25519SigningKeyId,
          },
          ed25519: {
            signerSlot: ed25519Signer.signerSlot,
            nearAccountId: 'ab'.repeat(32),
            nearEd25519SigningKeyId,
            publicKey,
            relayerKeyId: 'signing-worker-test',
            keyVersion: 'router-ab-ed25519-yao-v1',
            recoveryExportCapable: true,
            participantIds: ed25519Signer.participantIds,
            session: {
              sessionKind: 'jwt',
              walletSessionJwt: ed25519WalletSessionJwt({
                walletId: responseWalletId,
                nearAccountId: 'ab'.repeat(32),
                nearEd25519SigningKeyId,
                thresholdSessionId: 'registration-ceremony',
                signingGrantId: 'email-otp-ed25519-signing-grant',
              }),
              walletId: responseWalletId,
              nearAccountId: 'ab'.repeat(32),
              nearEd25519SigningKeyId,
              authorityScope,
              thresholdSessionId: 'registration-ceremony',
              signingGrantId: 'email-otp-ed25519-signing-grant',
              expiresAtMs: Number(
                captures.sharedRegistrationExpiresAtMs || Date.now() + 60_000,
              ),
              participantIds: ed25519Signer.participantIds,
              remainingUses: 3,
              signingRootId: 'project_matrix:dev',
              signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
              runtimePolicyScope: RUNTIME_POLICY_SCOPE,
              routerAbNormalSigning: {
                kind: 'router_ab_ed25519_normal_signing_v1',
                signingWorkerId: 'signing-worker-test',
              },
            },
          },
        };
        if (body.ecdsa) {
          attachMockedEcdsaFinalizeWalletKeys(captures, responseWalletId, responseBody);
        }
        return jsonResponse(responseBody);
      }
      const responseBody = await mockedEcdsaFinalizeResponse(captures, responseWalletId);
      if (body.ecdsa) {
        attachMockedEcdsaFinalizeWalletKeys(captures, responseWalletId, responseBody);
      }
      return jsonResponse(responseBody);
    }
    return jsonResponse({ ok: false, message: `unexpected path ${path}` }, 404);
  }) as typeof fetch;
  return {
    paths,
    restore: () => {
      globalThis.fetch = originalFetch;
    },
  };
}

async function withMockedIndexedDb<T>(run: () => Promise<T>): Promise<T> {
  clearAllThresholdEcdsaSessionRecords({ recordsByLane: new Map() });
  clearAllStoredThresholdEd25519SessionRecords();
  const indexedDB = IndexedDBManager as unknown as Record<string, unknown>;
  const originalListProfileAuthenticators = indexedDB.listProfileAuthenticators;
  const originalResolveProfileAccountContext = indexedDB.resolveProfileAccountContext;
  const originalGetKeyMaterial = IndexedDBManager.getKeyMaterial;
  const originalStoreKeyMaterial = IndexedDBManager.storeKeyMaterial;
  const keyMaterialWrites: unknown[] = [];
  indexedDB.listProfileAuthenticators = async () => [
    {
      credentialId: 'credential-id',
      transports: ['internal'],
    },
  ];
  indexedDB.resolveProfileAccountContext = async (accountRef: unknown) => ({
    profileId: 'near-profile:later.testnet',
    accountRef,
  });
  (IndexedDBManager as any).getKeyMaterial = async () => null;
  (IndexedDBManager as any).storeKeyMaterial = async (record: unknown) => {
    keyMaterialWrites.push(record);
  };
  try {
    return await run();
  } finally {
    indexedDB.listProfileAuthenticators = originalListProfileAuthenticators;
    indexedDB.resolveProfileAccountContext = originalResolveProfileAccountContext;
    (IndexedDBManager as any).getKeyMaterial = originalGetKeyMaterial;
    (IndexedDBManager as any).storeKeyMaterial = originalStoreKeyMaterial;
    clearAllThresholdEcdsaSessionRecords({ recordsByLane: new Map() });
    clearAllStoredThresholdEd25519SessionRecords();
  }
}
test('evm.registerEvmWallet wraps ECDSA-only wallet registration', async () => {
  const captures: Record<string, unknown> = {};
  const fetchMock = installRegisterWalletFetch(captures);
  try {
    const signer = createLocalEvmCapability({
      getContext: () => createContext(captures),
    });
    const result = await withMockedIndexedDb(() =>
      signer.registerEvmWallet({
        chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1, networkSlug: 'ethereum' }],
        participantIds: [1, 2],
        options: {},
      }),
    );

    expectRegistrationSuccess(result);
    expect(result).toMatchObject({
      success: true,
      thresholdEcdsaEthereumAddress: '0x3333333333333333333333333333333333333333',
    });
    expect((captures.intentRequestBody as any)?.signerSelection).toEqual({
      kind: 'signer_set',
      signers: [
        {
          kind: 'evm_family_ecdsa',
          chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1, networkSlug: 'ethereum' }],
          participantIds: [1, 2],
        },
      ],
    });
    expect((captures.intent as any)?.signerSelection).toEqual(
      (captures.intentRequestBody as any)?.signerSelection,
    );
    expectSingleRegistrationTouchIdPrompt(captures);
    expect(captures.bootstrapGrantBody).toMatchObject({
      authority: {
        kind: 'passkey_rp',
        rpId: RP_ID,
      },
    });
  } finally {
    fetchMock.restore();
  }
});

test('registerWallet orchestrates ECDSA-only wallet registration without NEAR profile work', async () => {
  const captures: Record<string, unknown> = {};
  const fetchMock = installRegisterWalletFetch(captures);
  try {
    const result = await withMockedIndexedDb(() =>
      registerWallet({
        context: createContext(captures),
        authMethod: { kind: 'passkey', rpId: RP_ID },
        wallet: { kind: 'server_allocated' },
        signerSelection: registrationSignerSet(
          evmFamilyRegistrationSigner([{ kind: 'evm', namespace: 'eip155', chainId: 1 }]),
        ),
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      }),
    );

    expectRegistrationSuccess(result);
    expect(result).toMatchObject({
      success: true,
      thresholdEcdsaEthereumAddress: '0x3333333333333333333333333333333333333333',
    });
    expect(fetchMock.paths).toEqual([
      '/v1/registration/bootstrap-grants',
      '/wallets/register/intent',
      '/wallets/register/start',
      '/wallets/register/derivation/respond',
      '/wallets/register/derivation/activate',
      '/wallets/register/finalize',
    ]);
    expect(captures.bootstrapGrantBody).not.toHaveProperty('newAccountId');
    expect(captures.registrationCredentialArgs).toMatchObject({
      walletId: WALLET_SUBJECT_ID,
      challengeB64u: captures.digest,
    });
    expectSingleRegistrationTouchIdPrompt(captures);
    expect(captures.finalizeBody).toMatchObject({
      ecdsa: {
        expectedKeyHandles: ['ederivation-registration-key'],
      },
    });
    expect(captures.persistedEcdsaSessions).toMatchObject({
      auth: { kind: 'passkey', credentialIdB64u: 'registration-credential-id' },
    });
    expect(captures.emailOtpYaoPrewarmCalls || 0).toBe(0);
  } finally {
    fetchMock.restore();
  }
});

test('registerWallet overlaps Email OTP enrollment material with ECDSA-only registration start', async () => {
  const events: string[] = [];
  const deferredEmailOtpEnrollmentMaterial = createDeferredPromise<Record<string, unknown>>();
  const captures: Record<string, unknown> = {
    registrationEvents: events,
    deferredEmailOtpEnrollmentMaterial,
    enableRegistrationPreparationModalClose: true,
  };
  const fetchMock = installRegisterWalletFetch(captures);
  const backupRepository = emailOtpRecoveryCodeBackupRepository as unknown as {
    write: (input: Record<string, unknown>) => Promise<Record<string, unknown>>;
    readMatching: (input: Record<string, unknown>) => Promise<Record<string, unknown> | null>;
  };
  const originalBackupWrite = backupRepository.write;
  const originalBackupReadMatching = backupRepository.readMatching;
  const walletId = walletIdFromString('email-otp-ecdsa.testnet');
  const appSessionJwt = jwtWithPayload({
    kind: 'app_session_v1',
    sub: EMAIL_OTP_PROVIDER_SUBJECT,
    walletId: String(walletId),
    providerSubject: 'google:registration-subject',
    appSessionVersion: 'app-session-v1',
    exp: Math.floor(Date.now() / 1000) + 3_600,
  });
  try {
    backupRepository.write = async (input) => {
      captures.recoveryCodeBackupWrite = input;
      const record = {
        v: 1,
        secretKind: 'email_otp_recovery_codes_backup',
        storageScope: input.storageScope,
        status: 'stored',
        walletId: input.walletId,
        enrollmentId: input.enrollmentId,
        enrollmentSealKeyVersion: input.enrollmentSealKeyVersion,
        recoveryCodesIssuedAtMs: input.recoveryCodesIssuedAtMs,
        recoveryKeys: input.recoveryKeys,
        createdAtMs: 1_700_000_000_100,
        lastDisplayedAtMs: null,
        lastDownloadedAtMs: null,
      };
      captures.recoveryCodeBackupRecord = record;
      return record;
    };
    backupRepository.readMatching = async () =>
      (captures.recoveryCodeBackupRecord as Record<string, unknown> | undefined) || null;
    const registration = withMockedIndexedDb(() =>
      registerWallet({
        context: createContext(captures),
        authMethod: {
          kind: 'email_otp',
          proofKind: 'google_sso_registration',
          email: 'ALICE@EXAMPLE.COM',
          appSessionJwt,
          googleEmailOtpRegistrationAttemptId: 'registration-attempt-1',
          googleEmailOtpRegistrationOfferId: 'registration-offer-1',
          googleEmailOtpRegistrationCandidateId: 'registration-candidate-1',
        },
        wallet: { kind: 'provided', walletId },
        signerSelection: registrationSignerSet(
          evmFamilyRegistrationSigner([{ kind: 'evm', namespace: 'eip155', chainId: 1 }]),
        ),
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      }),
    );

    await waitForTestCondition({
      label: 'ECDSA registration ceremony overlaps Email OTP enrollment material',
      predicate: () => fetchMock.paths.includes('/wallets/register/derivation/respond'),
    });

    expect(events).toContain('emailOtpEnrollmentMaterialStarted');
    expect(fetchMock.paths).toContain('/wallets/register/start');
    expect(fetchMock.paths).not.toContain('/wallets/register/finalize');
    expect(captures.ecdsaClientBootstrapArgs).toBeUndefined();

    deferredEmailOtpEnrollmentMaterial.resolve(
      emailOtpRegistrationEnrollmentMaterial({
        walletId: String(walletId),
        userId: 'google:registration-subject',
        ecdsaRootRequested: false,
      }),
    );
    const result = await registration;

    expectRegistrationSuccess(result);
    expect(captures.emailOtpYaoPrewarmCalls || 0).toBe(0);
    expect(events).toEqual(
      expect.arrayContaining([
        'emailOtpEnrollmentMaterialStarted',
        'fetch:/wallets/register/start',
        'fetch:/wallets/register/derivation/respond',
        'fetch:/wallets/register/derivation/activate',
        'emailOtpEnrollmentMaterialResolved',
        'fetch:/wallets/register/finalize',
      ]),
    );
    expect(events.indexOf('fetch:/wallets/register/start')).toBeLessThan(
      events.indexOf('emailOtpEnrollmentMaterialResolved'),
    );
    expect(events.indexOf('fetch:/wallets/register/derivation/respond')).toBeLessThan(
      events.indexOf('emailOtpEnrollmentMaterialResolved'),
    );
    expect(events.indexOf('emailOtpEnrollmentMaterialResolved')).toBeLessThan(
      events.indexOf('fetch:/wallets/register/finalize'),
    );
    expect(captures.emailOtpEnrollmentMaterialArgs).toMatchObject({
      walletId: String(walletId),
      userId: 'google:registration-subject',
      appSessionJwt,
    });
    expect(captures.finalizeBody).toMatchObject({
      emailOtpEnrollment: {
        clientUnlockPublicKeyB64u: 'email-otp-client-unlock-public-key',
        thresholdEcdsaClientVerifyingShareB64u: CLIENT_PUBLIC_KEY_B64U,
      },
      emailOtpBackupAck: {
        kind: 'email_otp_recovery_code_backup_ack_v1',
        offerId: 'registration-offer-1',
        candidateId: 'registration-candidate-1',
        recoveryCodesIssuedAtMs: 1_700_000_000_000,
        backupActionKind: 'manual',
        acknowledgedAtMs: expect.any(Number),
        idempotencyKey: expect.stringContaining('email-otp-recovery-code-backup-ack'),
      },
    });
    expect(captures.persistedEcdsaSessions).toMatchObject({
      auth: {
        kind: 'email_otp',
        emailOtpAuthContext: {
          authority: {
            factor: {
              kind: 'email_otp',
            },
          },
        },
      },
    });
  } finally {
    backupRepository.write = originalBackupWrite;
    backupRepository.readMatching = originalBackupReadMatching;
    deferredEmailOtpEnrollmentMaterial.reject(new Error('test cleanup'));
    fetchMock.restore();
  }
});

test('registerWallet starts Email OTP Yao and ECDSA registration in parallel', async () => {
  const events: string[] = [];
  const deferredEmailOtpYaoStart = createDeferredPromise<void>();
  const captures: Record<string, unknown> = {
    registrationEvents: events,
    deferredEmailOtpYaoStart,
    enableRegistrationPreparationModalClose: true,
  };
  const fetchMock = installRegisterWalletFetch(captures);
  const backupCapture = new EmailOtpRecoveryCodeBackupCapture(captures);
  const walletId = walletIdFromString('email-otp-mixed.testnet');
  const appSessionJwt = jwtWithPayload({
    kind: 'app_session_v1',
    sub: EMAIL_OTP_PROVIDER_SUBJECT,
    walletId: String(walletId),
    providerSubject: EMAIL_OTP_PROVIDER_SUBJECT,
    appSessionVersion: 'app-session-v1',
    exp: Math.floor(Date.now() / 1000) + 3_600,
  });
  backupCapture.install();
  try {
    const registration = withMockedIndexedDb(() =>
      registerWallet({
        context: createContext(captures),
        authMethod: {
          kind: 'email_otp',
          proofKind: 'google_sso_registration',
          email: 'alice@example.com',
          appSessionJwt,
          googleEmailOtpRegistrationAttemptId: 'registration-attempt-1',
          googleEmailOtpRegistrationOfferId: 'registration-offer-1',
          googleEmailOtpRegistrationCandidateId: 'registration-candidate-1',
        },
        wallet: { kind: 'provided', walletId },
        signerSelection: registrationSignerSet(
          nearEd25519RegistrationSigner(),
          evmFamilyRegistrationSigner([{ kind: 'evm', namespace: 'eip155', chainId: 1 }]),
        ),
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      }),
    );
    await waitForTestCondition({
      label: 'Email OTP Yao and ECDSA registration work to start',
      predicate: () =>
        events.includes('emailOtpYaoStartCalled') && events.includes('ecdsaCeremonyStarted'),
    });
    expect(captures.emailOtpYaoPrewarmCalls).toBe(1);
    expect(captures.finalizeBody).toBeUndefined();

    deferredEmailOtpYaoStart.resolve(undefined);
    const result = await registration;

    expectRegistrationSuccess(result);
    expect(result).toMatchObject({
      success: true,
      kind: 'near_ed25519_and_ecdsa_wallet_registered',
    });
    expect(events).toContain('emailOtpYaoCommitCalled');
    expect(registrationEventCount(events, 'emailOtpYaoCommitCalled')).toBe(1);
    expect(events).not.toContain('emailOtpYaoDisposed');
    expect(captures.finalizeBody).toBeDefined();
  } finally {
    backupCapture.restore();
    deferredEmailOtpYaoStart.reject(new Error('test cleanup'));
    fetchMock.restore();
  }
});

test('registerWallet disposes pending Yao exactly once when ECDSA fails first', async () => {
  const events: string[] = [];
  const deferredEmailOtpYaoStart = createDeferredPromise<void>();
  const captures: Record<string, unknown> = {
    registrationEvents: events,
    deferredEmailOtpYaoStart,
    ecdsaCeremonyFailure: true,
    enableRegistrationPreparationModalClose: true,
  };
  const fetchMock = installRegisterWalletFetch(captures);
  const backupCapture = new EmailOtpRecoveryCodeBackupCapture(captures);
  const walletId = walletIdFromString('email-otp-mixed-yao-failure.testnet');
  const appSessionJwt = jwtWithPayload({
    kind: 'app_session_v1',
    sub: EMAIL_OTP_PROVIDER_SUBJECT,
    walletId: String(walletId),
    providerSubject: EMAIL_OTP_PROVIDER_SUBJECT,
    appSessionVersion: 'app-session-v1',
    exp: Math.floor(Date.now() / 1000) + 3_600,
  });
  backupCapture.install();
  try {
    const registration = withMockedIndexedDb(() =>
      registerWallet({
        context: createContext(captures),
        authMethod: {
          kind: 'email_otp',
          proofKind: 'google_sso_registration',
          email: 'alice@example.com',
          appSessionJwt,
          googleEmailOtpRegistrationAttemptId: 'registration-attempt-1',
          googleEmailOtpRegistrationOfferId: 'registration-offer-1',
          googleEmailOtpRegistrationCandidateId: 'registration-candidate-1',
        },
        wallet: { kind: 'provided', walletId },
        signerSelection: registrationSignerSet(
          nearEd25519RegistrationSigner(),
          evmFamilyRegistrationSigner([{ kind: 'evm', namespace: 'eip155', chainId: 1 }]),
        ),
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      }),
    );
    await waitForTestCondition({
      label: 'ECDSA failure while Email OTP Yao registration is pending',
      predicate: () =>
        events.includes('emailOtpYaoStartCalled') && events.includes('ecdsaCeremonyStarted'),
    });

    expect(captures.finalizeBody).toBeUndefined();
    deferredEmailOtpYaoStart.resolve(undefined);
    const result = await registration;

    expect(result).toMatchObject({ success: false });
    expect(registrationEventCount(events, 'emailOtpYaoDisposed')).toBe(1);
    expect(captures.finalizeBody).toBeUndefined();
  } finally {
    backupCapture.restore();
    deferredEmailOtpYaoStart.reject(new Error('test cleanup'));
    fetchMock.restore();
  }
});

test('registerWallet disposes completed Email OTP Yao when deferred ECDSA fails', async () => {
  const events: string[] = [];
  const deferredEcdsaCeremony = createDeferredPromise<void>();
  const captures: Record<string, unknown> = {
    registrationEvents: events,
    deferredEcdsaCeremony,
    ecdsaCeremonyFailure: true,
    enableRegistrationPreparationModalClose: true,
  };
  const fetchMock = installRegisterWalletFetch(captures);
  const backupCapture = new EmailOtpRecoveryCodeBackupCapture(captures);
  const walletId = walletIdFromString('email-otp-mixed-ecdsa-failure.testnet');
  const appSessionJwt = jwtWithPayload({
    kind: 'app_session_v1',
    sub: EMAIL_OTP_PROVIDER_SUBJECT,
    walletId: String(walletId),
    providerSubject: EMAIL_OTP_PROVIDER_SUBJECT,
    appSessionVersion: 'app-session-v1',
    exp: Math.floor(Date.now() / 1000) + 3_600,
  });
  backupCapture.install();
  try {
    const registration = withMockedIndexedDb(() =>
      registerWallet({
        context: createContext(captures),
        authMethod: {
          kind: 'email_otp',
          proofKind: 'google_sso_registration',
          email: 'alice@example.com',
          appSessionJwt,
          googleEmailOtpRegistrationAttemptId: 'registration-attempt-1',
          googleEmailOtpRegistrationOfferId: 'registration-offer-1',
          googleEmailOtpRegistrationCandidateId: 'registration-candidate-1',
        },
        wallet: { kind: 'provided', walletId },
        signerSelection: registrationSignerSet(
          nearEd25519RegistrationSigner(),
          evmFamilyRegistrationSigner([{ kind: 'evm', namespace: 'eip155', chainId: 1 }]),
        ),
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      }),
    );
    await waitForTestCondition({
      label: 'Email OTP Yao completes before deferred ECDSA failure',
      predicate: () =>
        events.includes('ecdsaCeremonyStarted') && captures.emailOtpYaoStart !== undefined,
    });
    expect(events).not.toContain('ecdsaCeremonyResolved');
    expect(captures.finalizeBody).toBeUndefined();

    deferredEcdsaCeremony.resolve(undefined);
    const result = await registration;

    expect(result).toMatchObject({ success: false });
    expect(events).toContain('ecdsaCeremonyResolved');
    expect(events).toContain('emailOtpYaoDisposed');
    expect(registrationEventCount(events, 'emailOtpYaoDisposed')).toBe(1);
    expect(captures.finalizeBody).toBeUndefined();
  } finally {
    backupCapture.restore();
    deferredEcdsaCeremony.reject(new Error('test cleanup'));
    fetchMock.restore();
  }
});

test('registerWallet completes Email OTP Ed25519-only Yao registration atomically', async () => {
  const captures: Record<string, unknown> = {
    emailOtpYaoPrewarmFailure: true,
  };
  const fetchMock = installRegisterWalletFetch(captures);
  const backupCapture = new EmailOtpRecoveryCodeBackupCapture(captures);
  const walletId = walletIdFromString('email-otp-ed25519.testnet');
  const appSessionJwt = jwtWithPayload({
    kind: 'app_session_v1',
    sub: EMAIL_OTP_PROVIDER_SUBJECT,
    walletId: String(walletId),
    providerSubject: EMAIL_OTP_PROVIDER_SUBJECT,
    appSessionVersion: 'app-session-v1',
    exp: Math.floor(Date.now() / 1000) + 3_600,
  });
  backupCapture.install();
  try {
    const result = await withMockedIndexedDb(
      registerWallet.bind(undefined, {
        context: createContext(captures),
        authMethod: {
          kind: 'email_otp',
          proofKind: 'google_sso_registration',
          email: 'ALICE@EXAMPLE.COM',
          appSessionJwt,
          googleEmailOtpRegistrationAttemptId: 'registration-attempt-1',
          googleEmailOtpRegistrationOfferId: 'registration-offer-1',
          googleEmailOtpRegistrationCandidateId: 'registration-candidate-1',
        },
        wallet: { kind: 'provided', walletId },
        signerSelection: registrationSignerSet(nearEd25519RegistrationSigner()),
        options: {
          afterCall: captureEmailOtpRegistrationAfterCall.bind(undefined, captures),
        },
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      }),
    );

    expectRegistrationSuccess(result);
    expect(result).toMatchObject({
      success: true,
      kind: 'near_wallet_registered',
      walletId,
      operationalPublicKey: EMAIL_OTP_ED25519_PUBLIC_KEY,
    });
    expect(fetchMock.paths).toEqual([
      '/v1/registration/bootstrap-grants',
      '/wallets/register/intent',
      '/wallets/register/start',
      '/wallets/register/finalize',
    ]);
    expect(captures.emailOtpEnrollmentMaterialArgs).toMatchObject({
      walletId: String(walletId),
      userId: EMAIL_OTP_PROVIDER_SUBJECT,
      ed25519YaoFactor: {
        kind: 'ed25519_yao_factor_requested',
        providerSubject: EMAIL_OTP_PROVIDER_SUBJECT,
      },
    });
    expect(captures.emailOtpYaoWorkerOperations).toEqual([
      'bindEmailOtpEd25519YaoRoot',
      'startEmailOtpEd25519YaoRegistration',
      'commitEmailOtpEd25519YaoRegistration',
    ]);
    expect(captures.emailOtpYaoPrewarmCalls).toBe(1);
    expect(captures.emailOtpYaoStart).toMatchObject({
      walletId: String(walletId),
      providerSubject: EMAIL_OTP_PROVIDER_SUBJECT,
      registrationAuthorityId: 'registration-attempt-1',
      bearerToken: 'registration-grant',
    });
    expect(captures.finalizeBody).toMatchObject({
      kind: 'near_ed25519',
      ed25519: {
        activationReference: {
          kind: 'router_ab_ed25519_yao_activation_reference_v1',
          lifecycle_id: 'registration-ceremony',
        },
      },
      emailOtpEnrollment: {
        clientUnlockPublicKeyB64u: 'email-otp-client-unlock-public-key',
      },
      emailOtpBackupAck: {
        kind: 'email_otp_recovery_code_backup_ack_v1',
      },
    });
    expect(captures.finalizeBody).not.toHaveProperty('ecdsa');
    expect(captures.storedEmailOtpEd25519Registration).toMatchObject({
      walletId: String(walletId),
      email: 'alice@example.com',
      registrationAuthorityId: 'registration-attempt-1',
      signerSlot: 1,
      operationalPublicKey: EMAIL_OTP_ED25519_PUBLIC_KEY,
      participantIds: [1, 2],
    });
    expect(captures.storedEcdsaRegistration).toBeUndefined();
    expect(captures.activatedEmailOtpEd25519YaoCapability).toMatchObject({
      walletSessionState: {
        thresholdSessionId: 'registration-ceremony',
        signingGrantId: 'email-otp-ed25519-signing-grant',
        signingLane: {
          auth: {
            kind: 'email_otp',
            providerSubjectId: EMAIL_OTP_PROVIDER_SUBJECT,
          },
          identity: {
            signer: {
              account: {
                wallet: { walletId: String(walletId) },
              },
              signerSlot: 1,
            },
          },
        },
      },
    });
    expect(captures.rememberedEmailOtpAppSession).toEqual({
      kind: 'email_otp_app_session_binding',
      walletId,
      providerSubject: EMAIL_OTP_PROVIDER_SUBJECT,
      appSessionJwt,
    });
    expect(captures.emailOtpAppSessionRememberedBeforeAfterCall).toBe(true);
  } finally {
    backupCapture.restore();
    fetchMock.restore();
  }
});

test('Email OTP Ed25519-only registration disposes Yao state on finalize identity mismatch', async () => {
  const captures: Record<string, unknown> = {
    emailOtpEd25519FinalizePublicKey: `ed25519:${base58Encode(new Uint8Array(32).fill(9))}`,
  };
  const fetchMock = installRegisterWalletFetch(captures);
  const backupCapture = new EmailOtpRecoveryCodeBackupCapture(captures);
  const walletId = walletIdFromString('email-otp-ed25519-mismatch.testnet');
  const appSessionJwt = jwtWithPayload({
    kind: 'app_session_v1',
    sub: EMAIL_OTP_PROVIDER_SUBJECT,
    walletId: String(walletId),
    providerSubject: EMAIL_OTP_PROVIDER_SUBJECT,
    appSessionVersion: 'app-session-v1',
    exp: Math.floor(Date.now() / 1000) + 3_600,
  });
  backupCapture.install();
  try {
    const result = await withMockedIndexedDb(
      registerWallet.bind(undefined, {
        context: createContext(captures),
        authMethod: {
          kind: 'email_otp',
          proofKind: 'google_sso_registration',
          email: 'alice@example.com',
          appSessionJwt,
          googleEmailOtpRegistrationAttemptId: 'registration-attempt-1',
          googleEmailOtpRegistrationOfferId: 'registration-offer-1',
          googleEmailOtpRegistrationCandidateId: 'registration-candidate-1',
        },
        wallet: { kind: 'provided', walletId },
        signerSelection: registrationSignerSet(nearEd25519RegistrationSigner()),
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      }),
    );

    expect(result).toMatchObject({
      success: false,
      error: expect.stringContaining('mismatched signer identity'),
    });
    expect(captures.emailOtpYaoWorkerOperations).toEqual([
      'bindEmailOtpEd25519YaoRoot',
      'startEmailOtpEd25519YaoRegistration',
      'disposeEmailOtpEd25519YaoRegistration',
    ]);
    expect(captures.emailOtpYaoDisposed).toEqual({
      pendingHandle: 'email-otp-ed25519-pending-1',
    });
    expect(captures.storedEmailOtpEd25519Registration).toBeUndefined();
    expect(captures.activatedEmailOtpEd25519YaoCapability).toBeUndefined();
  } finally {
    backupCapture.restore();
    fetchMock.restore();
  }
});

test('registerWallet rejects invalid ECDSA respond bootstrap before finalize', async () => {
  const captures: Record<string, unknown> = {
    patchRegistrationBootstrap: (bootstrap: Record<string, unknown>) => ({
      ...bootstrap,
      publicIdentity: {
        ...(bootstrap.publicIdentity as Record<string, unknown>),
        derivationClientSharePublicKey33B64u: MISMATCHED_CLIENT_PUBLIC_KEY_B64U,
      },
    }),
  };
  const fetchMock = installRegisterWalletFetch(captures);
  try {
    const result = await withMockedIndexedDb(() =>
      registerWallet({
        context: createContext(captures),
        authMethod: { kind: 'passkey', rpId: RP_ID },
        wallet: { kind: 'server_allocated' },
        signerSelection: registrationSignerSet(
          evmFamilyRegistrationSigner([{ kind: 'evm', namespace: 'eip155', chainId: 1 }]),
        ),
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      }),
    );

    expect(result).toMatchObject({
      success: false,
      error: expect.stringMatching(/derivation_client_share_public_key33_b64u mismatch/),
    });
    expect(captures.finalizeBody).toBeUndefined();
    expect(captures.persistedEcdsaSessions).toBeUndefined();
    expect(captures.storedEcdsaRegistration).toBeUndefined();
  } finally {
    fetchMock.restore();
  }
});

test('registerWallet rejects mismatched ECDSA wallet key before registration persistence', async () => {
  const captures: Record<string, unknown> = {
    patchRegistrationWalletKey: (walletKey: Record<string, unknown>) => ({
      ...walletKey,
      keyHandle: 'mismatched-key-handle',
    }),
  };
  const fetchMock = installRegisterWalletFetch(captures);
  try {
    const result = await withMockedIndexedDb(() =>
      registerWallet({
        context: createContext(captures),
        authMethod: { kind: 'passkey', rpId: RP_ID },
        wallet: { kind: 'server_allocated' },
        signerSelection: registrationSignerSet(
          evmFamilyRegistrationSigner([{ kind: 'evm', namespace: 'eip155', chainId: 1 }]),
        ),
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      }),
    );

    expect(result).toMatchObject({
      success: false,
      error: expect.stringMatching(/keyHandle mismatch/),
    });
    expect(captures.finalizeBody).toBeDefined();
    expect(captures.persistedEcdsaSessions).toBeUndefined();
    expect(captures.storedEcdsaRegistration).toBeUndefined();
  } finally {
    fetchMock.restore();
  }
});
function installAddSignerFetch(captures: Record<string, unknown>) {
  const originalFetch = globalThis.fetch;
  const paths: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const path = url.pathname;
    paths.push(path);
    const body = init?.body ? JSON.parse(String(init.body)) : {};
    if (path === '/v1/registration/bootstrap-grants') {
      return jsonResponse({
        ok: true,
        grant: {
          token: 'bootstrap-grant',
          orgId: RUNTIME_POLICY_SCOPE.orgId,
          projectId: RUNTIME_POLICY_SCOPE.projectId,
          envId: RUNTIME_POLICY_SCOPE.envId,
          signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        },
      });
    }
    if (path === `/wallets/${WALLET_SUBJECT_ID}/signers/intent`) {
      const intent = {
        version: 'add_signer_intent_v1' as const,
        walletId: WALLET_SUBJECT_ID,
        signerSelection: body.signerSelection,
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
        nonceB64u: 'add-signer-nonce',
      };
      const digest = await computeAddSignerIntentDigestB64u(intent);
      captures.intent = intent;
      captures.digest = digest;
      return jsonResponse({
        ok: true,
        intent,
        addSignerIntentDigestB64u: digest,
        addSignerIntentGrant: 'add-signer-grant',
        expiresAtMs: Date.now() + 60_000,
      });
    }
    if (path === `/wallets/${WALLET_SUBJECT_ID}/signers/start`) {
      captures.startBody = body;
      if (body.intent?.signerSelection?.mode === 'ed25519') {
        const selection = body.intent.signerSelection.ed25519;
        const ceremonyId = 'add-signer-ceremony';
        const nearEd25519SigningKeyId = await computeAddSignerNearEd25519SigningKeyId({
          kind: 'wallet_add_signer_implicit_near_ed25519_key_v1',
          walletId: body.intent.walletId,
          signingRootId: 'project_matrix:dev',
          signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
          signerSlot: selection.signerSlot,
          participantIds: selection.participantIds,
          keyPurpose: selection.keyPurpose,
          keyVersion: selection.keyVersion,
          derivationVersion: selection.derivationVersion,
        });
        let admissionRequest = {
          scope: {
            lifecycle_id: ceremonyId,
            root_share_epoch: RUNTIME_POLICY_SCOPE.signingRootVersion,
            account_id: body.intent.walletId,
            wallet_session_id: ceremonyId,
            signer_set_id: registrationNearEd25519BranchKey(selection.signerSlot),
            signing_worker_id: 'signing-worker-test',
          },
          application_binding: {
            wallet_id: body.intent.walletId,
            near_ed25519_signing_key_id: nearEd25519SigningKeyId,
            signing_root_id: 'project_matrix:dev',
            key_creation_signer_slot: selection.signerSlot,
          },
          participant_ids: selection.participantIds,
        } as Record<string, any>;
        const patchEd25519AdmissionRequest = captures.patchEd25519AdmissionRequest as
          | ((request: Record<string, any>) => Record<string, any>)
          | undefined;
        if (patchEd25519AdmissionRequest) {
          admissionRequest = patchEd25519AdmissionRequest(admissionRequest);
        }
        return jsonResponse({
          ok: true,
          addSignerCeremonyId: ceremonyId,
          intent: body.intent,
          kind: 'near_ed25519',
          ed25519: { admissionRequest },
        });
      }
      if (body.intent?.signerSelection?.mode === 'ecdsa') {
        const chainTargets = body.intent.signerSelection.ecdsa.chainTargets as Record<
          string,
          unknown
        >[];
        const strictRegistration = await mockedEcdsaStrictRegistrationFacts({
          body,
          registrationPurpose: 'wallet_add_signer',
        });
        const prepare = {
          formatVersion: 'ecdsa-derivation-role-local',
          walletId: String(WALLET_SUBJECT_ID),
          evmFamilySigningKeySlotId: plannedEcdsaWalletKeyId(WALLET_SUBJECT_ID),
          ecdsaThresholdKeyId: 'ecdsa-threshold-key-id',
          signingRootId: 'project_matrix:dev',
          signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
          keyScope: 'evm-family',
          relayerKeyId: 'relayer-ecdsa',
          registrationPreparationId: 'add-signer-preparation',
          requestId: 'request-ecdsa',
          thresholdSessionId: 'session-ecdsa',
          signingGrantId: 'wallet-session-ecdsa',
          ttlMs: 600_000,
          remainingUses: 1,
          participantIds: [1, 2],
          runtimePolicyScope: RUNTIME_POLICY_SCOPE,
        };
        captures.ecdsaPrepare = prepare;
        return jsonResponse({
          ok: true,
          addSignerCeremonyId: 'add-signer-ceremony',
          intent: body.intent,
          kind: 'evm_family_ecdsa',
          ecdsa: {
            kind: 'evm_family_ecdsa_keygen',
            chainTargets,
            prepare,
            strictRegistration,
          },
        });
      }
    }
    if (path === `/wallets/${WALLET_SUBJECT_ID}/signers/derivation/respond`) {
      captures.respondBody = body;
      if (body.ecdsa?.strictRegistration) {
        return jsonResponse({
          ok: true,
          addSignerCeremonyId: body.addSignerCeremonyId,
          ecdsa: {
            kind: 'router_ab_ecdsa_registration_forwarded_v1',
            strictResult: {
              result: 'forwarded',
              response: {
                replay: { request_id: 'request-ecdsa', reserved: true },
                lifecycle: { lifecycle_id: 'wallet_add_signer', stored: true },
                bundles: {
                  signerA: {
                    kind: 'recipient_proof_bundle',
                    transcriptDigestB64u: CONTEXT_BINDING_32_B64U,
                    payloadB64u: 'proof-a',
                  },
                  signerB: {
                    kind: 'recipient_proof_bundle',
                    transcriptDigestB64u: CONTEXT_BINDING_32_B64U,
                    payloadB64u: 'proof-b',
                  },
                },
              },
            },
          },
        });
      }
      if (body.ecdsa) {
        const clientEntry = body.ecdsa.clientBootstraps[0];
        const addSignerEcdsaExpiresAtMs = Date.now() + 60_000;
        let ecdsaBootstrap = {
          ...clientEntry.clientBootstrap,
          publicIdentity: {
            derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
            relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
            groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
            ethereumAddress: '0x1111111111111111111111111111111111111111',
          },
          publicTranscriptDigest32B64u: 'transcript-digest',
          keyHandle: 'ederivation-key-matrix',
          applicationBindingDigestB64u: await ecdsaApplicationBindingDigestB64u(WALLET_SUBJECT_ID),
          relayerShareRetryCounter: 1,
          thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
          ethereumAddress: '0x1111111111111111111111111111111111111111',
          relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
          thresholdSessionId: String(clientEntry.clientBootstrap.thresholdSessionId || ''),
          expiresAtMs: addSignerEcdsaExpiresAtMs,
          expiresAt: new Date(addSignerEcdsaExpiresAtMs).toISOString(),
        } as Record<string, unknown>;
        const patchAddSignerBootstrap = captures.patchAddSignerBootstrap as
          | ((bootstrap: Record<string, unknown>) => Record<string, unknown>)
          | undefined;
        if (patchAddSignerBootstrap) {
          ecdsaBootstrap = patchAddSignerBootstrap(ecdsaBootstrap);
        }
        ecdsaBootstrap.jwt = ecdsaWalletSessionJwtForBootstrap(ecdsaBootstrap);
        return jsonResponse({
          ok: true,
          addSignerCeremonyId: body.addSignerCeremonyId,
          ecdsa: {
            bootstraps: [
              {
                chainTarget: clientEntry.chainTarget,
                bootstrap: ecdsaBootstrap,
              },
            ],
          },
        });
      }
    }
    if (path === `/wallets/${WALLET_SUBJECT_ID}/signers/derivation/activate`) {
      const ecdsaFacts = captures.ecdsaRegistrationFacts as Record<string, any>;
      const prepare = captures.ecdsaPrepare as Record<string, any>;
      let bootstrap = mockedEcdsaServerBootstrap(ecdsaFacts, prepare);
      const sessionJwt = ecdsaWalletSessionJwtForBootstrap(bootstrap);
      const patchAddSignerBootstrap = captures.patchAddSignerBootstrap as
        | ((value: Record<string, unknown>) => Record<string, unknown>)
        | undefined;
      if (patchAddSignerBootstrap) {
        bootstrap = patchAddSignerBootstrap(bootstrap);
      }
      bootstrap.jwt = sessionJwt;
      return jsonResponse({
        ok: true,
        addSignerCeremonyId: body.addSignerCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_activated_v1',
          activation: mockedEcdsaActivationReceipt(ecdsaFacts),
          bootstrap,
        },
      });
    }
    if (path === `/wallets/${WALLET_SUBJECT_ID}/signers/finalize`) {
      captures.finalizeBody = body;
      if (body.ecdsa) {
        const ecdsaFacts = captures.ecdsaRegistrationFacts as Record<string, any>;
        return jsonResponse({
          ok: true,
          walletId: WALLET_SUBJECT_ID,
          rpId: RP_ID,
          kind: 'evm_family_ecdsa',
          ecdsa: {
            walletKeys: [
              {
                keyScope: 'evm-family',
                chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 1 },
                walletId: String(WALLET_SUBJECT_ID),
                evmFamilySigningKeySlotId: plannedEcdsaWalletKeyId(WALLET_SUBJECT_ID),
                keyHandle: 'ederivation-key-matrix',
                ecdsaThresholdKeyId: 'ecdsa-threshold-key-id',
                signingRootId: 'project_matrix:dev',
                signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
                thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
                thresholdOwnerAddress: '0x3333333333333333333333333333333333333333',
                relayerKeyId: 'relayer-ecdsa',
                relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
                contextBinding32B64u: CONTEXT_BINDING_32_B64U,
                derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
                clientShareRetryCounter: 0,
                relayerShareRetryCounter: 1,
                participantIds: [1, 2],
                publicCapability: mockedEcdsaPublicCapability(ecdsaFacts),
              },
            ],
          },
        });
      }
    }
    return jsonResponse({ ok: false, message: `unexpected path ${path}` }, 404);
  }) as typeof fetch;
  return {
    paths,
    restore: () => {
      globalThis.fetch = originalFetch;
    },
  };
}

test('addWalletSigner orchestrates later ECDSA from an Ed25519 wallet', async () => {
  const captures: Record<string, unknown> = {};
  const fetchMock = installAddSignerFetch(captures);
  try {
    const result = await withMockedIndexedDb(() =>
      addWalletSigner({
        context: createContext(captures),
        walletId: WALLET_SUBJECT_ID,
        rpId: RP_ID,
        signerSelection: {
          mode: 'ecdsa',
          ecdsa: {
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1 }],
            participantIds: [1, 2],
          },
        },
        options: {},
      }),
    );

    expectRegistrationSuccess(result);
    expect(result).toMatchObject({
      success: true,
      thresholdEcdsaEthereumAddress: '0x3333333333333333333333333333333333333333',
    });
    expect(fetchMock.paths).toEqual([
      '/v1/registration/bootstrap-grants',
      `/wallets/${WALLET_SUBJECT_ID}/signers/intent`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/start`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/derivation/respond`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/derivation/activate`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/finalize`,
    ]);
    expect(captures.authenticationArgs).toMatchObject({
      challengeB64u: captures.digest,
      includeSecondPrfOutput: false,
    });
    expect(captures.startBody).toMatchObject({
      auth: {
        kind: 'webauthn_assertion',
        credential: {
          clientExtensionResults: null,
        },
      },
    });
    expect(captures.finalizeBody).toMatchObject({
      kind: 'evm_family_ecdsa',
      idempotencyKey: expect.stringMatching(/^wallet-add-signer-finalize:/),
      ecdsa: {
        expectedKeyHandles: ['ederivation-key-matrix'],
      },
    });
    expect(captures.persistedEcdsaSessions).toMatchObject({
      auth: { kind: 'passkey', credentialIdB64u: 'credential-id' },
    });
  } finally {
    fetchMock.restore();
  }
});

test('addWalletSigner rejects invalid ECDSA respond bootstrap before finalize', async () => {
  const captures: Record<string, unknown> = {
    patchAddSignerBootstrap: (bootstrap: Record<string, unknown>) => ({
      ...bootstrap,
      contextBinding32B64u: 'mismatched-context-binding',
    }),
  };
  const fetchMock = installAddSignerFetch(captures);
  try {
    const result = await withMockedIndexedDb(() =>
      addWalletSigner({
        context: createContext(captures),
        walletId: WALLET_SUBJECT_ID,
        rpId: RP_ID,
        signerSelection: {
          mode: 'ecdsa',
          ecdsa: {
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1 }],
            participantIds: [1, 2],
          },
        },
        options: {},
      }),
    );

    expect(result).toMatchObject({
      success: false,
      error: expect.stringMatching(/context_binding_b64u mismatch/),
    });
    expect(captures.finalizeBody).toBeUndefined();
    expect(captures.persistedEcdsaSessions).toBeUndefined();
    expect(captures.storedEcdsa).toBeUndefined();
  } finally {
    fetchMock.restore();
  }
});

test('addWalletSigner rejects substituted Ed25519 Yao admission before execution', async () => {
  const captures: Record<string, unknown> = {
    patchEd25519AdmissionRequest: (request: Record<string, any>) => ({
      ...request,
      application_binding: {
        ...request.application_binding,
        near_ed25519_signing_key_id: 'near-ed25519-signing-key-substituted',
      },
    }),
  };
  const fetchMock = installAddSignerFetch(captures);
  try {
    const result = await withMockedIndexedDb(() =>
      addWalletSigner({
        context: createContext(captures),
        walletId: WALLET_SUBJECT_ID,
        rpId: RP_ID,
        signerSelection: {
          mode: 'ed25519',
          ed25519: {
            mode: 'create_implicit_near_account',
            signerSlot: 3,
            participantIds: [1, 2],
            keyPurpose: 'near_tx',
            keyVersion: 'router-ab-ed25519-yao-v1',
            derivationVersion: 1,
          },
        },
        options: {},
      }),
    );

    expect(result).toMatchObject({
      success: false,
      error: expect.stringMatching(/Yao NEAR signing-key ID does not match/),
    });
    expect(fetchMock.paths).toEqual([
      '/v1/registration/bootstrap-grants',
      `/wallets/${WALLET_SUBJECT_ID}/signers/intent`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/start`,
    ]);
    expect(captures.finalizeBody).toBeUndefined();
    expect(captures.storedEd25519).toBeUndefined();
  } finally {
    fetchMock.restore();
  }
});
