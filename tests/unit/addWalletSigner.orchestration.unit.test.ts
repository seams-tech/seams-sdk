import { expect, test } from '@playwright/test';
import { buildFixtureRespondEd25519DeferredWork } from '../helpers/ed25519YaoAdmissionFixtures';
import {
  addWalletSigner,
  registerWallet,
} from '../../packages/sdk-web/src/SeamsWeb/operations/registration/registration';
import { createEvmSignerCapability } from '../../packages/sdk-web/src/SeamsWeb/publicApi/evm';
import { IndexedDBManager } from '../../packages/sdk-web/src/core/indexedDB';
import { walletSessionAuthorizations } from '../../packages/sdk-web/src/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { finalizeWalletRegistrationEcdsaSessions as finalizeWalletRegistrationEcdsaSessionsOperation } from '../../packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions';
import {
  readNearProvisioningState,
  resetNearProvisioningRegistryForTests,
} from '@/core/signingEngine/flows/registration/nearProvisioningRegistry';
import { UserVerificationPolicy } from '../../packages/sdk-web/src/core/types/authenticatorOptions';
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
import {
  parseMpcMaterialActivationRef,
  parseWebAuthnRpId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { parseNamedNearAccountId } from '../../packages/shared-ts/src/utils/near';
import { base58Encode } from '../../packages/shared-ts/src/utils/base58';
import { sha256HexUtf8 } from '../../packages/shared-ts/src/utils/digests';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '../../packages/shared-ts/src/utils/walletAuthAuthority';
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
import { base64UrlDecode } from '../../packages/shared-ts/src/utils/encoders';
import { computeWalletAddSignerEcdsaActivationRequestDigestB64u } from '../../packages/shared-ts/src/utils/walletAddSignerActivation';
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
        appSessionJwt: jwtWithPayload({
          kind: 'app_session_v1',
          sub: 'registration-passkey',
          walletId,
        }),
      };
    default:
      throw new Error('registration fixture requires an exact auth method');
  }
}

async function mockedNearEd25519FinalizeResponse(
  captures: Record<string, unknown>,
  walletId: string,
): Promise<Record<string, unknown>> {
  const base = await mockedEcdsaFinalizeResponse(captures, walletId);
  const intentAuthMethod = (captures.intent as any)?.authMethod;
  const nearSigner = mockedRegistrationNearEd25519Signer((captures.intent as any)?.signerSelection);
  if (!nearSigner) throw new Error('NEAR registration fixture requires an Ed25519 signer');
  const passkeyAuth = intentAuthMethod?.kind === 'passkey';
  const nearEd25519SigningKeyId = String(
    captures.nearEd25519SigningKeyId || 'near-ed25519-registration-key',
  );
  const nearAccountId = String(captures.sponsoredNearAccountId || 'ab'.repeat(32));
  const authorityScope = passkeyAuth
    ? { kind: 'passkey_rp', rpId: RP_ID }
    : {
        kind: 'email_otp',
        provider: 'google',
        providerUserId: EMAIL_OTP_PROVIDER_SUBJECT,
      };
  const accountProvisioning = captures.sponsoredNearAccountId
    ? {
        kind: 'sponsored_named_account',
        requestedAccountId: String(captures.sponsoredNearAccountId),
        sponsor: 'relayer',
      }
    : { kind: 'implicit_account', accountIdSource: 'ed25519_public_key' };
  const resolvedAccount = captures.sponsoredNearAccountId
    ? {
        kind: 'sponsored_named_account',
        nearAccountId,
        nearEd25519SigningKeyId,
        transactionHash: 'sponsored-named-account-tx',
      }
    : { kind: 'implicit_account', nearAccountId, nearEd25519SigningKeyId };
  const publicKey = String(
    captures.emailOtpEd25519FinalizePublicKey || EMAIL_OTP_ED25519_PUBLIC_KEY,
  );
  const result = {
    ...base,
    kind: 'near_ed25519',
    authorityScope,
    accountProvisioning,
    resolvedAccount,
    ed25519: {
      signerSlot: nearSigner.signerSlot,
      nearAccountId,
      nearEd25519SigningKeyId,
      publicKey,
      relayerKeyId: 'signing-worker-test',
      keyVersion: 'router-ab-ed25519-yao-v1',
      recoveryExportCapable: true,
      participantIds: nearSigner.participantIds,
      thresholdSessionId: 'registration-ceremony-session',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      routerAbNormalSigning: {
        kind: 'router_ab_ed25519_normal_signing_v1',
        signingWorkerId: 'signing-worker-test',
      },
    },
    nearProvisioning: { status: 'near_pending' },
  };
  return result;
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
        keyHandle: 'ederivation-key-registration',
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

/* A sponsored named account is created under the walletId itself, so the NEAR
   identity must come back as the walletId rather than a derived key. */
function sponsoredNearEd25519RegistrationSigner(
  requestedAccountId: string,
): RegistrationSignerRequest {
  const parsedRequestedAccountId = unwrapFixture(parseNamedNearAccountId(requestedAccountId));
  return {
    kind: 'near_ed25519' as const,
    accountProvisioning: {
      kind: 'sponsored_named_account' as const,
      requestedAccountId: parsedRequestedAccountId,
      sponsor: 'relayer' as const,
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
  const mixedRegistration =
    mockedRegistrationNearEd25519Signer(body.intent.signerSelection) !== null;
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
        public_key: 'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-test',
        public_key: 'x25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
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
    ethereum_address20_b64u: ethereumAddress20B64u('0x3333333333333333333333333333333333333333'),
    client_share_retry_counter: 0,
    server_share_retry_counter: 1,
  };
}

function mockedEcdsaPublicCapability(facts: Record<string, any>): Record<string, unknown> {
  return {
    kind: 'router_ab_ecdsa_derivation_public_capability_v1',
    context: facts.context,
    public_identity: mockedEcdsaPublicIdentity(),
    material_activation: {
      kind: 'mpc_material_activation_ref',
      activation_id: `ecdsa-activation:${facts.lifecycle.lifecycle_id}`,
      capability: `ecdsa-capability:${facts.lifecycle.account_id}`,
      material_owner: facts.lifecycle.account_id,
      key_binding: 'ecdsa-key-binding-fixture',
      lifecycle_binding: facts.lifecycle.lifecycle_id,
      signing_worker: facts.signer_set.selected_server.server_id,
    },
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
        : 'ederivation-key-registration',
    signingRootId: prepare.signingRootId,
    signingRootVersion: prepare.signingRootVersion,
    thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
    ethereumAddress: '0x3333333333333333333333333333333333333333',
    relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
    participantIds: [1, 2],
    thresholdSessionId: prepare.thresholdSessionId,
    activationEpoch: facts.lifecycle.root_share_epoch,
    expiresAtMs,
    expiresAt: new Date(expiresAtMs).toISOString(),
    remainingUses: prepare.remainingUses,
    routerAbEcdsaDerivationNormalSigning: {
      kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
      scope: {
        wallet_id: walletId,
        ecdsa_threshold_key_id: String(prepare.ecdsaThresholdKeyId),
        signing_root_id: String(prepare.signingRootId),
        signing_root_version: String(prepare.signingRootVersion),
        context: { application_binding_digest_b64u: facts.context.application_binding_digest_b64u },
        public_identity: mockedEcdsaPublicIdentity(),
        signing_worker: {
          server_id: 'signing-worker-test',
          key_epoch: 'worker-epoch-test',
          recipient_encryption_key:
            'x25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        },
        material_activation: {
          kind: 'mpc_material_activation_ref',
          activation_id: `ecdsa-activation:${facts.lifecycle.lifecycle_id}`,
          capability: `ecdsa-capability:${facts.lifecycle.account_id}`,
          material_owner: facts.lifecycle.account_id,
          key_binding: 'ecdsa-key-binding-fixture',
          lifecycle_binding: facts.lifecycle.lifecycle_id,
          signing_worker: 'signing-worker-test',
        },
        activation_epoch: facts.lifecycle.root_share_epoch,
      },
    },
  };
  return bootstrap;
}

function mockedEcdsaActivationReceipt(
  facts: Record<string, any>,
  activationRequestDigest?: { bytes: number[] },
): Record<string, unknown> {
  const digest = { bytes: new Array<number>(32).fill(0) };
  return {
    activation_correlation_id: facts.lifecycle.lifecycle_id,
    activation_request_digest: activationRequestDigest ?? digest,
    server_generation: 'generation-test',
    ecdsa_activation: {
      context: facts.context,
      public_identity: {
        ...mockedEcdsaPublicIdentity(),
      },
      signing_worker: facts.signer_set.selected_server,
      material_activation: {
        kind: 'mpc_material_activation_ref',
        activation_id: `ecdsa-activation:${facts.lifecycle.lifecycle_id}`,
        capability: `ecdsa-capability:${facts.lifecycle.account_id}`,
        material_owner: facts.lifecycle.account_id,
        key_binding: 'ecdsa-key-binding-fixture',
        lifecycle_binding: facts.lifecycle.lifecycle_id,
        signing_worker: facts.signer_set.selected_server.server_id,
      },
      activation_epoch: facts.lifecycle.root_share_epoch,
      activation_digest_b64u: CONTEXT_BINDING_32_B64U,
      activated_at_ms: Date.now(),
    },
    lifecycle_id: facts.lifecycle.lifecycle_id,
    transcript_digest: digest,
  };
}

function mockedRegistrationEstablishedEcdsaSession(
  walletId: string,
  bootstrap: Record<string, unknown>,
  near?: {
    nearAccountId: string;
    nearEd25519SigningKeyId: string;
    thresholdSessionId: string;
  },
): Record<string, unknown> {
  const seamsSessionId = `registration-seams:${walletId}`;
  const authorizationId = `registration-authorization:${walletId}`;
  const walletSessionId = `registration-wallet-session:${walletId}`;
  const quotaId = `registration-quota:${walletId}`;
  const thresholdSessionId = String(bootstrap.thresholdSessionId || 'session-ecdsa');
  const expiresAtMs = Number(bootstrap.expiresAtMs || Date.now() + 60_000);
  const remainingUses = Number(bootstrap.remainingUses || 1);
  const walletSessionJwt = jwtWithPayload({
    kind: 'router_ab_ecdsa_derivation_wallet_session_v1',
    walletId,
    sid: seamsSessionId,
    authorizationId,
    walletSessionId,
    quotaId,
    thresholdSessionId,
    thresholdExpiresAtMs: expiresAtMs,
  });
  const ecdsa = {
    walletSessionJwt,
    thresholdSessionId,
    keyHandle: String(bootstrap.keyHandle || 'ederivation-key-registration'),
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    routerAbEcdsaDerivationNormalSigning: bootstrap.routerAbEcdsaDerivationNormalSigning,
  };
  const tokens = near
    ? {
        kind: 'near_ed25519_and_evm_family_ecdsa',
        ecdsa,
        ed25519: {
          walletSessionJwt: jwtWithPayload({
            kind: 'router_ab_ed25519_wallet_session_v1',
            walletId,
            sid: seamsSessionId,
            authorizationId,
            walletSessionId,
            quotaId,
            thresholdSessionId: near.thresholdSessionId,
            nearAccountId: near.nearAccountId,
            nearEd25519SigningKeyId: near.nearEd25519SigningKeyId,
            thresholdExpiresAtMs: expiresAtMs,
          }),
          thresholdSessionId: near.thresholdSessionId,
          nearAccountId: near.nearAccountId,
          nearEd25519SigningKeyId: near.nearEd25519SigningKeyId,
          runtimePolicyScope: RUNTIME_POLICY_SCOPE,
          routerAbNormalSigning: {
            kind: 'router_ab_ed25519_normal_signing_v1',
            signingWorkerId: 'signing-worker-test',
          },
        },
      }
    : { kind: 'evm_family_ecdsa', ecdsa };
  return {
    kind: 'registration_established_wallet_session_v1',
    walletId,
    seamsSessionId,
    authorizationId,
    walletSessionId,
    quotaId,
    expiresAtMs,
    remainingUses,
    tokens,
  };
}

function mockedRegistrationEstablishedNearSession(args: {
  walletId: string;
  expiresAtMs: number;
  remainingUses: number;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  thresholdSessionId: string;
}): Record<string, unknown> {
  const seamsSessionId = `registration-seams:${args.walletId}`;
  const authorizationId = `registration-authorization:${args.walletId}`;
  const walletSessionId = `registration-wallet-session:${args.walletId}`;
  const quotaId = `registration-quota:${args.walletId}`;
  return {
    kind: 'registration_established_wallet_session_v1',
    walletId: args.walletId,
    seamsSessionId,
    authorizationId,
    walletSessionId,
    quotaId,
    expiresAtMs: args.expiresAtMs,
    remainingUses: args.remainingUses,
    tokens: {
      kind: 'near_ed25519',
      ed25519: {
        walletSessionJwt: jwtWithPayload({
          kind: 'router_ab_ed25519_wallet_session_v1',
          walletId: args.walletId,
          sid: seamsSessionId,
          authorizationId,
          walletSessionId,
          quotaId,
          thresholdSessionId: args.thresholdSessionId,
          nearAccountId: args.nearAccountId,
          nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
          thresholdExpiresAtMs: args.expiresAtMs,
        }),
        thresholdSessionId: args.thresholdSessionId,
        nearAccountId: args.nearAccountId,
        nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
        routerAbNormalSigning: {
          kind: 'router_ab_ed25519_normal_signing_v1',
          signingWorkerId: 'signing-worker-test',
        },
      },
    },
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

function emailOtpRegistrationAppSessionJwt(walletId: string): string {
  return jwtWithPayload({
    kind: 'app_session_v1',
    sub: EMAIL_OTP_PROVIDER_SUBJECT,
    walletId,
    providerSubject: EMAIL_OTP_PROVIDER_SUBJECT,
    authSource: {
      kind: 'oidc_provider',
      providerId: 'google_oidc',
      providerSubject: EMAIL_OTP_PROVIDER_SUBJECT,
    },
    provider: 'google',
    appSessionVersion: 'app-session-v1',
    exp: Math.floor(Date.now() / 1000) + 3_600,
  });
}

function ethereumAddress20B64u(address: string): string {
  return Buffer.from(address.replace(/^0x/i, ''), 'hex').toString('base64url');
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

function ecdsaCapabilityFromRegistrationResult(result: {
  capabilities?: readonly {
    kind: string;
    thresholdEcdsaEthereumAddress?: string;
    thresholdEcdsaPublicKeyB64u?: string;
  }[];
}): {
  thresholdEcdsaEthereumAddress?: string;
  thresholdEcdsaPublicKeyB64u?: string;
} | null {
  return result.capabilities?.find((capability) => capability.kind === 'evm_family_ecdsa') ?? null;
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

async function persistInitialCanonicalEcdsaActivationForTest(
  captures: Record<string, unknown>,
  input: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  captures.persistedCanonicalEcdsaActivation = input;
  const planInput = input.planInput as Record<string, unknown> | undefined;
  return {
    ok: true,
    kind: 'initial_canonical_ecdsa_activation_persisted_v1',
    ceremonyId: String(input.ceremonyId || ''),
    journalId: String(planInput?.journalId || ''),
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
      case 'persistEmailOtpEd25519YaoRegistrationMaterial': {
        this.captures.emailOtpYaoCommit = request.payload;
        registrationEvents(this.captures)?.push('emailOtpYaoCommitCalled');
        if (this.captures.failEmailOtpYaoSeal) {
          throw new Error('Yao seal rejected the wallet session');
        }
        const scope = this.captures.emailOtpYaoRootScope as Record<string, any>;
        return {
          activeClientHandle: 'email-otp-ed25519-active-1',
          metadata: {
            kind: 'router_ab_ed25519_yao_active_client_v1',
            scope: {
              lifecycle_id: 'registration-ceremony',
              root_share_epoch: RUNTIME_POLICY_SCOPE.signingRootVersion,
              account_id: scope.walletId,
              threshold_session_id: 'registration-ceremony',
              signer_set_id: registrationNearEd25519BranchKey(scope.signerSlot),
              signing_worker_id: 'signing-worker-test',
              material_activation: {
                kind: 'mpc_material_activation_ref',
                activation_id: 'ed25519-activation:registration-ceremony',
                capability: 'ed25519-capability:registration-ceremony',
                material_owner: scope.walletId,
                key_binding: scope.nearEd25519SigningKeyId,
                lifecycle_binding: 'registration-ceremony',
                signing_worker: 'signing-worker-test',
              },
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

async function captureActivatedEmailOtpEd25519YaoMaterial(
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
    const walletKeys = await finalizeWalletRegistrationEcdsaSessionsOperation(input as any);
    captures.persistedEcdsaSessions = input;
    return walletKeys;
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
          setWalletNearProvisioningState: async () => undefined,
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
      setWalletAuthenticated: (input: Record<string, unknown>) => {
        captures.walletAuthenticated = input;
      },
      persistEmailOtpEd25519YaoCapabilityForRefreshInternal: async (input: unknown) => {
        captures.persistedEmailOtpEd25519YaoCapabilityForRefresh = input;
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
      prewarmEcdsaRegistrationCrypto: async () => {
        incrementCaptureCounter(captures, 'ecdsaCryptoPrewarmCalls');
        return { kind: 'succeeded', wasmInitMs: 1 };
      },
      setWalletNearProvisioningState: async (write: { walletId: string; status: string }) => {
        const writes = (captures.nearProvisioningWrites as { status: string }[] | undefined) ?? [];
        writes.push(write);
        captures.nearProvisioningWrites = writes;
        /* Fails only the status the test names, so a test can break the
           near_ready write while every earlier transition still persists. */
        if (captures.failNearProvisioningWriteForStatus === write.status) {
          throw new Error(`durable NEAR provisioning write unavailable: ${write.status}`);
        }
      },
      activateVerifiedNearEd25519YaoMaterial: captureActivatedEmailOtpEd25519YaoMaterial.bind(
        undefined,
        captures,
      ),
      upsertEd25519YaoPublicCapabilityLaneReference: async (input: unknown) => {
        captures.upsertedEd25519YaoCapabilityLane = input;
      },
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
          registrationRequestDigestB64u: CONTEXT_BINDING_32_B64U,
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
      persistInitialCanonicalEcdsaActivation: persistInitialCanonicalEcdsaActivationForTest.bind(
        undefined,
        captures,
      ),
      finalizeRouterAbEcdsaRegistrationActivation: async (args: Record<string, any>) => {
        const ecdsaFacts = captures.ecdsaRegistrationFacts as Record<string, any>;
        const publicCapability = parseRouterAbEcdsaDerivationPublicCapabilityV1(
          mockedEcdsaPublicCapability(ecdsaFacts),
        );
        const intent = captures.intent as Record<string, any>;
        const walletId = String(intent.walletId || WALLET_SUBJECT_ID);
        const walletAuthAuthority =
          intent.authMethod?.kind === 'email_otp'
            ? buildEmailOtpWalletAuthAuthority({
                walletId,
                provider: 'google',
                providerUserId: EMAIL_OTP_PROVIDER_SUBJECT,
                emailHashHex: await sha256HexUtf8('alice@example.com'),
              })
            : buildPasskeyWalletAuthAuthority({
                walletId,
                rpId: RP_ID,
                credentialIdB64u: 'registration-credential-id',
              });
        const authority = await walletAuthAuthorityRef({ authority: walletAuthAuthority });
        const parsedMaterialActivation = parseMpcMaterialActivationRef({
          kind: 'mpc_material_activation_ref',
          activationId: 'activation:registration-ceremony',
          capability: 'capability:registration-ceremony',
          materialOwner: 'material-owner:registration-ceremony',
          keyBinding: 'key-binding:registration-ceremony',
          lifecycleBinding: 'lifecycle-binding:registration-ceremony',
          signingWorker: 'signing-worker:registration-ceremony',
        });
        if (!parsedMaterialActivation.ok) {
          throw new Error(parsedMaterialActivation.error.message);
        }
        return {
          kind: 'router_ab_ecdsa_registration_activation_finalized_v1',
          journalId: String(args.journalId || args.ceremonyId || 'registration-ceremony'),
          authority,
          materialActivation: parsedMaterialActivation.value,
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
    if (path === '/wallets/register/setup') {
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
      /* Setup absorbed intent and start: it issues the challenge and prepares
         the ECDSA branch. Ed25519 admission is authority-bound and belongs to
         respond, so it is not produced here. */
      const setupEcdsaSigner = mockedRegistrationEvmFamilyEcdsaSigner(selection);
      return jsonResponse({
        ok: true,
        kind: setupEcdsaSigner
          ? mockedRegistrationNearEd25519Signer(selection)
            ? 'near_ed25519_and_evm_family_ecdsa'
            : 'evm_family_ecdsa'
          : 'near_ed25519',
        registrationCeremonyId: 'registration-ceremony',
        walletId: String(walletId),
        registrationIntentDigestB64u: digest,
        intent,
        signedSetup: 'signed-setup-token',
        ...(setupEcdsaSigner
          ? {
              ecdsa: await mockedRegistrationEcdsaStart({ intent }, setupEcdsaSigner).then(
                (ecdsa) => {
                  captures.ecdsaPrepare = ecdsa.prepare;
                  return ecdsa;
                },
              ),
            }
          : {}),
      });
    }
    if (path === '/wallets/register/respond') {
      captures.respondBody = body;
      const respondSelection = (captures.intent as { signerSelection?: unknown } | undefined)
        ?.signerSelection;
      const respondEd25519 = mockedRegistrationNearEd25519Signer(respondSelection as never);
      const respondEcdsa = mockedRegistrationEvmFamilyEcdsaSigner(respondSelection as never);
      /* Respond derives the authority-bound Yao admission — the proof exists
         by this leg, which is why it lives here and not in setup. Built through
         the shared factory so a shape change fails there, not here. */
      const deferredEd25519 = respondEd25519
        ? {
            ed25519: buildFixtureRespondEd25519DeferredWork({
              lifecycleId: 'registration-ceremony',
              rootShareEpoch: RUNTIME_POLICY_SCOPE.signingRootVersion,
              walletId: String((captures.intent as { walletId?: unknown } | undefined)?.walletId),
              signerSetId: registrationNearEd25519BranchKey(respondEd25519.signerSlot),
              signingWorkerId: 'signing-worker-test',
              nearEd25519SigningKeyId: String(
                captures.nearEd25519SigningKeyId || 'near-ed25519-registration-key',
              ),
              signingRootId: 'project_matrix:dev',
              participantIds: [1, 2],
              signerSlot: respondEd25519.signerSlot,
            }),
          }
        : {};
      if (body.ecdsa?.strictRegistration) {
        return jsonResponse({
          ok: true,
          registrationCeremonyId: body.registrationCeremonyId,
          kind: respondEd25519 ? 'near_ed25519_and_evm_family_ecdsa' : 'evm_family_ecdsa',
          ...deferredEd25519,
          ecdsa: {
            kind: 'router_ab_ecdsa_registration_forwarded_v1',
            strictResult: {
              result: 'forwarded',
              response: {
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
              keyHandle: 'ederivation-key-registration',
              relayerShareRetryCounter: 1,
              thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
              ethereumAddress: '0x3333333333333333333333333333333333333333',
              relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
              thresholdSessionId: String(entry.clientBootstrap.thresholdSessionId || ''),
              expiresAtMs: registrationEcdsaExpiresAtMs,
              expiresAt: new Date(registrationEcdsaExpiresAtMs).toISOString(),
            } as Record<string, unknown>;
            if (patchRegistrationBootstrap) {
              bootstrap = patchRegistrationBootstrap(bootstrap);
            }
            return { chainTarget: entry.chainTarget, bootstrap };
          })
        : null;
      if (!respondEcdsa) {
        return jsonResponse({
          ok: true,
          registrationCeremonyId: body.registrationCeremonyId,
          kind: 'near_ed25519',
          ...deferredEd25519,
        });
      }
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
    if (path === '/wallets/register/activate') {
      const activateWalletId = String((captures.intent as any)?.walletId || WALLET_SUBJECT_ID);
      const activateHasEcdsa = Boolean(
        mockedRegistrationEvmFamilyEcdsaSigner((captures.intent as any)?.signerSelection),
      );
      if (!activateHasEcdsa) {
        const pendingBody = await mockedNearEd25519FinalizeResponse(captures, activateWalletId);
        const {
          authorityScope: _authorityScope,
          accountProvisioning: _accountProvisioning,
          resolvedAccount: _resolvedAccount,
          ed25519: _ed25519,
          ...pendingActivationBody
        } = pendingBody;
        captures.finalizeBody = { ...body, kind: 'near_ed25519' };
        const pendingBodies = (captures.finalizeBodies as unknown[] | undefined) ?? [];
        pendingBodies.push({ ...body, kind: 'near_ed25519' });
        captures.finalizeBodies = pendingBodies;
        return jsonResponse({
          ...pendingActivationBody,
          nearProvisioning: { status: 'near_pending' },
        });
      }
      const ecdsaFacts = captures.ecdsaRegistrationFacts as Record<string, any>;
      const prepare = captures.ecdsaPrepare as Record<string, any>;
      let bootstrap = mockedEcdsaServerBootstrap(ecdsaFacts, prepare);
      captures.sharedRegistrationExpiresAtMs = bootstrap.expiresAtMs;
      const patchRegistrationBootstrap = captures.patchRegistrationBootstrap as
        | ((value: Record<string, unknown>) => Record<string, unknown>)
        | undefined;
      if (patchRegistrationBootstrap) {
        bootstrap = patchRegistrationBootstrap(bootstrap);
      }
      /* Activate absorbed finalize, so it is the terminal commit these tests
         track: recorded under the same capture the finalize route used, with
         the plan kind the commit covers. */
      const activateKind = 'evm_family_ecdsa';
      captures.finalizeBody = { ...body, kind: activateKind };
      const activateBodies = (captures.finalizeBodies as unknown[] | undefined) ?? [];
      activateBodies.push({ ...body, kind: activateKind });
      captures.finalizeBodies = activateBodies;
      /* Activate absorbed finalize, so it answers with the terminal wallet and
         the activation payload together — `ecdsa` carries the wallet keys the
         commit produced plus the receipt and bootstrap the client needs to
         bring the wallet online. */
      const activateBody = await mockedEcdsaFinalizeResponse(captures, activateWalletId);
      attachMockedEcdsaFinalizeWalletKeys(captures, activateWalletId, activateBody);
      const mixedRegistration = mockedRegistrationNearEd25519Signer(
        (captures.intent as any)?.signerSelection,
      );
      activateBody.registrationEstablishedSession = mockedRegistrationEstablishedEcdsaSession(
        activateWalletId,
        bootstrap,
        mixedRegistration
          ? {
              nearAccountId: String(captures.sponsoredNearAccountId || 'ab'.repeat(32)),
              nearEd25519SigningKeyId: String(
                captures.nearEd25519SigningKeyId || 'near-ed25519-registration-key',
              ),
              thresholdSessionId: 'registration-ceremony-session',
            }
          : undefined,
      );
      const activateEcdsa = (activateBody as Record<string, any>).ecdsa ?? {};
      (activateBody as Record<string, any>).ecdsa = {
        ...activateEcdsa,
        activation: mockedEcdsaActivationReceipt(ecdsaFacts),
        bootstrap,
      };
      if (mixedRegistration) {
        /* Mixed plans: the NEAR arm is still deferred at this point. */
        (activateBody as Record<string, any>).nearProvisioning = { status: 'pending' };
      }
      return jsonResponse(activateBody);
    }
    if (path === '/wallets/register/near-provisioning') {
      captures.finalizeBody = body;
      const finalizeBodies = (captures.finalizeBodies as unknown[] | undefined) ?? [];
      finalizeBodies.push(body);
      captures.finalizeBodies = finalizeBodies;
      if (body.ed25519 && captures.failDeferredEd25519Finalize) {
        return jsonResponse({ ok: false, message: 'deferred Ed25519 finalize unavailable' }, 503);
      }
      const responseWalletId = String((captures.intent as any)?.walletId || WALLET_SUBJECT_ID);
      const intentAuthMethod = (captures.intent as any)?.authMethod;
      if (body.ed25519) {
        const ed25519Signer = mockedRegistrationNearEd25519Signer(
          (captures.intent as any)?.signerSelection,
        );
        if (!ed25519Signer) {
          return jsonResponse({ ok: false, message: 'missing Ed25519 signer fixture' }, 400);
        }
        const nearEd25519SigningKeyId = String(
          captures.nearEd25519SigningKeyId || 'near-ed25519-registration-key',
        );
        const providerSubject = EMAIL_OTP_PROVIDER_SUBJECT;
        const passkeyAuth = intentAuthMethod?.kind === 'passkey';
        const authorityScope = passkeyAuth
          ? { kind: 'passkey_rp', rpId: RP_ID }
          : {
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
          /* Refactor 94 Phase 4+5: finalize commits one branch per call, so the
             relayer answers with the branch the request asked for. */
          kind: 'near_ed25519',
          authority: passkeyAuth
            ? buildPasskeyWalletAuthAuthority({
                walletId: responseWalletId,
                rpId: RP_ID,
                credentialIdB64u: 'registration-credential-id',
              })
            : buildEmailOtpWalletAuthAuthority({
                walletId: responseWalletId,
                provider: 'google',
                providerUserId: providerSubject,
                emailHashHex,
              }),
          authMethod: passkeyAuth
            ? {
                kind: 'passkey',
                credentialIdB64u: 'registration-credential-id',
                credentialPublicKeyB64u: 'registration-credential-public-key',
              }
            : {
                kind: 'email_otp',
                registrationAuthorityId: 'registration-attempt-1',
              },
          ...(passkeyAuth
            ? { rpId: RP_ID }
            : { appSessionJwt: String(intentAuthMethod?.appSessionJwt || '') }),
          authorityScope,
          /* Sponsored named provisioning resolves to the requested account,
             which is the walletId; implicit resolves to the derived key. */
          accountProvisioning: captures.sponsoredNearAccountId
            ? {
                kind: 'sponsored_named_account',
                requestedAccountId: String(captures.sponsoredNearAccountId),
                sponsor: 'relayer',
              }
            : {
                kind: 'implicit_account',
                accountIdSource: 'ed25519_public_key',
              },
          resolvedAccount: captures.sponsoredNearAccountId
            ? {
                kind: 'sponsored_named_account',
                nearAccountId: String(captures.sponsoredNearAccountId),
                nearEd25519SigningKeyId,
                transactionHash: 'sponsored-named-account-tx',
              }
            : {
                kind: 'implicit_account',
                nearAccountId: 'ab'.repeat(32),
                nearEd25519SigningKeyId,
              },
          ed25519: {
            signerSlot: ed25519Signer.signerSlot,
            nearAccountId: String(captures.sponsoredNearAccountId || 'ab'.repeat(32)),
            nearEd25519SigningKeyId,
            publicKey,
            relayerKeyId: 'signing-worker-test',
            keyVersion: 'router-ab-ed25519-yao-v1',
            recoveryExportCapable: true,
            participantIds: ed25519Signer.participantIds,
            thresholdSessionId: 'registration-ceremony-session',
            runtimePolicyScope: RUNTIME_POLICY_SCOPE,
            routerAbNormalSigning: {
              kind: 'router_ab_ed25519_normal_signing_v1',
              signingWorkerId: 'signing-worker-test',
            },
          },
        };
        responseBody.registrationEstablishedSession = mockedRegistrationEstablishedNearSession({
          walletId: responseWalletId,
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 1,
          nearAccountId: String(captures.sponsoredNearAccountId || 'ab'.repeat(32)),
          nearEd25519SigningKeyId,
          thresholdSessionId: 'registration-ceremony-session',
        });
        responseBody.nearProvisioning = { status: 'near_ready' };
        return jsonResponse(responseBody);
      }
      /* Only the deferred NEAR arm reaches this route now; the ECDSA terminal
         wallet is activate's answer. */
      return jsonResponse({ ok: false, message: 'near-provisioning requires ed25519 work' }, 400);
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

type RegisterWalletFetchMock = ReturnType<typeof installRegisterWalletFetch>;

async function withRegisterWalletFetch<T>(
  captures: Record<string, unknown>,
  run: (fetchMock: RegisterWalletFetchMock) => Promise<T>,
): Promise<T> {
  const fetchMock = installRegisterWalletFetch(captures);
  try {
    return await run(fetchMock);
  } finally {
    fetchMock.restore();
  }
}

async function withMockedIndexedDb<T>(run: () => Promise<T>): Promise<T> {
  const indexedDB = IndexedDBManager as unknown as Record<string, unknown>;
  const originalListProfileAuthenticators = indexedDB.listProfileAuthenticators;
  const originalResolveProfileAccountContext = indexedDB.resolveProfileAccountContext;
  const originalGetKeyMaterial = IndexedDBManager.getKeyMaterial;
  const originalStoreKeyMaterial = IndexedDBManager.storeKeyMaterial;
  const originalCreateOrMergeExactActive = walletSessionAuthorizations.createOrMergeExactActive;
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
  walletSessionAuthorizations.createOrMergeExactActive = async ({ incoming }) => incoming;
  try {
    return await run();
  } finally {
    indexedDB.listProfileAuthenticators = originalListProfileAuthenticators;
    indexedDB.resolveProfileAccountContext = originalResolveProfileAccountContext;
    (IndexedDBManager as any).getKeyMaterial = originalGetKeyMaterial;
    (IndexedDBManager as any).storeKeyMaterial = originalStoreKeyMaterial;
    walletSessionAuthorizations.createOrMergeExactActive = originalCreateOrMergeExactActive;
  }
}
test('evm.registerEvmWallet wraps ECDSA-only wallet registration', async () => {
  const captures: Record<string, unknown> = {};
  await withRegisterWalletFetch(captures, async (fetchMock) => {
    const signer = createLocalEvmCapability({
      getContext: () => createContext(captures),
    });
    const result = await withMockedIndexedDb(() =>
      signer.registerEvmWallet({
        chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1, networkSlug: 'ethereum' }],
        participantIds: [1, 2],
        authMethod: { kind: 'passkey', rpId: RP_ID },
        options: {},
      }),
    );

    expectRegistrationSuccess(result);
    expect(result).toMatchObject({
      success: true,
      capabilities: [
        {
          kind: 'evm_family_ecdsa',
          thresholdEcdsaEthereumAddress: '0x3333333333333333333333333333333333333333',
        },
      ],
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
  });
});

test('registerWallet orchestrates ECDSA-only wallet registration without NEAR profile work', async () => {
  const captures: Record<string, unknown> = {};
  await withRegisterWalletFetch(captures, async (fetchMock) => {
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
      capabilities: [
        {
          kind: 'evm_family_ecdsa',
          thresholdEcdsaEthereumAddress: '0x3333333333333333333333333333333333333333',
        },
      ],
    });
    /* Registration completes through the three-route protocol. */
    expect(fetchMock.paths).toEqual([
      '/wallets/register/setup',
      '/wallets/register/respond',
      '/wallets/register/activate',
    ]);
    expect(captures.registrationCredentialArgs).toMatchObject({
      walletId: WALLET_SUBJECT_ID,
      challengeB64u: captures.digest,
    });
    expectSingleRegistrationTouchIdPrompt(captures);
    expect(captures.finalizeBody).toMatchObject({
      ecdsa: {
        clientActivation: {
          derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
        },
      },
    });
    expect(captures.persistedEcdsaSessions).toMatchObject({
      session: {
        authority: {
          kind: 'wallet_auth_authority_ref',
          walletId: WALLET_SUBJECT_ID,
        },
      },
    });
    expect(captures.emailOtpYaoPrewarmCalls || 0).toBe(0);
  });
});

test('registerWallet overlaps Email OTP enrollment material with ECDSA registration', async () => {
  const events: string[] = [];
  const deferredEmailOtpEnrollmentMaterial = createDeferredPromise<Record<string, unknown>>();
  const captures: Record<string, unknown> = {
    registrationEvents: events,
    deferredEmailOtpEnrollmentMaterial,
    enableRegistrationPreparationModalClose: true,
  };
  await withRegisterWalletFetch(captures, async (fetchMock) => {
    const walletId = walletIdFromString('email-otp-ecdsa.testnet');
    const appSessionJwt = emailOtpRegistrationAppSessionJwt(String(walletId));
    try {
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
        predicate: () => fetchMock.paths.includes('/wallets/register/respond'),
      });

      expect(events).toContain('emailOtpEnrollmentMaterialStarted');
      expect(fetchMock.paths).toContain('/wallets/register/setup');
      expect(fetchMock.paths).not.toContain('/wallets/register/activate');
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
          'fetch:/wallets/register/setup',
          'fetch:/wallets/register/respond',
          'emailOtpEnrollmentMaterialResolved',
          'fetch:/wallets/register/activate',
        ]),
      );
      expect(events.indexOf('fetch:/wallets/register/setup')).toBeLessThan(
        events.indexOf('emailOtpEnrollmentMaterialResolved'),
      );
      expect(events.indexOf('fetch:/wallets/register/respond')).toBeLessThan(
        events.indexOf('emailOtpEnrollmentMaterialResolved'),
      );
      expect(events.indexOf('emailOtpEnrollmentMaterialResolved')).toBeLessThan(
        events.indexOf('fetch:/wallets/register/activate'),
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
      });
      expect(captures.persistedEcdsaSessions).toMatchObject({
        session: {
          authority: {
            kind: 'wallet_auth_authority_ref',
            walletId,
          },
        },
      });
    } finally {
      deferredEmailOtpEnrollmentMaterial.reject(new Error('test cleanup'));
    }
  });
});

test('registerWallet starts Email OTP Yao and ECDSA registration in parallel', async () => {
  const events: string[] = [];
  const deferredEmailOtpYaoStart = createDeferredPromise<void>();
  const captures: Record<string, unknown> = {
    registrationEvents: events,
    deferredEmailOtpYaoStart,
    enableRegistrationPreparationModalClose: true,
  };
  await withRegisterWalletFetch(captures, async (fetchMock) => {
    const walletId = walletIdFromString('email-otp-mixed.testnet');
    const appSessionJwt = emailOtpRegistrationAppSessionJwt(String(walletId));
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
      /* Refactor 94C: plans with an ECDSA branch kick the WASM prewarm during
       the auth window, fire-and-forget. */
      expect(captures.ecdsaCryptoPrewarmCalls).toBe(1);
      /* Refactor 94 Phase 4+5: the ECDSA branch finalizes without waiting for the
       Yao ceremony, so by this point commit #1 has already gone out — and it
       carries the ECDSA kind alone, never the removed combined kind. */
      await waitForTestCondition({
        label: 'ECDSA finalize to be issued before the Yao ceremony settles',
        predicate: () => captures.finalizeBody !== undefined,
      });
      expect(captures.finalizeBody).toMatchObject({ kind: 'evm_family_ecdsa' });

      deferredEmailOtpYaoStart.resolve(undefined);
      const result = await registration;

      expectRegistrationSuccess(result);
      /* Registration success now means ECDSA-ready. The NEAR branch is still
       settling, and the caller learns that from `nearProvisioning` rather than
       from registration having blocked on it. */
      expect(result).toMatchObject({
        success: true,
        kind: 'ecdsa_wallet_registered_near_pending',
        nearProvisioning: { status: 'pending' },
      });
      /* Commit #2 is deliberately not awaited by registration, so it lands after
       the ECDSA-ready result resolves rather than before it. */
      await waitForTestCondition({
        label: 'the deferred Ed25519 Yao commit to land after registration returned',
        predicate: () => events.includes('emailOtpYaoCommitCalled'),
      });
      expect(registrationEventCount(events, 'emailOtpYaoCommitCalled')).toBe(1);
      expect(events).not.toContain('emailOtpYaoDisposed');
      expect(captures.finalizeBody).toBeDefined();
    } finally {
      deferredEmailOtpYaoStart.reject(new Error('test cleanup'));
    }
  });
});

/* Refactor 94 Phase 4+5. Registration returns an ECDSA-ready wallet before the
   Ed25519 branch settles, so a terminal failure in the deferred commit must
   never fault the wallet that already resolved. */
async function runMixedEmailOtpRegistration(
  captures: Record<string, unknown>,
  nearSigner: RegistrationSignerRequest = nearEd25519RegistrationSigner(),
) {
  resetNearProvisioningRegistryForTests();
  const events = captures.registrationEvents as string[];
  const walletId = walletIdFromString('email-otp-mixed.testnet');
  const appSessionJwt = emailOtpRegistrationAppSessionJwt(String(walletId));
  const result = await withMockedIndexedDb(() =>
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
        nearSigner,
        evmFamilyRegistrationSigner([{ kind: 'evm', namespace: 'eip155', chainId: 1 }]),
      ),
      options: {},
      authenticatorOptions: {
        userVerification: UserVerificationPolicy.Preferred,
        originPolicy: { single: true, all_subdomains: false, multiple: [] },
      },
    }),
  );
  return { result, events, walletId };
}

test('registerWallet keeps the ECDSA wallet when the deferred Ed25519 finalize fails', async () => {
  const events: string[] = [];
  const captures: Record<string, unknown> = {
    registrationEvents: events,
    enableRegistrationPreparationModalClose: true,
    failDeferredEd25519Finalize: true,
  };
  await withRegisterWalletFetch(captures, async (fetchMock) => {
    try {
      const { result } = await runMixedEmailOtpRegistration(captures);

      /* The ECDSA wallet is durable and reported as such even though the NEAR
       branch could not be committed. */
      expectRegistrationSuccess(result);
      expect(result).toMatchObject({
        success: true,
        kind: 'ecdsa_wallet_registered_near_pending',
      });
      expect(
        String(ecdsaCapabilityFromRegistrationResult(result)?.thresholdEcdsaEthereumAddress ?? ''),
      ).not.toBe('');

      await waitForTestCondition({
        label: 'the deferred Ed25519 finalize to be attempted and rejected',
        predicate: () =>
          ((captures.finalizeBodies as unknown[] | undefined) ?? []).some(
            (entry) => (entry as { ed25519?: unknown }).ed25519 !== undefined,
          ),
      });
      /* A failed deferred commit must not seal Yao material. */
      expect(events).not.toContain('emailOtpYaoCommitCalled');
      /* Phase 6: the outcome is published, not swallowed. */
      await waitForTestCondition({
        label: 'NEAR provisioning to be published as retryable',
        predicate: () =>
          readNearProvisioningState(walletIdFromString('email-otp-mixed.testnet'))?.status ===
          'near_failed_retryable',
      });
    } finally {
    }
  });
});

test('registerWallet keeps the ECDSA wallet when the deferred Yao seal fails', async () => {
  const events: string[] = [];
  const captures: Record<string, unknown> = {
    registrationEvents: events,
    enableRegistrationPreparationModalClose: true,
    failEmailOtpYaoSeal: true,
  };
  await withRegisterWalletFetch(captures, async (fetchMock) => {
    try {
      const { result } = await runMixedEmailOtpRegistration(captures);

      expectRegistrationSuccess(result);
      expect(result).toMatchObject({
        success: true,
        kind: 'ecdsa_wallet_registered_near_pending',
      });

      /* The seal is reached and rejects; the wallet that already resolved is
       untouched by it. */
      await waitForTestCondition({
        label: 'the deferred Yao seal to be attempted',
        predicate: () => events.includes('emailOtpYaoCommitCalled'),
      });
      /* A seal failure leaves NEAR retryable, never ready. */
      await waitForTestCondition({
        label: 'NEAR provisioning to be published as retryable after the seal failed',
        predicate: () =>
          readNearProvisioningState(walletIdFromString('email-otp-mixed.testnet'))?.status ===
          'near_failed_retryable',
      });
      expect(
        readNearProvisioningState(walletIdFromString('email-otp-mixed.testnet'))?.status,
      ).not.toBe('near_ready');
    } finally {
    }
  });
});

test('a passkey mixed registration returns an ECDSA-ready wallet before Yao settles', async () => {
  const events: string[] = [];
  const captures: Record<string, unknown> = {
    registrationEvents: events,
    enableRegistrationPreparationModalClose: true,
  };
  await withRegisterWalletFetch(captures, async (fetchMock) => {
    resetNearProvisioningRegistryForTests();
    const result = await withMockedIndexedDb(() =>
      registerWallet({
        context: createContext(captures),
        authMethod: { kind: 'passkey', rpId: RP_ID },
        wallet: { kind: 'server_allocated' },
        signerSelection: registrationSignerSet(
          nearEd25519RegistrationSigner(),
          evmFamilyRegistrationSigner([{ kind: 'evm', namespace: 'eip155', chainId: 1 }]),
        ),
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: { single: true, all_subdomains: false, multiple: [] },
        },
      }),
    );

    /* Passkey takes the same split: ECDSA-ready first, NEAR still pending, and
       exactly one Touch ID prompt for the whole registration. */
    expectRegistrationSuccess(result);
    expect(result).toMatchObject({
      success: true,
      kind: 'ecdsa_wallet_registered_near_pending',
      nearProvisioning: { status: 'pending' },
    });
    expect(captures.storedEcdsaRegistration).toBeDefined();
    expectSingleRegistrationTouchIdPrompt(captures);
  });
});

/* Refactor 94 Phase 4+5. The whole point of the split is that the wallet is
   usable before the Yao ceremony settles, so this holds Yao open for the entire
   test and checks what the wallet can already do. */
test('the ECDSA wallet is durable and usable while the Yao ceremony is still blocked', async () => {
  const events: string[] = [];
  const deferredEmailOtpYaoStart = createDeferredPromise<void>();
  const captures: Record<string, unknown> = {
    registrationEvents: events,
    deferredEmailOtpYaoStart,
    enableRegistrationPreparationModalClose: true,
  };
  await withRegisterWalletFetch(captures, async (fetchMock) => {
    try {
      const { result } = await runMixedEmailOtpRegistration(captures);
      const walletId = walletIdFromString('email-otp-mixed.testnet');

      /* Yao has not been released, and registration has already returned. */
      expect(events).not.toContain('emailOtpYaoCommitCalled');
      expectRegistrationSuccess(result);
      expect(result).toMatchObject({
        success: true,
        kind: 'ecdsa_wallet_registered_near_pending',
        nearProvisioning: { status: 'pending' },
      });

      /* Commit #1 is durable: the ECDSA signer records were persisted, and the
       wallet carries a usable threshold address. */
      expect(captures.storedEcdsaRegistration).toBeDefined();
      const ecdsaCapability = ecdsaCapabilityFromRegistrationResult(result);
      const ecdsaAddress = String(ecdsaCapability?.thresholdEcdsaEthereumAddress ?? '');
      expect(ecdsaAddress).not.toBe('');
      expect(String(ecdsaCapability?.thresholdEcdsaPublicKeyB64u ?? '')).not.toBe('');

      /* The wallet is entered under its own id, not a NEAR account that does not
       exist yet. */
      expect(String((result as { walletId?: unknown }).walletId ?? '')).toBe(String(walletId));

      /* NEAR is still unfinished the whole time, which is what makes the above
       an assertion about the gap between the two commits. */
      expect(readNearProvisioningState(walletId)?.status).not.toBe('near_ready');
      expect(events).not.toContain('emailOtpYaoCommitCalled');
    } finally {
      deferredEmailOtpYaoStart.reject(new Error('test cleanup'));
    }
  });
});

test('a failed near_ready write never publishes near_ready', async () => {
  const events: string[] = [];
  const captures: Record<string, unknown> = {
    registrationEvents: events,
    enableRegistrationPreparationModalClose: true,
    /* Yao succeeds; only the durable near_ready write breaks. */
    failNearProvisioningWriteForStatus: 'near_ready',
  };
  await withRegisterWalletFetch(captures, async (fetchMock) => {
    try {
      const { result } = await runMixedEmailOtpRegistration(captures);
      const walletId = walletIdFromString('email-otp-mixed.testnet');

      /* The ECDSA wallet is durable and reported as such. */
      expectRegistrationSuccess(result);
      expect(result).toMatchObject({ success: true, kind: 'ecdsa_wallet_registered_near_pending' });
      expect(
        String(ecdsaCapabilityFromRegistrationResult(result)?.thresholdEcdsaEthereumAddress ?? ''),
      ).not.toBe('');

      /* The Yao ceremony itself succeeded, so this isolates the durable write. */
      await waitForTestCondition({
        label: 'the Yao seal to succeed before the durable write is attempted',
        predicate: () => events.includes('emailOtpYaoCommitCalled'),
      });
      await waitForTestCondition({
        label: 'provisioning to settle as retryable after the near_ready write failed',
        predicate: () => readNearProvisioningState(walletId)?.status === 'near_failed_retryable',
      });

      /* near_ready must never reach the page on an unpersisted success. */
      expect(readNearProvisioningState(walletId)?.status).not.toBe('near_ready');

      const writes = (captures.nearProvisioningWrites as { status: string }[]) ?? [];
      const attempted = writes.map((entry) => entry.status);
      expect(attempted).toContain('near_ready');
      expect(attempted).toContain('near_failed_retryable');
      /* The failed write is attempted before the retryable one that replaces it. */
      expect(attempted.indexOf('near_ready')).toBeLessThan(
        attempted.indexOf('near_failed_retryable'),
      );
    } finally {
    }
  });
});

test('sponsored NEAR provisioning keeps the wallet id as the account identity', async () => {
  const events: string[] = [];
  const captures: Record<string, unknown> = {
    registrationEvents: events,
    enableRegistrationPreparationModalClose: true,
  };
  captures.sponsoredNearAccountId = 'email-otp-mixed.testnet';
  await withRegisterWalletFetch(captures, async (fetchMock) => {
    try {
      await runMixedEmailOtpRegistration(
        captures,
        sponsoredNearEd25519RegistrationSigner('email-otp-mixed.testnet'),
      );
      const walletId = walletIdFromString('email-otp-mixed.testnet');

      await waitForTestCondition({
        label: 'deferred NEAR provisioning to reach near_ready',
        predicate: () => readNearProvisioningState(walletId)?.status === 'near_ready',
      });

      const state = readNearProvisioningState(walletId);
      /* A sponsored named account must not rename the wallet: the NEAR account
       identity stays the walletId registration was issued against. */
      expect(state).toMatchObject({ status: 'near_ready', nearAccountId: String(walletId) });

      /* The durable write agrees with what the page observed. */
      const readyWrite = (
        (captures.nearProvisioningWrites as { status: string; nearAccountId?: string }[]) ?? []
      ).find((entry) => entry.status === 'near_ready');
      expect(readyWrite?.nearAccountId).toBe(String(walletId));
    } finally {
    }
  });
});

test('the two registration commits carry distinct idempotency keys', async () => {
  const events: string[] = [];
  const captures: Record<string, unknown> = {
    registrationEvents: events,
    enableRegistrationPreparationModalClose: true,
  };
  await withRegisterWalletFetch(captures, async (fetchMock) => {
    try {
      await runMixedEmailOtpRegistration(captures);
      await waitForTestCondition({
        label: 'both registration commits to be issued',
        predicate: () => ((captures.finalizeBodies as unknown[] | undefined) ?? []).length >= 2,
      });

      const bodies = (
        captures.finalizeBodies as {
          kind?: string;
          idempotencyKey: string;
          ed25519?: unknown;
        }[]
      ).slice(0, 2);
      expect(bodies[0].kind).toBe('evm_family_ecdsa');
      expect(bodies[1].ed25519).toBeDefined();
      /* The server derives its side-effect key from {ceremonyId, idempotencyKey}.
       A shared key would replay commit #1's response instead of committing the
       Ed25519 branch, so exact retry of either commit can only converge while
       these stay distinct. */
      expect(bodies[0].idempotencyKey).not.toBe(bodies[1].idempotencyKey);
      expect(bodies[0].idempotencyKey).toBeTruthy();
      expect(bodies[1].idempotencyKey).toBeTruthy();
    } finally {
    }
  });
});

test('registerWallet does not start Yao when ECDSA fails before respond', async () => {
  const events: string[] = [];
  const captures: Record<string, unknown> = {
    registrationEvents: events,
    ecdsaCeremonyFailure: true,
    enableRegistrationPreparationModalClose: true,
  };
  await withRegisterWalletFetch(captures, async (fetchMock) => {
    const walletId = walletIdFromString('email-otp-mixed-yao-failure.testnet');
    const appSessionJwt = emailOtpRegistrationAppSessionJwt(String(walletId));
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
      const result = await registration;

      expect(result).toMatchObject({ success: false });
      expect(events).not.toContain('emailOtpYaoStartCalled');
      expect(events).not.toContain('emailOtpYaoDisposed');
      expect(captures.finalizeBody).toBeUndefined();
    } finally {
    }
  });
});

test('registerWallet does not start Yao while ECDSA respond is unresolved', async () => {
  const events: string[] = [];
  const deferredEcdsaCeremony = createDeferredPromise<void>();
  const captures: Record<string, unknown> = {
    registrationEvents: events,
    deferredEcdsaCeremony,
    ecdsaCeremonyFailure: true,
    enableRegistrationPreparationModalClose: true,
  };
  await withRegisterWalletFetch(captures, async (fetchMock) => {
    const walletId = walletIdFromString('email-otp-mixed-ecdsa-failure.testnet');
    const appSessionJwt = emailOtpRegistrationAppSessionJwt(String(walletId));
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
        label: 'ECDSA registration to start before its deferred failure',
        predicate: () => events.includes('ecdsaCeremonyStarted'),
      });
      expect(events).not.toContain('ecdsaCeremonyResolved');
      expect(events).not.toContain('emailOtpYaoStartCalled');
      expect(captures.finalizeBody).toBeUndefined();

      deferredEcdsaCeremony.resolve(undefined);
      const result = await registration;

      expect(result).toMatchObject({ success: false });
      expect(events).toContain('ecdsaCeremonyResolved');
      expect(events).not.toContain('emailOtpYaoStartCalled');
      expect(events).not.toContain('emailOtpYaoDisposed');
      expect(captures.finalizeBody).toBeUndefined();
    } finally {
      deferredEcdsaCeremony.reject(new Error('test cleanup'));
    }
  });
});

test('registerWallet completes an Email OTP Ed25519-only wallet after Yao', async () => {
  const captures: Record<string, unknown> = {
    emailOtpYaoPrewarmFailure: true,
  };
  await withRegisterWalletFetch(captures, async (fetchMock) => {
    const walletId = walletIdFromString('email-otp-ed25519.testnet');
    const appSessionJwt = emailOtpRegistrationAppSessionJwt(String(walletId));
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
        kind: 'wallet_registered',
        walletId,
      });
      expect(fetchMock.paths.slice(0, 3)).toEqual([
        '/wallets/register/setup',
        '/wallets/register/respond',
        '/wallets/register/activate',
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
        'persistEmailOtpEd25519YaoRegistrationMaterial',
      ]);
      expect(captures.emailOtpYaoPrewarmCalls).toBe(1);
      expect(captures.emailOtpYaoStart).toMatchObject({
        walletId: String(walletId),
        providerSubject: EMAIL_OTP_PROVIDER_SUBJECT,
        registrationAuthorityId: 'registration-attempt-1',
        bearerToken: 'signed-setup-token',
      });
      expect(fetchMock.paths).toContain('/wallets/register/near-provisioning');
      expect(captures.emailOtpYaoWorkerOperations).toEqual([
        'bindEmailOtpEd25519YaoRoot',
        'startEmailOtpEd25519YaoRegistration',
        'persistEmailOtpEd25519YaoRegistrationMaterial',
      ]);
      expect(captures.finalizeBody).toMatchObject({
        ed25519: {
          activationReference: {
            kind: 'router_ab_ed25519_yao_activation_reference_v1',
            lifecycle_id: 'registration-ceremony',
          },
        },
      });
      expect((captures.finalizeBodies as Record<string, unknown>[])[0]).toMatchObject({
        emailOtpEnrollment: {
          clientUnlockPublicKeyB64u: 'email-otp-client-unlock-public-key',
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
      expect(captures.rememberedEmailOtpAppSession).toEqual({
        kind: 'email_otp_app_session_binding',
        walletId,
        providerSubject: EMAIL_OTP_PROVIDER_SUBJECT,
        appSessionJwt,
      });
      expect(captures.emailOtpAppSessionRememberedBeforeAfterCall).toBe(true);
    } finally {
    }
  });
});

test('Email OTP Ed25519-only registration reports an identity mismatch', async () => {
  const captures: Record<string, unknown> = {
    emailOtpEd25519FinalizePublicKey: `ed25519:${base58Encode(new Uint8Array(32).fill(9))}`,
  };
  await withRegisterWalletFetch(captures, async (fetchMock) => {
    const walletId = walletIdFromString('email-otp-ed25519-mismatch.testnet');
    const appSessionJwt = emailOtpRegistrationAppSessionJwt(String(walletId));
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
        error: expect.stringMatching(/Ed25519 Yao finalize returned mismatched signer identity/),
      });
      expect(readNearProvisioningState(walletId)?.status).not.toBe('near_ready');
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
    }
  });
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
  await withRegisterWalletFetch(captures, async (fetchMock) => {
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
      error: expect.stringMatching(/derivationClientSharePublicKey33B64u mismatch/),
    });
    expect(captures.finalizeBody).toBeDefined();
    expect(captures.persistedEcdsaSessions).toBeUndefined();
    expect(captures.storedEcdsaRegistration).toBeUndefined();
  });
});

function installAddSignerFetch(captures: Record<string, unknown>) {
  const originalFetch = globalThis.fetch;
  const paths: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const path = url.pathname;
    paths.push(path);
    const body = init?.body ? JSON.parse(String(init.body)) : {};
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
            threshold_session_id: ceremonyId,
            signer_set_id: registrationNearEd25519BranchKey(selection.signerSlot),
            signing_worker_id: 'signing-worker-test',
            material_activation: {
              kind: 'mpc_material_activation_ref',
              activation_id: `ed25519-activation:${ceremonyId}`,
              capability: `ed25519-capability:${ceremonyId}`,
              material_owner: body.intent.walletId,
              key_binding: nearEd25519SigningKeyId,
              lifecycle_binding: ceremonyId,
              signing_worker: 'signing-worker-test',
            },
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
      captures.activateBody = body;
      let bootstrap = mockedEcdsaServerBootstrap(ecdsaFacts, prepare);
      const patchAddSignerBootstrap = captures.patchAddSignerBootstrap as
        | ((value: Record<string, unknown>) => Record<string, unknown>)
        | undefined;
      if (patchAddSignerBootstrap) {
        bootstrap = patchAddSignerBootstrap(bootstrap);
      }
      return jsonResponse({
        ok: true,
        addSignerCeremonyId: body.addSignerCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_activated_v1',
          /* The receipt echoes the digest the client sent, as the Router
             forwarder does — the client asserts the two are equal before it
             finalizes the activation journal. */
          activation: mockedEcdsaActivationReceipt(
            ecdsaFacts,
            body.ecdsa.expectedActivationRequestDigest,
          ),
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

type AddSignerFetchMock = ReturnType<typeof installAddSignerFetch>;

async function withAddSignerFetch<T>(
  captures: Record<string, unknown>,
  run: (fetchMock: AddSignerFetchMock) => Promise<T>,
): Promise<T> {
  const fetchMock = installAddSignerFetch(captures);
  try {
    return await run(fetchMock);
  } finally {
    fetchMock.restore();
  }
}

test('addWalletSigner orchestrates later ECDSA from an Ed25519 wallet', async () => {
  const captures: Record<string, unknown> = {};
  await withAddSignerFetch(captures, async (fetchMock) => {
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
      capabilities: [
        {
          kind: 'evm_family_ecdsa',
          thresholdEcdsaEthereumAddress: '0x3333333333333333333333333333333333333333',
        },
      ],
    });
    expect(fetchMock.paths).toEqual([
      `/wallets/${WALLET_SUBJECT_ID}/signers/intent`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/start`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/derivation/respond`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/derivation/activate`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/finalize`,
    ]);
    /* No preparation round trip: the digest activate carries is the one the
       client computed from the canonical add-signer activation command. */
    const activateBody = captures.activateBody as Record<string, any>;
    const respondBody = captures.respondBody as Record<string, any>;
    expect(activateBody.ecdsa.expectedActivationRequestDigest.bytes).toEqual(
      Array.from(
        base64UrlDecode(
          await computeWalletAddSignerEcdsaActivationRequestDigestB64u({
            addSignerCeremonyId: activateBody.addSignerCeremonyId,
            activationCorrelationId: activateBody.ecdsa.activationCorrelationId,
            publicFacts: activateBody.ecdsa.publicFacts,
          }),
        ),
      ),
    );
    expect(typeof respondBody.ecdsa.requestDigestB64u).toBe('string');
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
      session: {
        authority: {
          kind: 'wallet_auth_authority_ref',
          walletId: WALLET_SUBJECT_ID,
        },
      },
    });
  });
});

test('addWalletSigner rejects invalid ECDSA respond bootstrap before finalize', async () => {
  const captures: Record<string, unknown> = {
    patchAddSignerBootstrap: (bootstrap: Record<string, unknown>) => ({
      ...bootstrap,
      contextBinding32B64u: 'mismatched-context-binding',
    }),
  };
  await withAddSignerFetch(captures, async (fetchMock) => {
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
      error: expect.stringMatching(/contextBinding32B64u mismatch/),
    });
    expect(captures.finalizeBody).toBeUndefined();
    expect(captures.persistedEcdsaSessions).toBeUndefined();
    expect(captures.storedEcdsa).toBeUndefined();
  });
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
  await withAddSignerFetch(captures, async (fetchMock) => {
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
      `/wallets/${WALLET_SUBJECT_ID}/signers/intent`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/start`,
    ]);
    expect(captures.finalizeBody).toBeUndefined();
    expect(captures.storedEd25519).toBeUndefined();
  });
});
