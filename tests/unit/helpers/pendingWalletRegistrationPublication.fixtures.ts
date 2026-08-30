import {
  buildActiveWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
} from '@shared/authorization/walletAuthority';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import {
  parseDeviceId,
  parsePrincipalId,
  parseTenantId,
} from '@shared/authorization/capabilityKinds';
import { parseWalletSessionOperationCredentialV1 } from '@shared/device-linking/parsers';
import { buildExactAdministeredSignerManifestV1 } from '@shared/device-linking/delegatedActivationPlan';
import { parseEd25519PublicKeyB64u } from '@shared/passkey-custody/primitives';
import { parseCorrelationId, parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  parseEmailOtpChallengeId,
  parseEmailOtpProviderUserId,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWalletKeyId,
  parseVerifiedEmailAddress,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type WalletId,
} from '@shared/utils/domainIds';
import { sha256HexUtf8 } from '@shared/utils/digests';
import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import {
  isEmailOtpWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { SIGNER_AUTH_METHODS, SIGNER_KINDS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import type {
  ActiveWalletAuthorityV1,
  WalletSignerActivationSetV1,
} from '@shared/authorization/walletAuthority';
import type {
  ProfileAuthenticatorRecord,
  LocalWalletAuthMethodRecord,
} from '@/core/indexedDB/passkeyClientDB.types';
import type { KeyMaterialRecord } from '@/core/indexedDB/keyMaterial.types';
import type { ActivateAccountSignerInput } from '@/core/indexedDB/accountSignerLifecycle';
import {
  prepareWalletEd25519RegistrationProjectionPublication,
  prepareWalletEmailOtpEd25519RegistrationPublication,
} from '@/core/signingEngine/flows/registration/accountLifecycle';
import { toAccountId } from '@/core/types/accountIds';
import { WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND } from '@/core/signingEngine/walletCustody/ed25519SeedMaterial';
import {
  buildPendingWalletRegistrationCommitV1,
  type PendingWalletRegistrationCommitV1,
} from '@/core/indexedDB/pendingWalletRegistrationCommit';
import type {
  PublishPendingWalletRegistrationCommitInputV1,
  StoreWalletRegistrationPublicationInputV1,
} from '@/core/indexedDB/seamsWalletDB/repositories';
import { buildWalletCustodyCommitPayloadFixture } from './passkeyCustodyEnvelope.fixtures';
import { buildMpcMaterialActivationRefFixture } from './ecdsaMaterialRef.fixtures';
import { buildExactWalletSessionAuthorizationFixture } from './exactWalletSessionAuthorization.fixtures';
import { projectActiveWalletSession } from '../../../packages/wallet-server/src/authorization/domain';
import { fixtureRouterAbEcdsaActivationFacts } from '../../helpers/routerAbSigningRuntimeTestUtils';

function unwrap<T>(result: { ok: true; value: T } | { ok: false; error: { message: string } }): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function digest(fill: number) {
  return parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(fill)));
}

function buildSignerActivation(walletId: string): {
  activation: ActivateAccountSignerInput;
  keyMaterial: KeyMaterialRecord;
} {
  const signerId = 'ed25519:publication-signer';
  const account = {
    profileId: walletId,
    chainIdKey: 'near:testnet',
    accountAddress: 'publication.testnet',
    accountModel: 'near-native',
  };
  const metadata = {
    walletId,
    nearAccountId: 'publication.testnet',
    nearEd25519SigningKeyId: 'near-publication-key',
    relayerKeyId: 'relayer-publication-key',
    keyVersion: 'v1',
    operationalPublicKey: 'ed25519:publication-public-key',
  };
  const activation: ActivateAccountSignerInput = {
    account,
    signer: {
      signerId,
      signerType: 'threshold',
      signerKind: SIGNER_KINDS.thresholdEd25519,
      signerAuthMethod: SIGNER_AUTH_METHODS.passkey,
      signerSource: SIGNER_SOURCES.passkeyRegistration,
      metadata,
    },
    activationPolicy: { mode: 'fail_if_occupied', signerSlot: 1 },
    preferredSlot: 1,
    mutation: { routeThroughOutbox: false },
  };
  return {
    activation,
    keyMaterial: {
      profileId: walletId,
      signerSlot: 1,
      chainIdKey: account.chainIdKey,
      accountAddress: account.accountAddress,
      keyKind: 'threshold_share_v1',
      algorithm: 'ed25519',
      publicKey: metadata.operationalPublicKey,
      signerId,
      timestamp: 100,
      schemaVersion: 1,
      payload: {
        walletId,
        nearAccountId: metadata.nearAccountId,
        nearEd25519SigningKeyId: metadata.nearEd25519SigningKeyId,
        relayerKeyId: metadata.relayerKeyId,
        keyVersion: metadata.keyVersion,
      },
    },
  };
}

function buildSignerActivationSet(walletId: WalletId): WalletSignerActivationSetV1 {
  const walletKeyId = unwrap(parseWalletKeyId('wallet-key:publication'));
  const materialActivation = buildMpcMaterialActivationRefFixture('publication-authority');
  const signer = {
    kind: 'exact_administered_ed25519_signer_v1' as const,
    keyFamily: 'ed25519' as const,
    walletId,
    walletKeyId,
    registeredPublicKeyB64u: parseEd25519PublicKeyB64u(
      base64UrlEncode(new Uint8Array(32).fill(17)),
    ),
  };
  const activationSet = buildWalletSignerActivationSetV1({
    manifest: buildExactAdministeredSignerManifestV1([signer]),
    materialActivations: {
      keyFamilies: ['ed25519'],
      ed25519: materialActivation,
    },
  });
  return activationSet;
}

type PublicationFixtureVariant =
  | {
      readonly authKind: 'passkey';
      readonly operation: 'near_provisioning';
      readonly keyFamilies: 'ed25519';
      readonly includeSigner: true;
    }
  | {
      readonly authKind: 'email_otp';
      readonly operation: 'near_provisioning';
      readonly keyFamilies: 'ed25519';
      readonly includeSigner: true;
    }
  | {
      readonly authKind: 'passkey';
      readonly operation: 'registration_activate';
      readonly keyFamilies: 'ecdsa_secp256k1';
      readonly includeSigner: false;
    }
  | {
      readonly authKind: 'passkey';
      readonly operation: 'registration_activate';
      readonly keyFamilies: 'mixed';
      readonly includeSigner: false;
    };

export type PendingWalletRegistrationPublicationFixture = {
  readonly input: PublishPendingWalletRegistrationCommitInputV1;
  readonly walletId: string;
  readonly authorityId: string;
  readonly walletAuthMethodId: string;
  readonly profileId: string;
};

type ActiveWalletAuthMethodRecordV2 = Extract<
  WalletAuthMethodRecordV2,
  { readonly status: 'active' }
>;

export async function buildPendingWalletRegistrationPublicationFixture(
  options: PublicationFixtureVariant,
): Promise<PendingWalletRegistrationPublicationFixture> {
  const { authKind, operation, keyFamilies, includeSigner } = options;

  const walletId = unwrap(parseWalletId(`wallet:r103f-publication-${authKind}`));
  const authorityId = unwrap(parseWalletAuthorityId(`authority:r103f-publication-${authKind}`));
  const walletAuthMethodId = unwrap(
    parseWalletAuthMethodId(`wallet-auth-method:r103f-publication-${authKind}`),
  );
  const rpId = unwrap(parseWebAuthnRpId('publication.example.test'));
  const credentialIdB64u = unwrap(
    parseWebAuthnCredentialIdB64u(`credential:r103f-publication-${authKind}`),
  );
  const credentialPublicKeyB64u = base64UrlEncode(new Uint8Array(32).fill(23));
  const activationSet = buildSignerActivationSet(walletId);
  const activationSetDigestB64u = await computeWalletSignerActivationSetDigestB64u(activationSet);
  const authorityDraft: ActiveWalletAuthorityV1 = {
    kind: 'wallet_authority_v1',
    authorityId,
    walletId,
    principal: {
      kind: 'owner_device',
      deviceId: unwrap(parseDeviceId('device:r103f-publication')),
    },
    provenance: { kind: 'wallet_registration' },
    permissions: buildFullOwnerPermissionsV1(),
    signerActivations: activationSet,
    signerActivationSetDigestB64u: activationSetDigestB64u,
    authorityDigestB64u: digest(31),
    revocationEpoch: 0,
    createdAtMs: 10,
    updatedAtMs: 10,
    state: 'active',
    activatedAtMs: 20,
  };
  const foundingAuthority = buildActiveWalletAuthorityV1({
    ...authorityDraft,
    authorityDigestB64u: await computeWalletAuthorityDigestB64u(authorityDraft),
  });

  let authority: WalletAuthAuthority;
  let initialAuthMethod: LocalWalletAuthMethodRecord;
  let foundingAuthMethod: ActiveWalletAuthMethodRecordV2;
  let pendingAuth: PendingWalletRegistrationCommitV1['auth'];
  let authenticators: readonly ProfileAuthenticatorRecord[];
  if (authKind === 'passkey') {
    authority = {
      walletId,
      factor: { kind: 'passkey', credentialIdB64u },
      verifier: { kind: 'webauthn', rpId },
      bindingId: walletAuthMethodId,
    };
    initialAuthMethod = {
      version: 'wallet_auth_method_v1',
      kind: 'passkey',
      status: 'active',
      localStatus: 'synced',
      walletId,
      rpId,
      credentialIdB64u,
      credentialPublicKeyB64u,
      counter: 0,
      createdAtMs: 10,
      updatedAtMs: 20,
    };
    const candidate = buildWalletAuthMethodRecordV2({
      version: 'wallet_auth_method_v2',
      walletAuthMethodId,
      walletId,
      walletAuthorityId: authorityId,
      kind: 'passkey',
      status: 'active',
      rpId,
      credentialIdB64u,
      credentialPublicKeyB64u,
      counter: 0,
      createdAtMs: 10,
      updatedAtMs: 20,
      activatedAtMs: 20,
    });
    if (candidate.status !== 'active') throw new Error('passkey fixture method is not active');
    foundingAuthMethod = candidate;
    pendingAuth = { kind: 'passkey', rpId, credentialIdB64u, transports: ['internal'] };
    authenticators = [
      {
        profileId: String(walletId),
        signerSlot: 1,
        credentialId: String(credentialIdB64u),
        credentialPublicKey: new Uint8Array(32).fill(23),
        registered: new Date(10).toISOString(),
        syncedAt: new Date(20).toISOString(),
      },
    ];
  } else {
    const email = unwrap(parseVerifiedEmailAddress('publication@example.test'));
    const emailHashHex = await sha256HexUtf8(email);
    const registrationAuthorityId = unwrap(parseEmailOtpChallengeId('challenge:r103f-publication'));
    const providerSubject = unwrap(parseEmailOtpProviderUserId('provider:r103f-publication'));
    authority = {
      walletId,
      factor: { kind: 'email_otp', provider: 'email', providerUserId: providerSubject },
      verifier: { kind: 'email_otp_wallet_auth_method', emailHashHex },
      bindingId: walletAuthMethodId,
    };
    initialAuthMethod = {
      version: 'wallet_auth_method_v1',
      kind: 'email_otp',
      status: 'active',
      localStatus: 'synced',
      walletId,
      emailHashHex,
      registrationAuthorityId,
      authority,
      createdAtMs: 10,
      updatedAtMs: 20,
    };
    const candidate = buildWalletAuthMethodRecordV2({
      version: 'wallet_auth_method_v2',
      walletAuthMethodId,
      walletId,
      walletAuthorityId: authorityId,
      kind: 'email_otp',
      status: 'active',
      emailHashHex,
      registrationAuthorityId,
      createdAtMs: 10,
      updatedAtMs: 20,
      activatedAtMs: 20,
    });
    if (candidate.status !== 'active') throw new Error('Email OTP fixture method is not active');
    foundingAuthMethod = candidate;
    pendingAuth = {
      kind: 'email_otp',
      email,
      registrationAuthorityId,
      providerSubject,
      enrollment: {
        enrollmentSealKeyVersion: 'enrollment-key-v1',
        serverSealedFactorCiphertextB64u: 'sealed-factor-publication',
        clientUnlockPublicKeyB64u: 'unlock-key-publication',
        unlockKeyVersion: 'unlock-key-v1',
      },
    };
    authenticators = [];
  }

  const localMaterialBase = {
    custodyCommit: buildWalletCustodyCommitPayloadFixture({
      walletId: String(walletId),
      keySet: keyFamilies === 'ed25519' ? 'near_ed25519_v1' : 'evm_family_ecdsa_v1',
      origin: 'join',
    }),
    ed25519: {
      activationReference: {
        kind: 'router_ab_ed25519_yao_activation_reference_v1' as const,
        lifecycle_id: 'lifecycle:r103f-publication',
        session_id: Array.from({ length: 32 }, (_, index) => index),
      },
      localMaterial: {
        b64u: 'sealed-ed25519-publication',
        nonceB64u: 'nonce-ed25519-publication',
        applicationBindingDigestB64u: 'binding-ed25519-publication',
      },
      metadata: {
        materialActivation: buildMpcMaterialActivationRefFixture('publication-authority'),
        registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(17)),
        signingWorkerVerifyingShareB64u: base64UrlEncode(new Uint8Array(32).fill(19)),
        stateEpoch: '1',
        signingWorkerId: 'signing-worker-publication',
        participantIds: [1, 2] as const,
        nearEd25519SigningKeyId: 'near-publication-key',
        signerSlot: 1,
      },
    },
  };
  const ed25519LocalMaterial: Extract<
    PendingWalletRegistrationCommitV1['localMaterial'],
    { readonly keyFamilies: readonly ['ed25519'] }
  > = {
    keyFamilies: ['ed25519'] as const,
    ...localMaterialBase,
  };
  const ecdsaLocalMaterial: Extract<
    PendingWalletRegistrationCommitV1['localMaterial'],
    { readonly keyFamilies: readonly ['ecdsa_secp256k1'] }
  > = {
    keyFamilies: ['ecdsa_secp256k1'] as const,
    custodyCommit: localMaterialBase.custodyCommit,
    ecdsa: {
      activationJournalId: parseCorrelationId('correlation:r103f-publication'),
      clientActivation: fixtureRouterAbEcdsaActivationFacts(),
      activationRequestDigestB64u: digest(41),
    },
  };
  const mixedLocalMaterial: Extract<
    PendingWalletRegistrationCommitV1['localMaterial'],
    { readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'] }
  > = {
    keyFamilies: ['ed25519', 'ecdsa_secp256k1'] as const,
    custodyCommit: localMaterialBase.custodyCommit,
    ed25519: localMaterialBase.ed25519,
    ecdsa: {
      activationJournalId: parseCorrelationId('correlation:r103f-publication'),
      clientActivation: fixtureRouterAbEcdsaActivationFacts(),
      activationRequestDigestB64u: digest(41),
    },
  };
  const localMaterial: PendingWalletRegistrationCommitV1['localMaterial'] =
    keyFamilies === 'ed25519'
      ? ed25519LocalMaterial
      : keyFamilies === 'ecdsa_secp256k1'
        ? ecdsaLocalMaterial
        : mixedLocalMaterial;
  const registrationCeremonyId = `ceremony:r103f-publication-${authKind}`;
  const idempotencyKey = `idempotency:r103f-publication-${authKind}`;
  const pending =
    operation === 'near_provisioning'
      ? buildPendingWalletRegistrationCommitV1({
          kind: 'pending_wallet_registration_commit_v1',
          operation: 'near_provisioning',
          registrationCeremonyId,
          idempotencyKey,
          walletId,
          walletAuthMethodId,
          signedSetup: 'signed-setup:r103f-publication',
          auth: pendingAuth,
          localMaterial: ed25519LocalMaterial,
          createdAtMs: 10,
          updatedAtMs: 20,
        })
      : buildPendingWalletRegistrationCommitV1({
          kind: 'pending_wallet_registration_commit_v1',
          operation: 'registration_activate',
          registrationCeremonyId,
          idempotencyKey,
          walletId,
          walletAuthMethodId,
          signedSetup: 'signed-setup:r103f-publication',
          auth: pendingAuth,
          localMaterial,
          createdAtMs: 10,
          updatedAtMs: 20,
        });
  const signerData = buildSignerActivation(String(walletId));
  const registration: StoreWalletRegistrationPublicationInputV1 = {
    profiles: [
      {
        profileId: String(walletId),
        defaultSignerSlot: 1,
        ...(authKind === 'passkey'
          ? { passkeyCredential: { id: 'credential-publication', rawId: String(credentialIdB64u) } }
          : {}),
      },
    ],
    initialAuthMethod,
    authenticators,
    signerActivations: includeSigner ? [signerData.activation] : [],
    keyMaterials: includeSigner ? [signerData.keyMaterial] : [],
    lastProfileState: { profileId: String(walletId), activeSignerSlot: 1, scope: null },
  };
  const issuedSession = buildExactWalletSessionAuthorizationFixture({
    label: `pending-publication-${authKind}-${operation}`,
    tenantId: unwrap(parseTenantId(`tenant:pending-publication-${authKind}`)),
    principalId: unwrap(parsePrincipalId(`principal:pending-publication-${authKind}`)),
    authority: foundingAuthority,
    walletAuthMethodId: foundingAuthMethod.walletAuthMethodId,
    issuedAtMs: 10,
    expiresAtMs: 10_000,
    remainingUses: 3,
  });
  const operationCredential = parseWalletSessionOperationCredentialV1({
    kind: 'opaque_wallet_session_operation_credential_v1',
    token: `wst_${base64UrlEncode(new Uint8Array(32).fill(authKind === 'passkey' ? 29 : 30))}`,
    walletSessionId: issuedSession.session.walletSessionId,
  });
  return {
    walletId: String(walletId),
    authorityId: String(authorityId),
    walletAuthMethodId: String(walletAuthMethodId),
    profileId: String(walletId),
    input: {
      pending,
      authority,
      foundingAuthority: { authority: foundingAuthority, authMethod: foundingAuthMethod },
      request: {
        operation,
        registrationCeremonyId,
        idempotencyKey,
        walletId,
        walletAuthMethodId,
      },
      walletSessionPublication:
        keyFamilies === 'mixed'
          ? { kind: 'credential_free_projection' }
          : {
              kind: 'issued',
              walletSession: projectActiveWalletSession(issuedSession),
              operationCredential,
            },
      registration,
    },
  };
}

export function buildPasskeyNearProvisioningPublicationFixture(): Promise<PendingWalletRegistrationPublicationFixture> {
  return buildPendingWalletRegistrationPublicationFixture({
    authKind: 'passkey',
    operation: 'near_provisioning',
    keyFamilies: 'ed25519',
    includeSigner: true,
  });
}

export function buildEmailNearProvisioningPublicationFixture(): Promise<PendingWalletRegistrationPublicationFixture> {
  return buildPendingWalletRegistrationPublicationFixture({
    authKind: 'email_otp',
    operation: 'near_provisioning',
    keyFamilies: 'ed25519',
    includeSigner: true,
  });
}

export function buildEcdsaActivationPublicationFixture(): Promise<PendingWalletRegistrationPublicationFixture> {
  return buildPendingWalletRegistrationPublicationFixture({
    authKind: 'passkey',
    operation: 'registration_activate',
    keyFamilies: 'ecdsa_secp256k1',
    includeSigner: false,
  });
}

export function buildMixedActivationPublicationFixture(): Promise<PendingWalletRegistrationPublicationFixture> {
  return buildPendingWalletRegistrationPublicationFixture({
    authKind: 'passkey',
    operation: 'registration_activate',
    keyFamilies: 'mixed',
    includeSigner: false,
  });
}

export async function buildPasskeyNearProvisioningProductionPublicationFixture(): Promise<PendingWalletRegistrationPublicationFixture> {
  const fixture = await buildPasskeyNearProvisioningPublicationFixture();
  const pendingAuth = fixture.input.pending.auth;
  if (pendingAuth.kind !== 'passkey') {
    throw new Error('Passkey publication fixture has a non-passkey pending authority');
  }
  const registration = prepareWalletEd25519RegistrationProjectionPublication({
    walletId: fixture.input.request.walletId,
    nearAccountId: toAccountId('publication.testnet'),
    nearEd25519SigningKeyId: 'near-publication-key',
    rpId: pendingAuth.rpId,
    credentialIdB64u: pendingAuth.credentialIdB64u,
    transports: pendingAuth.transports,
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(23)),
    signerSlot: 1,
    operationalPublicKey: 'ed25519:publication-public-key',
    relayerKeyId: 'relayer-publication-key',
    keyVersion: 'v1',
    participantIds: [1, 2],
    custodyMaterial: {
      binding: {
        kind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
        applicationBindingDigestB64u: 'binding-ed25519-publication',
        registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(17)),
        participantIds: [1, 2],
        stateEpoch: '1',
        walletId: String(fixture.input.request.walletId),
        nearAccountId: 'publication.testnet',
        nearEd25519SigningKeyId: 'near-publication-key',
        signerSlot: 1,
        signingWorkerId: 'signing-worker-publication',
        signingWorkerVerifyingShareB64u: base64UrlEncode(new Uint8Array(32).fill(19)),
      },
      sealed: {
        ciphertextB64u: 'sealed-ed25519-publication',
        nonceB64u: 'nonce-ed25519-publication',
      },
    },
  });
  return {
    walletId: fixture.walletId,
    authorityId: fixture.authorityId,
    walletAuthMethodId: fixture.walletAuthMethodId,
    profileId: fixture.profileId,
    input: {
      pending: fixture.input.pending,
      authority: fixture.input.authority,
      foundingAuthority: fixture.input.foundingAuthority,
      request: fixture.input.request,
      walletSessionPublication: fixture.input.walletSessionPublication,
      registration,
    },
  };
}

export async function buildEmailOtpNearProvisioningProductionPublicationFixture(): Promise<PendingWalletRegistrationPublicationFixture> {
  const fixture = await buildEmailNearProvisioningPublicationFixture();
  const pendingAuth = fixture.input.pending.auth;
  const authority = fixture.input.authority;
  if (pendingAuth.kind !== 'email_otp' || !isEmailOtpWalletAuthAuthority(authority)) {
    throw new Error('Email OTP publication fixture has a mismatched authority');
  }
  const registration = await prepareWalletEmailOtpEd25519RegistrationPublication({
    walletId: fixture.input.request.walletId,
    nearAccountId: toAccountId('publication.testnet'),
    nearEd25519SigningKeyId: 'near-publication-key',
    email: pendingAuth.email,
    registrationAuthorityId: pendingAuth.registrationAuthorityId,
    authority,
    signerSlot: 1,
    operationalPublicKey: 'ed25519:publication-public-key',
    relayerKeyId: 'relayer-publication-key',
    keyVersion: 'v1',
    participantIds: [1, 2],
    custodyMaterial: {
      binding: {
        kind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
        applicationBindingDigestB64u: 'binding-ed25519-publication',
        registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(17)),
        participantIds: [1, 2],
        stateEpoch: '1',
        walletId: String(fixture.input.request.walletId),
        nearAccountId: 'publication.testnet',
        nearEd25519SigningKeyId: 'near-publication-key',
        signerSlot: 1,
        signingWorkerId: 'signing-worker-publication',
        signingWorkerVerifyingShareB64u: base64UrlEncode(new Uint8Array(32).fill(19)),
      },
      sealed: {
        ciphertextB64u: 'sealed-ed25519-publication',
        nonceB64u: 'nonce-ed25519-publication',
      },
    },
  });
  return {
    walletId: fixture.walletId,
    authorityId: fixture.authorityId,
    walletAuthMethodId: fixture.walletAuthMethodId,
    profileId: fixture.profileId,
    input: {
      pending: fixture.input.pending,
      authority: fixture.input.authority,
      foundingAuthority: fixture.input.foundingAuthority,
      request: fixture.input.request,
      walletSessionPublication: fixture.input.walletSessionPublication,
      registration,
    },
  };
}
