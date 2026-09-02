import { expect, test } from '@playwright/test';
import {
  projectActiveOwnerWalletExecutionLane,
  resolveActiveOwnerWalletExecutionLane,
  resolveWalletAuthMethodIdForAuthority,
  type WalletExecutionLaneProjectionSource,
} from '../../packages/wallet-server/src/core/signingLanes/WalletExecutionLaneProjection';
import type { WalletSignerRecord } from '../../packages/wallet-server/src/core/WalletStore';
import {
  buildYaoEd25519WalletSignerRecord,
  ed25519NearPublicKeyFromBytes,
} from '../../packages/wallet-server/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoWalletSigner';
import { buildWalletAuthMethodRecordV2 } from '../../packages/shared-ts/src/utils/registrationIntent';
import {
  parseProviderSubject,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { routerAbMpcMaterialActivationRefFromWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { createWalletEcdsaSignerRecord } from './helpers/walletRegistrationSigner.fixtures';
import { buildRouterAbEd25519YaoCapabilityReplacementFixture } from './helpers/routerAbEd25519YaoRecoveryRequestScoped.fixtures';
import {
  walletAuthAuthorityRef,
} from '../../packages/shared-ts/src/utils/walletAuthAuthority';

function resultValue<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

const walletId = resultValue(parseWalletId('wallet:r101-projection'));
const now = 1_900_000_000_000;

function passkeyAuthMethod(status: 'active' | 'revoked' = 'active', methodWalletId = walletId) {
  return buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: resultValue(parseWalletAuthMethodId('wallet-auth-method:r101-projection')),
    walletAuthorityId: resultValue(parseWalletAuthorityId('wallet-authority:r101-projection')),
    kind: 'passkey',
    status,
    walletId: methodWalletId,
    rpId: 'wallet.example.test',
    credentialIdB64u: 'credential-r101',
    credentialPublicKeyB64u: 'public-key-r101',
    counter: 0,
    createdAtMs: now,
    updatedAtMs: now,
    activatedAtMs: now,
    ...(status === 'revoked' ? { revokedAtMs: now + 1 } : {}),
  });
}

function source(input: {
  readonly authMethods?: readonly ReturnType<typeof passkeyAuthMethod>[];
  readonly signers?: readonly WalletSignerRecord[];
}): WalletExecutionLaneProjectionSource {
  return {
    listWalletAuthMethods: async () => input.authMethods ?? [],
    listWalletSigners: async () => input.signers ?? [],
  };
}

test.describe('R101 owner wallet execution lane projection', () => {
  test('projects one active auth method and exact EVM-family signer into stable owner records', async () => {
    const signer = createWalletEcdsaSignerRecord({ walletId, now });
    const authMethod = passkeyAuthMethod();
    const materialActivation = routerAbMpcMaterialActivationRefFromWire(
      signer.walletKey.publicCapability.material_activation,
    );
    const result = await resolveActiveOwnerWalletExecutionLane({
      source: source({ authMethods: [authMethod], signers: [signer] }),
      walletId,
      walletAuthMethodId: authMethod.walletAuthMethodId,
      expectedMaterialActivation: materialActivation,
    });

    expect(result.kind).toBe('projected');
    if (result.kind !== 'projected') return;
    expect(result.projection.walletKey).toMatchObject({
      keyFamily: 'ecdsa_secp256k1',
      walletId,
      evmAddress: signer.walletKey.thresholdOwnerAddress,
    });
    expect(result.projection.lane).toMatchObject({
      laneKind: 'owner_passkey',
      walletAuthMethodId: authMethod.walletAuthMethodId,
      lifecycle: { state: 'active', revocationEpoch: 0 },
      ownerParticipantContinuity: {
        signerId: `ecdsa-key:${signer.walletKey.keyHandle}`,
        participantIds: [1, 2],
      },
    });
    expect(result.projection.materialActivation).toEqual(materialActivation);
  });

  test('collapses matching chain-target rows and refuses conflicting activation receipts', async () => {
    const signer = createWalletEcdsaSignerRecord({ walletId, now });
    const secondChain = {
      ...signer,
      signerId: 'ecdsa:eip155:10',
      chainTargetKey: 'eip155:10',
      chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 10 } as const,
      walletKey: {
        ...signer.walletKey,
        chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 10 } as const,
      },
    };
    const authMethod = passkeyAuthMethod();
    const materialActivation = routerAbMpcMaterialActivationRefFromWire(
      signer.walletKey.publicCapability.material_activation,
    );
    const projection = await projectActiveOwnerWalletExecutionLane({
      walletId,
      walletAuthMethodId: authMethod.walletAuthMethodId,
      authMethod,
      signers: [signer, secondChain],
      expectedMaterialActivation: materialActivation,
    });
    expect(projection.walletKey.keyFamily).toBe('ecdsa_secp256k1');

    const conflict = {
      ...secondChain,
      activationReceipt: {
        ...secondChain.activationReceipt,
        server_generation: 'conflicting-generation',
      },
    };
    await expect(
      projectActiveOwnerWalletExecutionLane({
        walletId,
        walletAuthMethodId: authMethod.walletAuthMethodId,
        authMethod,
        signers: [signer, conflict],
        expectedMaterialActivation: materialActivation,
      }),
    ).rejects.toThrow();
  });

  test('projects an exact Ed25519 Yao signer without synthesizing HPKE participants', async () => {
    const fixture = buildRouterAbEd25519YaoCapabilityReplacementFixture();
    const edWalletId = resultValue(parseWalletId(fixture.walletId));
    const capability = fixture.next;
    const application = capability.admissionRequest.application_binding;
    const scope = capability.admissionRequest.scope;
    const signer = buildYaoEd25519WalletSignerRecord({
      walletId: edWalletId,
      nearAccountId: fixture.nearAccountId,
      nearEd25519SigningKeyId: fixture.nearSigningKeyId,
      thresholdSessionId: scope.threshold_session_id,
      signerSlot: application.key_creation_signer_slot,
      publicKey: ed25519NearPublicKeyFromBytes(
        capability.activationResult.public_receipt.registered_public_key,
      ),
      signingWorkerId: fixture.signingWorkerId,
      keyVersion: 'yao-recovery-key-v1',
      participantIds: capability.admissionRequest.participant_ids,
      signingRootId: application.signing_root_id,
      signingRootVersion: scope.root_share_epoch,
      runtimePolicyScope: capability.runtimePolicyScope,
      activeYaoCapability: capability,
      custodyKeyManifestDigestB64u: Buffer.alloc(32, 21).toString('base64url'),
      now,
    });
    const authMethod = passkeyAuthMethod('active', edWalletId);
    const materialActivation = routerAbMpcMaterialActivationRefFromWire(
      capability.activationResult.public_receipt.material_activation,
    );
    const result = await resolveActiveOwnerWalletExecutionLane({
      source: source({ authMethods: [authMethod], signers: [signer] }),
      walletId: edWalletId,
      walletAuthMethodId: authMethod.walletAuthMethodId,
      expectedMaterialActivation: materialActivation,
    });

    expect(result.kind).toBe('projected');
    if (result.kind !== 'projected') return;
    expect(result.projection.walletKey).toMatchObject({
      keyFamily: 'ed25519',
      walletId: edWalletId,
      nearEd25519SigningKeyId: fixture.nearSigningKeyId,
    });
    expect(result.projection.lane).toMatchObject({
      laneKind: 'owner_passkey',
      ownerParticipantContinuity: {
        signerId: signer.signerId,
        participantIds: signer.participantIds,
        signingWorkerId: fixture.signingWorkerId,
      },
    });
    expect('holderParticipant' in result.projection.lane).toBe(false);
    expect('serverParticipant' in result.projection.lane).toBe(false);
  });

  test('refuses revoked authorization and missing exact material before projection', async () => {
    const signer = createWalletEcdsaSignerRecord({ walletId, now });
    const revoked = passkeyAuthMethod('revoked');
    const materialActivation = routerAbMpcMaterialActivationRefFromWire(
      signer.walletKey.publicCapability.material_activation,
    );
    const revokedResult = await resolveActiveOwnerWalletExecutionLane({
      source: source({ authMethods: [revoked], signers: [signer] }),
      walletId,
      walletAuthMethodId: revoked.walletAuthMethodId,
      expectedMaterialActivation: materialActivation,
    });
    expect(revokedResult).toEqual({ kind: 'refused', reason: 'auth_method_inactive' });

    const missingResult = await resolveActiveOwnerWalletExecutionLane({
      source: source({ authMethods: [passkeyAuthMethod()], signers: [] }),
      walletId,
      walletAuthMethodId: passkeyAuthMethod().walletAuthMethodId,
      expectedMaterialActivation: materialActivation,
    });
    expect(missingResult).toEqual({ kind: 'refused', reason: 'signer_missing' });
  });

  test('resolves passkey and Email OTP authority references to one exact active method', async () => {
    const passkey = passkeyAuthMethod();
    if (passkey.kind !== 'passkey') throw new Error('passkey fixture is required');
    const passkeyAuthority = {
      walletId,
      factor: { kind: 'passkey' as const, credentialIdB64u: passkey.credentialIdB64u },
      verifier: { kind: 'webauthn' as const, rpId: passkey.rpId },
      bindingId: passkey.walletAuthMethodId,
    };
    const passkeyId = await resolveWalletAuthMethodIdForAuthority({
      walletId,
      authorityRef: await walletAuthAuthorityRef({ authority: passkeyAuthority }),
      authSource: { kind: 'passkey', credentialIdB64u: passkey.credentialIdB64u },
      authMethods: [passkey],
    });
    expect(passkeyId).toBe(passkey.walletAuthMethodId);
    const canonicalCredentialBindingId = resultValue(
      parseWalletAuthMethodId(`passkey:${passkey.rpId}:${passkey.credentialIdB64u}`),
    );
    const canonicalAuthority = {
      walletId,
      factor: { kind: 'passkey' as const, credentialIdB64u: passkey.credentialIdB64u },
      verifier: { kind: 'webauthn' as const, rpId: passkey.rpId },
      bindingId: canonicalCredentialBindingId,
    };
    expect(
      await resolveWalletAuthMethodIdForAuthority({
        walletId,
        authorityRef: await walletAuthAuthorityRef({ authority: canonicalAuthority }),
        authSource: { kind: 'passkey', credentialIdB64u: passkey.credentialIdB64u },
        authMethods: [passkey],
      }),
    ).toBeNull();

    const email = buildWalletAuthMethodRecordV2({
      version: 'wallet_auth_method_v2',
      walletAuthMethodId: resultValue(parseWalletAuthMethodId('wallet-auth-method:r101-email')),
      walletAuthorityId: resultValue(parseWalletAuthorityId('wallet-authority:r101-projection')),
      kind: 'email_otp',
      status: 'active',
      walletId,
      emailHashHex: 'email-hash-r101',
      registrationAuthorityId: 'registration-authority-r101',
      createdAtMs: now,
      updatedAtMs: now,
      activatedAtMs: now,
    });
    if (email.kind !== 'email_otp') throw new Error('Email OTP fixture is invalid');
    const providerSubject = resultValue(parseProviderSubject('google:provider-user-r101'));
    const emailAuthority = {
      walletId,
      factor: {
        kind: 'email_otp' as const,
        provider: 'google' as const,
        providerUserId: providerSubject,
      },
      verifier: {
        kind: 'email_otp_wallet_auth_method' as const,
        emailHashHex: email.emailHashHex,
      },
      bindingId: email.walletAuthMethodId,
    };
    const emailId = await resolveWalletAuthMethodIdForAuthority({
      walletId,
      authorityRef: await walletAuthAuthorityRef({ authority: emailAuthority }),
      authSource: {
        kind: 'oidc_provider',
        providerId: 'google_oidc',
        providerSubject,
      },
      authMethods: [email],
    });
    expect(emailId).toBe(email.walletAuthMethodId);
  });
});
