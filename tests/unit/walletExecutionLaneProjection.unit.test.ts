import { expect, test } from '@playwright/test';
import {
  projectActiveOwnerWalletExecutionLane,
  resolveActiveOwnerWalletExecutionLane,
  resolveWalletAuthMethodIdForAuthority,
  type WalletExecutionLaneProjectionSource,
} from '../../packages/sdk-server-ts/src/core/signingLanes/WalletExecutionLaneProjection';
import { normalizeWalletAuthMethod } from '../../packages/sdk-server-ts/src/core/d1WalletAuthMethodStore';
import type { WalletSignerRecord } from '../../packages/sdk-server-ts/src/core/WalletStore';
import { walletAuthMethodRecordId } from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseProviderSubject, parseWalletId } from '../../packages/shared-ts/src/utils/domainIds';
import { routerAbMpcMaterialActivationRefFromWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { createWalletEcdsaSignerRecord } from './helpers/walletRegistrationSigner.fixtures';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
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

function passkeyAuthMethod(status: 'active' | 'revoked' = 'active') {
  const record = normalizeWalletAuthMethod({
    version: 'wallet_auth_method_v1',
    kind: 'passkey',
    status,
    walletId,
    rpId: 'wallet.example.test',
    credentialIdB64u: 'credential-r101',
    credentialPublicKeyB64u: 'public-key-r101',
    counter: 0,
    createdAtMs: now,
    updatedAtMs: now,
  });
  if (!record) throw new Error('passkey auth fixture is invalid');
  return record;
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
      walletAuthMethodId: walletAuthMethodRecordId(authMethod),
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
      walletAuthMethodId: walletAuthMethodRecordId(authMethod),
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
      walletAuthMethodId: walletAuthMethodRecordId(authMethod),
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
        walletAuthMethodId: walletAuthMethodRecordId(authMethod),
        authMethod,
        signers: [signer, conflict],
        expectedMaterialActivation: materialActivation,
      }),
    ).rejects.toThrow();
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
      walletAuthMethodId: walletAuthMethodRecordId(revoked),
      expectedMaterialActivation: materialActivation,
    });
    expect(revokedResult).toEqual({ kind: 'refused', reason: 'auth_method_inactive' });

    const missingResult = await resolveActiveOwnerWalletExecutionLane({
      source: source({ authMethods: [passkeyAuthMethod()], signers: [] }),
      walletId,
      walletAuthMethodId: walletAuthMethodRecordId(passkeyAuthMethod()),
      expectedMaterialActivation: materialActivation,
    });
    expect(missingResult).toEqual({ kind: 'refused', reason: 'signer_missing' });
  });

  test('resolves passkey and Email OTP authority references to one exact active method', async () => {
    const passkey = passkeyAuthMethod();
    if (passkey.kind !== 'passkey') throw new Error('passkey fixture is required');
    const passkeyAuthority = buildPasskeyWalletAuthAuthority({
      walletId,
      rpId: passkey.rpId,
      credentialIdB64u: passkey.credentialIdB64u,
    });
    const passkeyId = await resolveWalletAuthMethodIdForAuthority({
      walletId,
      authorityRef: await walletAuthAuthorityRef({ authority: passkeyAuthority }),
      authSource: { kind: 'passkey', credentialIdB64u: passkey.credentialIdB64u },
      authMethods: [passkey],
    });
    expect(passkeyId).toBe(walletAuthMethodRecordId(passkey));

    const email = normalizeWalletAuthMethod({
      version: 'wallet_auth_method_v1',
      kind: 'email_otp',
      status: 'active',
      walletId,
      emailHashHex: 'email-hash-r101',
      registrationAuthorityId: 'registration-authority-r101',
      createdAtMs: now,
      updatedAtMs: now,
    });
    if (!email || email.kind !== 'email_otp') throw new Error('Email OTP fixture is invalid');
    const emailAuthority = buildEmailOtpWalletAuthAuthority({
      walletId,
      provider: 'google',
      providerUserId: 'google:provider-user-r101',
      emailHashHex: email.emailHashHex,
    });
    const providerSubject = resultValue(parseProviderSubject('google:provider-user-r101'));
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
    expect(emailId).toBe(walletAuthMethodRecordId(email));
  });
});
