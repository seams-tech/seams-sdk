import { expect, test } from '@playwright/test';
import {
  parseWalletRegistrationFinalizeResponse,
  type WalletRegistrationEcdsaWalletKey,
} from '@/core/rpcClients/relayer/walletRegistration';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';

const WALLET_ID = 'registration-finalize-boundary';
const RP_ID = 'wallet.example.test';
const CREDENTIAL_ID = 'credential-registration-finalize';
const OWNER_ADDRESS = `0x${'41'.repeat(20)}`;

function registrationFinalizeEcdsaWalletKey(): WalletRegistrationEcdsaWalletKey {
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: WALLET_ID,
    chain: 'tempo',
    ethereumAddress: OWNER_ADDRESS,
  });
  const backendBinding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
  if (!backendBinding || backendBinding.materialKind !== 'role_local_ready_state_blob') {
    throw new Error('registration finalize fixture requires role-local public facts');
  }
  const publicFacts = backendBinding.ecdsaRoleLocalReadyRecord.publicFacts;
  const publicIdentity = publicFacts.publicCapability.public_identity;
  return {
    keyScope: 'evm-family',
    chainTarget: bootstrap.thresholdEcdsaKeyRef.chainTarget,
    walletId: WALLET_ID,
    evmFamilySigningKeySlotId: bootstrap.thresholdEcdsaKeyRef.evmFamilySigningKeySlotId,
    keyHandle: bootstrap.thresholdEcdsaKeyRef.keyHandle,
    ecdsaThresholdKeyId: bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId,
    signingRootId: publicFacts.signingRootId,
    signingRootVersion: publicFacts.signingRootVersion,
    thresholdEcdsaPublicKeyB64u: bootstrap.keygen.thresholdEcdsaPublicKeyB64u,
    thresholdOwnerAddress: OWNER_ADDRESS,
    relayerKeyId: backendBinding.relayerKeyId,
    relayerVerifyingShareB64u: bootstrap.keygen.relayerVerifyingShareB64u,
    contextBinding32B64u: publicIdentity.context_binding_b64u,
    derivationClientSharePublicKey33B64u: publicIdentity.derivation_client_share_public_key33_b64u,
    clientShareRetryCounter: publicIdentity.client_share_retry_counter,
    relayerShareRetryCounter: publicIdentity.server_share_retry_counter,
    participantIds: [1, 2],
    publicCapability: publicFacts.publicCapability,
  };
}

function validFinalizeResponse() {
  const walletKey = registrationFinalizeEcdsaWalletKey();
  return {
    ok: true,
    walletId: WALLET_ID,
    authority: buildPasskeyWalletAuthAuthority({
      walletId: WALLET_ID,
      rpId: RP_ID,
      credentialIdB64u: CREDENTIAL_ID,
    }),
    rpId: RP_ID,
    authMethod: {
      kind: 'passkey',
      credentialIdB64u: CREDENTIAL_ID,
      credentialPublicKeyB64u: 'credential-public-key',
    },
    kind: 'evm_family_ecdsa',
    ecdsa: { walletKeys: [walletKey] },
    registrationDiagnostics: {
      kind: 'wallet_registration_route_diagnostics_v1',
      route: 'wallets_register_finalize',
      entries: [{ name: 'registerFinalizeTotalMs', durationMs: 12 }],
    },
  };
}

test('registration finalize parser validates the complete ECDSA response', () => {
  const parsed = parseWalletRegistrationFinalizeResponse({
    value: validFinalizeResponse(),
    expectedKind: 'evm_family_ecdsa',
  });

  expect(parsed.kind).toBe('evm_family_ecdsa');
  expect(parsed.ecdsa.walletKeys[0]?.thresholdOwnerAddress).toBe(OWNER_ADDRESS);
});

test('registration finalize parser rejects nested server material', () => {
  const response = validFinalizeResponse();
  const walletKey = response.ecdsa.walletKeys[0] as WalletRegistrationEcdsaWalletKey & {
    serverShare?: string;
  };
  walletKey.serverShare = 'forbidden';

  expect(() =>
    parseWalletRegistrationFinalizeResponse({
      value: response,
      expectedKind: 'evm_family_ecdsa',
    }),
  ).toThrow('unexpected serverShare');
});

test('registration finalize parser rejects public capability substitution', () => {
  const response = validFinalizeResponse();
  response.ecdsa.walletKeys[0]!.contextBinding32B64u = 'substituted-context';

  expect(() =>
    parseWalletRegistrationFinalizeResponse({
      value: response,
      expectedKind: 'evm_family_ecdsa',
    }),
  ).toThrow('public capability mismatch');
});
