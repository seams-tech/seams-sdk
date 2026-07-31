import { expect, test } from '@playwright/test';
import {
  parseWalletRegistrationFinalizeResponse,
  type WalletRegistrationEcdsaWalletKey,
} from '@/core/rpcClients/relayer/walletRegistration';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  createThresholdEcdsaBootstrapFixture,
  thresholdEcdsaBootstrapPublicFactsFixture,
} from './helpers/ecdsaBootstrap.fixtures';

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
  const publicFacts = thresholdEcdsaBootstrapPublicFactsFixture(bootstrap);
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
    thresholdEcdsaPublicKeyB64u: bootstrap.thresholdEcdsaKeyRef.thresholdEcdsaPublicKeyB64u,
    thresholdOwnerAddress: OWNER_ADDRESS,
    relayerKeyId: backendBinding.relayerKeyId,
    relayerVerifyingShareB64u: bootstrap.thresholdEcdsaKeyRef.relayerVerifyingShareB64u,
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

test('registration finalize parser retains validated Ed25519 material facts', () => {
  const authority = buildPasskeyWalletAuthAuthority({
    walletId: WALLET_ID,
    rpId: RP_ID,
    credentialIdB64u: CREDENTIAL_ID,
  });
  const parsed = parseWalletRegistrationFinalizeResponse({
    expectedKind: 'near_ed25519',
    value: {
      ok: true,
      walletId: WALLET_ID,
      authority,
      rpId: RP_ID,
      authMethod: {
        kind: 'passkey',
        credentialIdB64u: CREDENTIAL_ID,
        credentialPublicKeyB64u: 'credential-public-key',
      },
      kind: 'near_ed25519',
      authorityScope: { kind: 'passkey_rp', rpId: RP_ID },
      accountProvisioning: {
        kind: 'sponsored_named_account',
        requestedAccountId: 'alice.testnet',
        sponsor: 'relayer',
      },
      resolvedAccount: {
        kind: 'sponsored_named_account',
        nearAccountId: 'alice.testnet',
        nearEd25519SigningKeyId: 'ed25519:key',
        transactionHash: 'near-transaction',
      },
      ed25519: {
        signerSlot: 1,
        nearAccountId: 'alice.testnet',
        nearEd25519SigningKeyId: 'ed25519:key',
        publicKey: 'ed25519:key',
        relayerKeyId: 'worker-1',
        keyVersion: 'router-ab-ed25519-yao-v1',
        recoveryExportCapable: true,
        participantIds: [1, 2],
        runtimePolicyScope: {
          orgId: 'org-1',
          projectId: 'project-1',
          envId: 'env-1',
          signingRootVersion: 'root-v1',
        },
        routerAbNormalSigning: {
          kind: 'router_ab_ed25519_normal_signing_v1',
          signingWorkerId: 'worker-1',
        },
      },
    },
  });

  expect(parsed.kind).toBe('near_ed25519');
  if (parsed.kind !== 'near_ed25519') throw new Error('expected Ed25519 finalize result');
  expect(parsed.ed25519.runtimePolicyScope).toEqual({
    orgId: 'org-1',
    projectId: 'project-1',
    envId: 'env-1',
    signingRootVersion: 'root-v1',
  });
  expect(parsed.ed25519.routerAbNormalSigning.signingWorkerId).toBe('worker-1');
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
