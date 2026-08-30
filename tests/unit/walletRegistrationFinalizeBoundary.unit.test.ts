import { expect, test } from '@playwright/test';
import {
  parseWalletRegistrationFinalizeResponse,
  type WalletRegistrationEcdsaWalletKey,
} from '@/core/rpcClients/relayer/walletRegistration';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import {
  createThresholdEcdsaBootstrapFixture,
  thresholdEcdsaBootstrapPublicFactsFixture,
} from './helpers/ecdsaBootstrap.fixtures';
import { buildEcdsaActivationPublicationFixture } from './helpers/pendingWalletRegistrationPublication.fixtures';
import { isPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';

const OWNER_ADDRESS = `0x${'41'.repeat(20)}`;

function registrationFinalizeEcdsaWalletKey(walletId: string): WalletRegistrationEcdsaWalletKey {
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: walletId,
    chain: 'tempo',
    ethereumAddress: OWNER_ADDRESS,
  });
  const backendBinding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
  const publicFacts = thresholdEcdsaBootstrapPublicFactsFixture(bootstrap);
  const publicIdentity = publicFacts.publicCapability.public_identity;
  return {
    keyScope: 'evm-family',
    chainTarget: bootstrap.thresholdEcdsaKeyRef.chainTarget,
    walletId,
    evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
      walletId,
      signingRootId: publicFacts.signingRootId,
      signingRootVersion: publicFacts.signingRootVersion,
    }),
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

async function validFinalizeResponse() {
  const publication = await buildEcdsaActivationPublicationFixture();
  const authority = publication.input.authority;
  if (!isPasskeyWalletAuthAuthority(authority)) {
    throw new Error('expected passkey registration publication fixture');
  }
  const foundingAuthMethod = publication.input.foundingAuthority.authMethod;
  if (foundingAuthMethod.kind !== 'passkey') {
    throw new Error('expected passkey founding auth method fixture');
  }
  const walletId = publication.walletId;
  const walletKey = registrationFinalizeEcdsaWalletKey(walletId);
  return {
    ok: true,
    walletId,
    authority,
    foundingAuthority: publication.input.foundingAuthority.authority,
    foundingAuthMethod,
    rpId: String(authority.verifier.rpId),
    authMethod: {
      kind: 'passkey',
      credentialIdB64u: String(authority.factor.credentialIdB64u),
      credentialPublicKeyB64u: foundingAuthMethod.credentialPublicKeyB64u,
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

test('registration finalize parser validates the complete ECDSA response', async () => {
  const parsed = parseWalletRegistrationFinalizeResponse({
    value: await validFinalizeResponse(),
    expectedKind: 'evm_family_ecdsa',
  });

  expect(parsed.kind).toBe('evm_family_ecdsa');
  expect(parsed.ecdsa.walletKeys[0]?.thresholdOwnerAddress).toBe(OWNER_ADDRESS);
});

test('registration finalize parser retains validated Ed25519 material facts', async () => {
  const { ecdsa: _ecdsa, ...finalizeResponse } = await validFinalizeResponse();
  const parsed = parseWalletRegistrationFinalizeResponse({
    expectedKind: 'near_ed25519',
    value: {
      ok: true,
      ...finalizeResponse,
      kind: 'near_ed25519',
      authorityScope: { kind: 'passkey_rp', rpId: finalizeResponse.rpId },
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
        thresholdSessionId: 'threshold-session-1',
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
  expect(parsed.ed25519.thresholdSessionId).toBe('threshold-session-1');
  expect(parsed.ed25519.routerAbNormalSigning.signingWorkerId).toBe('worker-1');
});

test('registration finalize parser rejects nested server material', async () => {
  const response = await validFinalizeResponse();
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

test('registration finalize parser rejects public capability substitution', async () => {
  const response = await validFinalizeResponse();
  response.ecdsa.walletKeys[0]!.contextBinding32B64u = 'substituted-context';

  expect(() =>
    parseWalletRegistrationFinalizeResponse({
      value: response,
      expectedKind: 'evm_family_ecdsa',
    }),
  ).toThrow('public capability mismatch');
});
