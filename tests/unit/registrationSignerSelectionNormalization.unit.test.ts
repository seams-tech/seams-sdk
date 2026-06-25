import { expect, test } from '@playwright/test';
import { AuthService } from '@server/core/AuthService';
import { DEFAULT_TEST_CONFIG } from '../setup/config';

const ORG_ID = 'org_registration_signer_selection_tests';
const RUNTIME_POLICY_SCOPE = {
  orgId: ORG_ID,
  projectId: 'project_registration_signer_selection_tests',
  envId: 'dev',
  signingRootVersion: 'default',
} as const;

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

async function createIntentFromBoundary(service: AuthService, request: unknown) {
  return await service.createRegistrationIntent({
    request: request as never,
    orgId: ORG_ID,
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
  });
}

test.describe('registration signer-selection normalization', () => {
  test('normalizes Ed25519-only signer selection into the registration intent', async () => {
    const result = await createIntentFromBoundary(makeService(), {
      wallet: {
        kind: 'provided',
        walletId: ' wallet_alice ',
      },
      rpId: ' wallet.example.test ',
      authMethod: { kind: 'passkey' },
      signerSelection: {
        mode: ' ed25519_only ',
        ed25519: {
          accountProvisioning: {
            kind: 'sponsored_named_account',
            requestedAccountId: ' alice.testnet ',
            sponsor: 'relayer',
          },
          signerSlot: 1,
          participantIds: [1, '2', 0, -1, 2.5, 'three'],
          keyPurpose: ' near_tx ',
          keyVersion: ' threshold-ed25519-hss-v1 ',
          derivationVersion: '1',
        },
      },
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.message);
    expect(result.intent).toMatchObject({
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      signerSelection: {
        mode: 'ed25519_only',
        ed25519: {
          accountProvisioning: {
            kind: 'sponsored_named_account',
            requestedAccountId: 'alice.testnet',
            sponsor: 'relayer',
          },
          signerSlot: 1,
          participantIds: [1, 2],
          keyPurpose: 'near_tx',
          keyVersion: 'threshold-ed25519-hss-v1',
          derivationVersion: 1,
        },
      },
    });
  });

  test('normalizes combined Ed25519 and ECDSA signer selection', async () => {
    const chainTarget = { chain: 'tempo', chainId: 978 };
    const result = await createIntentFromBoundary(makeService(), {
      wallet: {
        kind: 'provided',
        walletId: 'wallet_combined',
      },
      rpId: 'wallet.example.test',
      authMethod: { kind: 'passkey' },
      signerSelection: {
        mode: 'ed25519_and_ecdsa',
        ed25519: {
          accountProvisioning: {
            kind: 'sponsored_named_account',
            requestedAccountId: 'bob.testnet',
            sponsor: 'relayer',
          },
          signerSlot: '2',
          participantIds: ['1', '2'],
          keyPurpose: 'near_tx',
          keyVersion: 'threshold-ed25519-hss-v1',
          derivationVersion: 1,
        },
        ecdsa: {
          participantIds: ['1', 'bad', 2],
          chainTargets: [chainTarget],
        },
      },
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.message);
    expect(result.intent.signerSelection).toEqual({
      mode: 'ed25519_and_ecdsa',
      ed25519: {
        accountProvisioning: {
          kind: 'sponsored_named_account',
          requestedAccountId: 'bob.testnet',
          sponsor: 'relayer',
        },
        signerSlot: 2,
        participantIds: [1, 2],
        keyPurpose: 'near_tx',
        keyVersion: 'threshold-ed25519-hss-v1',
        derivationVersion: 1,
      },
      ecdsa: {
        participantIds: [1, 2],
        chainTargets: [chainTarget],
      },
    });
  });

  test('rejects unsupported or incomplete signer selections', async () => {
    await expect(
      createIntentFromBoundary(makeService(), {
        wallet: { kind: 'server_generated' },
        rpId: 'wallet.example.test',
        authMethod: { kind: 'passkey' },
        signerSelection: {
          mode: 'unknown',
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'unsupported registration mode',
    });

    await expect(
      createIntentFromBoundary(makeService(), {
        wallet: { kind: 'server_generated' },
        rpId: 'wallet.example.test',
        authMethod: { kind: 'passkey' },
        signerSelection: {
          mode: 'ed25519_only',
          ed25519: {
            accountProvisioning: {
              kind: 'sponsored_named_account',
              requestedAccountId: 'alice.testnet',
              sponsor: 'relayer',
            },
            signerSlot: 1,
            participantIds: [],
            keyPurpose: 'near_tx',
            keyVersion: 'threshold-ed25519-hss-v1',
            derivationVersion: 1,
          },
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'ed25519 signer spec is invalid',
    });

    await expect(
      createIntentFromBoundary(makeService(), {
        wallet: { kind: 'server_generated' },
        rpId: 'wallet.example.test',
        authMethod: { kind: 'passkey' },
        signerSelection: {
          mode: 'ed25519_and_ecdsa',
          ed25519: {
            accountProvisioning: {
              kind: 'sponsored_named_account',
              requestedAccountId: 'alice.testnet',
              sponsor: 'relayer',
            },
            signerSlot: 1,
            participantIds: [1, 2],
            keyPurpose: 'near_tx',
            keyVersion: 'threshold-ed25519-hss-v1',
            derivationVersion: 1,
          },
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'combined registration requires valid ed25519 and ecdsa specs',
    });
  });
});
