import { expect, test } from '@playwright/test';
import { AuthService } from '@server/core/AuthService';
import { normalizeRegistrationSignerPlan } from '../../packages/shared-ts/src/utils/registrationIntent';
import { registrationSignerSetRequestSelection } from '../../packages/sdk-web/src/core/rpcClients/relayer/registrationSignerSetRequest';
import { DEFAULT_TEST_CONFIG } from '../setup/config';

const ORG_ID = 'org_registration_signer_selection_tests';
const EVM_CHAIN_TARGET = { chain: 'tempo', chainId: 978 };
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

function makeNearEd25519SignerFields(signerSlot: number): Record<string, unknown> {
  return {
    accountProvisioning: {
      kind: 'sponsored_named_account',
      requestedAccountId: 'alice.testnet',
      sponsor: 'relayer',
    },
    signerSlot,
    participantIds: [1, '2', 0, -1, 2.5, 'three'],
    keyPurpose: 'near_tx',
    keyVersion: 'threshold-ed25519-hss-v1',
    derivationVersion: '1',
  };
}

function makeNearEd25519Signer(signerSlot: number): Record<string, unknown> {
  const fields = makeNearEd25519SignerFields(signerSlot);
  return {
    kind: 'near_ed25519',
    accountProvisioning: fields.accountProvisioning,
    signerSlot: fields.signerSlot,
    participantIds: fields.participantIds,
    derivationVersion: fields.derivationVersion,
  };
}

function makeEvmFamilyEcdsaSignerFields(chainTargets: readonly unknown[]): Record<string, unknown> {
  return {
    participantIds: ['1', 'bad', 2],
    chainTargets,
  };
}

function makeEvmFamilyEcdsaSigner(chainTargets: readonly unknown[]): Record<string, unknown> {
  const fields = makeEvmFamilyEcdsaSignerFields(chainTargets);
  return {
    kind: 'evm_family_ecdsa',
    participantIds: fields.participantIds,
    chainTargets: fields.chainTargets,
  };
}

test.describe('registration signer-set normalization', () => {
  test('normalizes signer-set request input into a branch-keyed signer plan', () => {
    const result = normalizeRegistrationSignerPlan({
      kind: 'signer_set',
      signers: [makeNearEd25519Signer(1), makeEvmFamilyEcdsaSigner([EVM_CHAIN_TARGET])],
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.message);
    expect(result.value).toEqual({
      kind: 'signer_set',
      branches: [
        {
          kind: 'near_ed25519',
          branchKey: 'near_ed25519:slot:1',
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
        {
          kind: 'evm_family_ecdsa',
          branchKey: 'evm_family_ecdsa:{"chain":"tempo","chainId":978}',
          participantIds: [1, 2],
          chainTargets: [EVM_CHAIN_TARGET],
        },
      ],
    });
  });

  test('rejects duplicate signer-set branch identities', () => {
    expect(
      normalizeRegistrationSignerPlan({
        kind: 'signer_set',
        signers: [makeNearEd25519Signer(1), makeNearEd25519Signer(1)],
      }),
    ).toEqual({
      ok: false,
      code: 'invalid_body',
      message: 'duplicate near_ed25519 signer slot is invalid',
    });

    expect(
      normalizeRegistrationSignerPlan({
        kind: 'signer_set',
        signers: [
          makeEvmFamilyEcdsaSigner([EVM_CHAIN_TARGET]),
          makeEvmFamilyEcdsaSigner([EVM_CHAIN_TARGET]),
        ],
      }),
    ).toEqual({
      ok: false,
      code: 'invalid_body',
      message: 'duplicate evm_family_ecdsa chain target is invalid',
    });
  });

  test('rejects unsupported signer-set branch kinds', () => {
    expect(
      normalizeRegistrationSignerPlan({
        kind: 'signer_set',
        signers: [
          {
            kind: 'future_protocol',
            participantIds: [1, 2],
          },
        ],
      }),
    ).toEqual({
      ok: false,
      code: 'invalid_body',
      message: 'unsupported registration signer kind',
    });
  });

  test('rejects non-signer-set registration selection shapes', () => {
    const result = normalizeRegistrationSignerPlan({
      mode: 'legacy_mode',
      ed25519: makeNearEd25519SignerFields(2),
    });

    expect(result).toEqual({
      ok: false,
      code: 'invalid_body',
      message: 'signerSelection.kind must be signer_set',
    });
  });

  test('keeps SDK registration RPC requests on signer-set wire shape', () => {
    const signerSetSelection = {
      kind: 'signer_set',
      signers: [makeNearEd25519Signer(2), makeEvmFamilyEcdsaSigner([EVM_CHAIN_TARGET])],
    } as const;

    expect(registrationSignerSetRequestSelection(signerSetSelection)).toBe(signerSetSelection);
  });

  test('creates registration intents from signer-set request input at the service boundary', async () => {
    const result = await createIntentFromBoundary(makeService(), {
      wallet: {
        kind: 'provided',
        walletId: 'wallet_signer_set',
      },
      authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
      signerSelection: {
        kind: 'signer_set',
        signers: [makeNearEd25519Signer(1), makeEvmFamilyEcdsaSigner([EVM_CHAIN_TARGET])],
      },
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.message);
    expect(result.intent.signerSelection).toEqual({
      kind: 'signer_set',
      signers: [
        {
          kind: 'near_ed25519',
          accountProvisioning: {
            kind: 'sponsored_named_account',
            requestedAccountId: 'alice.testnet',
            sponsor: 'relayer',
          },
          signerSlot: 1,
          participantIds: [1, 2],
          derivationVersion: 1,
        },
        {
          kind: 'evm_family_ecdsa',
          participantIds: [1, 2],
          chainTargets: [EVM_CHAIN_TARGET],
        },
      ],
    });
  });

  test('normalizes NEAR Ed25519 signer-set selection into the registration intent', async () => {
    const result = await createIntentFromBoundary(makeService(), {
      wallet: {
        kind: 'provided',
        walletId: ' wallet_alice ',
      },
      authMethod: { kind: 'passkey', rpId: ' wallet.example.test ' },
      signerSelection: {
        kind: 'signer_set',
        signers: [
          {
            kind: 'near_ed25519',
            accountProvisioning: {
              kind: 'sponsored_named_account',
              requestedAccountId: ' alice.testnet ',
              sponsor: 'relayer',
            },
            signerSlot: 1,
            participantIds: [1, '2', 0, -1, 2.5, 'three'],
            derivationVersion: '1',
          },
        ],
      },
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.message);
    expect(result.intent).toMatchObject({
      walletId: 'wallet_alice',
      authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      signerSelection: {
        kind: 'signer_set',
        signers: [
          {
            kind: 'near_ed25519',
            accountProvisioning: {
              kind: 'sponsored_named_account',
              requestedAccountId: 'alice.testnet',
              sponsor: 'relayer',
            },
            signerSlot: 1,
            participantIds: [1, 2],
            derivationVersion: 1,
          },
        ],
      },
    });
  });

  test('normalizes combined Ed25519 and ECDSA signer-set selection', async () => {
    const chainTarget = { chain: 'tempo', chainId: 978 };
    const result = await createIntentFromBoundary(makeService(), {
      wallet: {
        kind: 'provided',
        walletId: 'wallet_combined',
      },
      authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
      signerSelection: {
        kind: 'signer_set',
        signers: [
          {
            kind: 'near_ed25519',
            accountProvisioning: {
              kind: 'sponsored_named_account',
              requestedAccountId: 'bob.testnet',
              sponsor: 'relayer',
            },
            signerSlot: '2',
            participantIds: ['1', '2'],
            derivationVersion: 1,
          },
          {
            kind: 'evm_family_ecdsa',
            participantIds: ['1', 'bad', 2],
            chainTargets: [chainTarget],
          },
        ],
      },
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.message);
    expect(result.intent.signerSelection).toEqual({
      kind: 'signer_set',
      signers: [
        {
          kind: 'near_ed25519',
          accountProvisioning: {
            kind: 'sponsored_named_account',
            requestedAccountId: 'bob.testnet',
            sponsor: 'relayer',
          },
          signerSlot: 2,
          participantIds: [1, 2],
          derivationVersion: 1,
        },
        {
          kind: 'evm_family_ecdsa',
          participantIds: [1, 2],
          chainTargets: [chainTarget],
        },
      ],
    });
  });

  test('rejects unsupported or incomplete signer selections', async () => {
    await expect(
      createIntentFromBoundary(makeService(), {
        wallet: { kind: 'server_allocated' },
        authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
        signerSelection: {
          mode: 'legacy_mode',
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'signerSelection.kind must be signer_set',
    });

    await expect(
      createIntentFromBoundary(makeService(), {
        wallet: { kind: 'server_allocated' },
        authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'near_ed25519',
              accountProvisioning: {
                kind: 'sponsored_named_account',
                requestedAccountId: 'alice.testnet',
                sponsor: 'relayer',
              },
              signerSlot: 1,
              participantIds: [],
              derivationVersion: 1,
            },
          ],
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'near_ed25519 signer spec is invalid',
    });

    await expect(
      createIntentFromBoundary(makeService(), {
        wallet: { kind: 'server_allocated' },
        authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'evm_family_ecdsa',
              participantIds: [1, 2],
              chainTargets: [],
            },
          ],
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'evm_family_ecdsa signer spec is invalid',
    });
  });
});
