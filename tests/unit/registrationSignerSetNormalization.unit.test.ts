import { expect, test } from '@playwright/test';
import { normalizeRegistrationSignerPlan } from '../../packages/shared-ts/src/utils/registrationIntent';
import { registrationSignerSetRequestSelection } from '../../packages/sdk-web/src/core/rpcClients/relayer/registrationSignerSetRequest';

const EVM_CHAIN_TARGET = { chain: 'tempo', chainId: 978 };

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
    keyVersion: 'router-ab-ed25519-yao-v1',
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
          keyVersion: 'router-ab-ed25519-yao-v1',
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
});
