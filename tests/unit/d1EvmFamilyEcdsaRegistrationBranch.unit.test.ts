import { expect, test } from '@playwright/test';

import { buildD1EvmFamilyEcdsaRegistrationPrepare } from '../../packages/wallet-server/src/router/cloudflare/d1/registration/d1EvmFamilyEcdsaRegistrationBranch';
import { registrationPreparationIdFromString } from '../../packages/wallet-server/src/core/registrationContracts';
import type {
  ThresholdEcdsaChainTarget,
  ThresholdRuntimePolicyScope,
} from '../../packages/wallet-server/src/core/types';
import type {
  RouterAbEcdsaStrictRegistrationPort,
  RouterAbEcdsaStrictRegistrationTopology,
} from '../../packages/wallet-server/src/router/domains/ecdsa/routerAbEcdsaStrictRegistration';
import { routerAbEcdsaStrictRegistrationRequestBindingJson } from '../../packages/wallet-server/src/router/domains/ecdsa/routerAbEcdsaStrictRegistration';
import type {
  RouterAbEcdsaRegistrationRequestFactsV1,
  RouterAbEcdsaRegistrationRequestV1,
} from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import { parseWalletId } from '../../packages/shared-ts/src/utils/domainIds';
import { requireParsedDomainId } from './helpers/cloudflareD1RouterApiAuthService.fixtures';

const tempoTarget: ThresholdEcdsaChainTarget = {
  kind: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
};

const arcTarget: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};

const runtimePolicyScope: ThresholdRuntimePolicyScope = {
  orgId: 'org-test',
  projectId: 'signing-root',
  envId: 'dev',
  signingRootVersion: 'default',
};

const VALID_ECDSA_DIGEST32_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_ECDSA_PUBLIC_KEY33_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_ECDSA_SERVER_PUBLIC_KEY33_B64U = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_ETHEREUM_ADDRESS20_B64U = Buffer.from('11'.repeat(20), 'hex').toString('base64url');

function testStrictRegistrationTopology(): RouterAbEcdsaStrictRegistrationTopology {
  return {
    routerId: 'router-shared-budget-fixture',
    signerSet: {
      signer_set_id: 'signer-set-shared-budget-fixture',
      policy: 'all_2',
      signer_a: {
        role: 'signer_a',
        signer_id: 'signer-a-shared-budget-fixture',
        key_epoch: 'epoch-shared-budget-fixture',
      },
      signer_b: {
        role: 'signer_b',
        signer_id: 'signer-b-shared-budget-fixture',
        key_epoch: 'epoch-shared-budget-fixture',
      },
      selected_server: {
        server_id: 'signing-worker-shared-budget-fixture',
        key_epoch: 'epoch-shared-budget-fixture',
        recipient_encryption_key:
          'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
    },
    deriverRecipientKeys: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-shared-budget-fixture',
        public_key: 'x25519:2222222222222222222222222222222222222222222222222222222222222222',
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-shared-budget-fixture',
        public_key: 'x25519:3333333333333333333333333333333333333333333333333333333333333333',
      },
    },
  };
}

function testStrictRegistrationPort(): RouterAbEcdsaStrictRegistrationPort {
  const topology = testStrictRegistrationTopology();
  return {
    topology: () => topology,
    register: async () => {
      throw new Error('strict registration register() is unreachable in this fixture');
    },
    registerInitialWithTenantRoot: async () => {
      throw new Error('strict registration register() is unreachable in this fixture');
    },
    activate: async () => {
      throw new Error('strict registration activate() is unreachable in this fixture');
    },
  };
}

function testRegistrationRequestFromFacts(
  facts: RouterAbEcdsaRegistrationRequestFactsV1,
): RouterAbEcdsaRegistrationRequestV1 {
  const digest = { bytes: new Array<number>(32).fill(0) };
  const { deriver_recipient_keys: _deriverRecipientKeys, ...requestFacts } = facts;
  return {
    ...requestFacts,
    client_ephemeral_public_key: 'client-ephemeral-public-key',
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

test.describe('D1 EVM-family ECDSA registration prepare', () => {
  test('uses one Wallet Session quota for all chain targets in one registration', async () => {
    const prepared = await buildD1EvmFamilyEcdsaRegistrationPrepare({
      registrationPurpose: 'wallet_registration',
      registrationCeremonyId: 'wrc_shared_budget',
      registrationPreparationId: registrationPreparationIdFromString('wrp_shared_budget'),
      walletId: requireParsedDomainId(parseWalletId('test-wallet')),
      signingRootId: 'signing-root:dev',
      signingRootVersion: 'default',
      chainTargets: [tempoTarget, arcTarget],
      participantIds: [1, 2],
      runtimePolicyScope,
      strictRegistration: testStrictRegistrationPort(),
    });

    expect(prepared.ok).toBe(true);
    if (!prepared.ok) return;

    expect(prepared.ecdsa.kind).toBe('evm_family_ecdsa_keygen');
    expect(prepared.ecdsa.chainTargets).toEqual([tempoTarget, arcTarget]);
    const prepare = prepared.ecdsa.prepare;
    expect(prepare.thresholdSessionId).not.toBe('');
    expect(prepare.remainingUses).toBe(3);
    expect(prepare.participantIds).toEqual([1, 2]);
  });

  test('rejects ECDSA registration participant pairs other than [1, 2]', async () => {
    const prepared = await buildD1EvmFamilyEcdsaRegistrationPrepare({
      registrationPurpose: 'wallet_registration',
      registrationCeremonyId: 'wrc_shared_budget_pair',
      registrationPreparationId: registrationPreparationIdFromString('wrp_shared_budget_pair'),
      walletId: requireParsedDomainId(parseWalletId('test-wallet')),
      signingRootId: 'signing-root:dev',
      signingRootVersion: 'default',
      chainTargets: [tempoTarget, arcTarget],
      participantIds: [1, 2, 3],
      runtimePolicyScope,
      strictRegistration: testStrictRegistrationPort(),
    });

    expect(prepared).toEqual({
      ok: false,
      code: 'invalid_body',
      message: 'ECDSA registration requires participant pair [1, 2]',
    });
  });
});
