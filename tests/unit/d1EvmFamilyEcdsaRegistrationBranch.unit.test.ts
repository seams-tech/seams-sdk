import { expect, test } from '@playwright/test';

import { buildD1EvmFamilyEcdsaRegistrationPrepare } from '../../packages/sdk-server-ts/src/router/cloudflare/d1EvmFamilyEcdsaRegistrationBranch';
import { resolveD1RegistrationSharedSigningBudget } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationSharedSigningBudget';
import { toD1EcdsaDerivationClientBootstrapRequest } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords';
import type { StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch } from '../../packages/sdk-server-ts/src/core/RegistrationCeremonyStore';
import { registrationPreparationIdFromString } from '../../packages/sdk-server-ts/src/core/registrationContracts';
import type { WalletSigningBudgetSessionStatus } from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/WalletSessionStore';
import type {
  ThresholdEcdsaChainTarget,
  ThresholdRuntimePolicyScope,
} from '../../packages/sdk-server-ts/src/core/types';
import type {
  RouterAbEcdsaStrictRegistrationPort,
  RouterAbEcdsaStrictRegistrationTopology,
} from '../../packages/sdk-server-ts/src/router/routerAbEcdsaStrictRegistration';
import {
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaRegistrationRequestFactsV1,
  type RouterAbEcdsaRegistrationRequestV1,
} from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import { registrationEvmFamilyEcdsaBranchKey } from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseWalletId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  requireParsedDomainId,
  testEcdsaClientBootstrap,
  testEcdsaServerBootstrapResponse,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import { createEcdsaOnlyWalletSigningBudgetSessionStatus } from './helpers/walletSigningBudgetStatus.fixtures';

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

async function buildSharedSigningBudgetFixture(): Promise<{
  readonly walletId: string;
  readonly signingGrantId: string;
  readonly state: StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch;
  readonly status: WalletSigningBudgetSessionStatus;
}> {
  const walletId = requireParsedDomainId(parseWalletId('test-wallet'));
  const prepared = await buildD1EvmFamilyEcdsaRegistrationPrepare({
    registrationCeremonyId: 'wrc_shared_budget_resolver',
    registrationPreparationId: registrationPreparationIdFromString('wrp_shared_budget_resolver'),
    walletId,
    signingRootId: 'signing-root:dev',
    signingRootVersion: 'default',
    chainTargets: [tempoTarget, arcTarget],
    participantIds: [1, 2],
    runtimePolicyScope,
    strictRegistration: testStrictRegistrationPort(),
  });
  if (!prepared.ok) throw new Error(prepared.message);
  const prepare = prepared.ecdsa.prepare;
  const facts = prepared.ecdsa.strictRegistration;
  const signingGrantId = prepare.signingGrantId;
  const clientBootstrap = testEcdsaClientBootstrap(prepare);
  const serverBootstrap = testEcdsaServerBootstrapResponse(
    toD1EcdsaDerivationClientBootstrapRequest(clientBootstrap),
  );
  const state: StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch = {
    kind: 'evm_family_ecdsa_activated',
    branchKey: registrationEvmFamilyEcdsaBranchKey([tempoTarget, arcTarget]),
    derivationKind: prepared.ecdsa.kind,
    chainTargets: prepared.ecdsa.chainTargets,
    prepare,
    strictRegistration: facts,
    registrationRequest: testRegistrationRequestFromFacts(facts),
    publicFacts: {
      registrationRequestDigestB64u: VALID_ECDSA_DIGEST32_B64U,
      proofTranscriptDigestB64u: VALID_ECDSA_DIGEST32_B64U,
      contextBinding32B64u: VALID_ECDSA_DIGEST32_B64U,
      derivationClientSharePublicKey33B64u: VALID_ECDSA_PUBLIC_KEY33_B64U,
      clientShareRetryCounter: 0,
      participantId: 1,
    },
    activation: {
      ecdsa_activation: {
        context: facts.context,
        public_identity: {
          context_binding_b64u: VALID_ECDSA_DIGEST32_B64U,
          derivation_client_share_public_key33_b64u: VALID_ECDSA_PUBLIC_KEY33_B64U,
          server_public_key33_b64u: VALID_ECDSA_SERVER_PUBLIC_KEY33_B64U,
          threshold_public_key33_b64u: VALID_ECDSA_PUBLIC_KEY33_B64U,
          ethereum_address20_b64u: VALID_ETHEREUM_ADDRESS20_B64U,
          client_share_retry_counter: 0,
          server_share_retry_counter: 0,
        },
        signing_worker: facts.signer_set.selected_server,
        activation_epoch: facts.lifecycle.root_share_epoch,
        activation_digest_b64u: VALID_ECDSA_DIGEST32_B64U,
        activated_at_ms: Date.now(),
      },
      lifecycle_id: facts.lifecycle.lifecycle_id,
      transcript_digest: { bytes: new Array<number>(32).fill(0) },
      activated: true,
    },
    publicCapability: parseRouterAbEcdsaDerivationPublicCapabilityV1({
      kind: 'router_ab_ecdsa_derivation_public_capability_v1',
      context: facts.context,
      public_identity: {
        context_binding_b64u: VALID_ECDSA_DIGEST32_B64U,
        derivation_client_share_public_key33_b64u: VALID_ECDSA_PUBLIC_KEY33_B64U,
        server_public_key33_b64u: VALID_ECDSA_SERVER_PUBLIC_KEY33_B64U,
        threshold_public_key33_b64u: VALID_ECDSA_PUBLIC_KEY33_B64U,
        ethereum_address20_b64u: VALID_ETHEREUM_ADDRESS20_B64U,
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      signer_set: facts.signer_set,
      deriver_recipient_keys: facts.deriver_recipient_keys,
      router_id: facts.router_id,
      client_id: facts.client_id,
      activation_epoch: facts.lifecycle.root_share_epoch,
      registration_request_digest_b64u: VALID_ECDSA_DIGEST32_B64U,
      proof_transcript_digest_b64u: VALID_ECDSA_DIGEST32_B64U,
    }),
    bootstrap: serverBootstrap,
  };
  const status = createEcdsaOnlyWalletSigningBudgetSessionStatus({
    walletId,
    expiresAtMs: serverBootstrap.expiresAtMs,
    ecdsaBindings: [
      {
        thresholdSessionId: prepare.thresholdSessionId,
        evmFamilySigningKeySlotId: prepare.evmFamilySigningKeySlotId,
        participantIds: [...prepare.participantIds],
      },
    ],
    committedRemainingUses: prepare.remainingUses,
  });
  return { walletId, signingGrantId, state, status };
}

class FixtureWalletBudgetStatusReader {
  constructor(
    private readonly signingGrantId: string,
    private readonly status: WalletSigningBudgetSessionStatus,
  ) {}

  async read(signingGrantId: string): Promise<WalletSigningBudgetSessionStatus | null> {
    return signingGrantId === this.signingGrantId ? this.status : null;
  }
}

test.describe('D1 EVM-family ECDSA registration prepare', () => {
  test('uses one signing grant for all chain targets in one registration', async () => {
    const prepared = await buildD1EvmFamilyEcdsaRegistrationPrepare({
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
    expect(prepare.signingGrantId).not.toBe('');
    expect(prepare.thresholdSessionId).not.toBe('');
    expect(prepare.remainingUses).toBe(3);
    expect(prepare.participantIds).toEqual([1, 2]);
  });

  test('rejects ECDSA registration participant pairs other than [1, 2]', async () => {
    const prepared = await buildD1EvmFamilyEcdsaRegistrationPrepare({
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

  test('resolves one authoritative wallet budget for mixed registration', async () => {
    const fixture = await buildSharedSigningBudgetFixture();
    const reader = new FixtureWalletBudgetStatusReader(fixture.signingGrantId, fixture.status);

    await expect(
      resolveD1RegistrationSharedSigningBudget({
        walletId: fixture.walletId,
        ecdsaState: fixture.state,
        getWalletBudgetStatus: reader.read.bind(reader),
      }),
    ).resolves.toEqual({
      ok: true,
      budget: {
        kind: 'registration_shared_signing_budget',
        signingGrantId: fixture.signingGrantId,
        expiresAtMs: fixture.status.expiresAtMs,
        remainingUses: 3,
      },
    });
  });
});
