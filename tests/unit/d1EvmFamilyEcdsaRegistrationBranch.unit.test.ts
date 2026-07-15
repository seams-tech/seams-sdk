import { expect, test } from '@playwright/test';

import { buildD1EvmFamilyEcdsaRegistrationPrepare } from '../../packages/sdk-server-ts/src/router/cloudflare/d1EvmFamilyEcdsaRegistrationBranch';
import { resolveD1RegistrationSharedSigningBudget } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationSharedSigningBudget';
import { toD1EcdsaHssClientBootstrapRequest } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords';
import type { StoredWalletRegistrationEvmFamilyEcdsaRespondedBranch } from '../../packages/sdk-server-ts/src/core/RegistrationCeremonyStore';
import type {
  WalletSigningBudgetEcdsaBinding,
  WalletSigningBudgetEcdsaBindings,
  WalletSigningBudgetSessionStatus,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/WalletSessionStore';
import type { ThresholdEcdsaChainTarget } from '../../packages/sdk-server-ts/src/core/types';
import { registrationEvmFamilyEcdsaBranchKey } from '../../packages/shared-ts/src/utils/registrationIntent';
import {
  testEcdsaClientBootstrap,
  testEcdsaServerBootstrapResponse,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';

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

class FixtureWalletBudgetStatusReader {
  constructor(
    private readonly signingGrantId: string,
    private readonly status: WalletSigningBudgetSessionStatus,
  ) {}

  async read(signingGrantId: string): Promise<WalletSigningBudgetSessionStatus | null> {
    return signingGrantId === this.signingGrantId ? this.status : null;
  }
}

async function buildSharedSigningBudgetFixture(): Promise<{
  readonly walletId: string;
  readonly signingGrantId: string;
  readonly state: StoredWalletRegistrationEvmFamilyEcdsaRespondedBranch;
  readonly status: WalletSigningBudgetSessionStatus;
}> {
  const walletId = 'test-wallet';
  const prepared = await buildD1EvmFamilyEcdsaRegistrationPrepare({
    registrationCeremonyId: 'wrc_shared_budget_resolver',
    walletId,
    signingRootId: 'signing-root:dev',
    signingRootVersion: 'default',
    chainTargets: [tempoTarget, arcTarget],
    participantIds: [1, 2, 3],
  });
  if (!prepared.ok) throw new Error(prepared.message);
  const firstTarget = prepared.ecdsa.targets[0];
  if (!firstTarget) throw new Error('Shared signing-budget fixture requires an ECDSA target');
  const signingGrantId = firstTarget.prepare.signingGrantId;
  const expiresAtMs = Date.now() + firstTarget.prepare.ttlMs;
  const bootstraps: StoredWalletRegistrationEvmFamilyEcdsaRespondedBranch['responded']['bootstraps'] =
    [];
  const additionalBindings: WalletSigningBudgetEcdsaBinding[] = [];
  let firstBinding: WalletSigningBudgetEcdsaBinding | null = null;
  for (const target of prepared.ecdsa.targets) {
    const clientBootstrap = testEcdsaClientBootstrap(target.prepare);
    const serverBootstrap = testEcdsaServerBootstrapResponse(
      toD1EcdsaHssClientBootstrapRequest(clientBootstrap),
    );
    serverBootstrap.expiresAtMs = expiresAtMs;
    serverBootstrap.expiresAt = new Date(expiresAtMs).toISOString();
    bootstraps.push({ chainTarget: target.chainTarget, bootstrap: serverBootstrap });
    const binding: WalletSigningBudgetEcdsaBinding = {
      thresholdSessionId: target.prepare.thresholdSessionId,
      evmFamilySigningKeySlotId: target.prepare.evmFamilySigningKeySlotId,
      participantIds: [...target.prepare.participantIds],
    };
    if (firstBinding) additionalBindings.push(binding);
    else firstBinding = binding;
  }
  if (!firstBinding) throw new Error('Shared signing-budget fixture requires an ECDSA binding');
  const ecdsaBindings: WalletSigningBudgetEcdsaBindings = [firstBinding, ...additionalBindings];
  const state: StoredWalletRegistrationEvmFamilyEcdsaRespondedBranch = {
    kind: 'evm_family_ecdsa_responded',
    branchKey: registrationEvmFamilyEcdsaBranchKey([tempoTarget, arcTarget]),
    hssKind: prepared.ecdsa.kind,
    targets: prepared.ecdsa.targets,
    responded: { bootstraps },
  };
  const status: WalletSigningBudgetSessionStatus = {
    record: {
      kind: 'wallet_signing_budget_session',
      expiresAtMs,
      walletId,
      bindings: { kind: 'ecdsa_only', ecdsa: ecdsaBindings },
    },
    expiresAtMs,
    committedRemainingUses: firstTarget.prepare.remainingUses,
    reservedUses: 0,
    availableUses: firstTarget.prepare.remainingUses,
    remainingUses: firstTarget.prepare.remainingUses,
  };
  return { walletId, signingGrantId, state, status };
}

test.describe('D1 EVM-family ECDSA registration prepare', () => {
  test('uses one signing grant for all chain targets in one registration', async () => {
    const prepared = await buildD1EvmFamilyEcdsaRegistrationPrepare({
      registrationCeremonyId: 'wrc_shared_budget',
      walletId: 'test-wallet',
      signingRootId: 'signing-root:dev',
      signingRootVersion: 'default',
      chainTargets: [tempoTarget, arcTarget],
      participantIds: [1, 2],
    });

    expect(prepared.ok).toBe(true);
    if (!prepared.ok) return;

    const targets = prepared.ecdsa.targets;
    expect(targets).toHaveLength(2);
    expect(new Set(targets.map((target) => target.prepare.signingGrantId)).size).toBe(1);
    expect(new Set(targets.map((target) => target.prepare.thresholdSessionId)).size).toBe(2);
    expect(targets.map((target) => target.prepare.remainingUses)).toEqual([3, 3]);
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
