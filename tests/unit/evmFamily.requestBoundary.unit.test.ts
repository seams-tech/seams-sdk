import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { evmFamilySigningTargetFromExplicitTarget } from '@/core/signingEngine/flows/signEvmFamily/types';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { buildEvmFamilyEcdsaKeyIdentity } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';

import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';
import { testEcdsaChainTarget } from './helpers/ecdsaChainTarget.fixtures';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
test.describe('EVM-family request boundaries', () => {
  test('allows EIP-1559 transaction encoding against a Tempo signing target', () => {
    const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    });
    const request = {
      chain: 'evm',
      kind: 'eip1559',
      senderSignatureAlgorithm: 'secp256k1',
      tx: {
        chainId: 42431,
        maxPriorityFeePerGas: 1n,
        maxFeePerGas: 2n,
        gasLimit: 21_000n,
        to: `0x${'11'.repeat(20)}`,
        value: 0n,
        data: '0x',
        accessList: [],
      },
    } as any;

    expect(evmFamilySigningTargetFromExplicitTarget({ request, chainTarget })).toEqual(chainTarget);
  });

  test('derives Tempo family from concrete request kind when request.chain drifts', () => {
    const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    });
    const request = {
      chain: 'evm',
      kind: 'tempoTransaction',
      senderSignatureAlgorithm: 'secp256k1',
      tx: {
        chainId: 42431,
        maxPriorityFeePerGas: 1n,
        maxFeePerGas: 2n,
        gasLimit: 21_000n,
        nonceKey: 1n,
        calls: [{ to: `0x${'11'.repeat(20)}`, value: 0n }],
      },
    } as any;

    expect(evmFamilySigningTargetFromExplicitTarget({ request, chainTarget })).toEqual(chainTarget);
  });

  test('routes Tempo EIP-1559 requests through the Tempo flow with the EVM encoder', () => {
    const transactionExecutor = fs.readFileSync(
      path.join(
        repoRoot,
        'packages/wallet/src/core/signingEngine/flows/signEvmFamily/transactionExecutor.ts',
      ),
      'utf8',
    );
    expect(transactionExecutor).toContain(
      "args.chainTarget.kind === 'evm' || args.request.kind === 'eip1559'",
    );
    // The loader choice is a formatted ternary, so match it on its parts.
    // Asserting the one-line form made this guard fail on reflow rather than on
    // the routing it exists to protect.
    const loaderChoice = transactionExecutor.replace(/\s+/g, ' ');
    expect(loaderChoice).toContain(
      "targetKind === 'tempo' ? loadSignEvmFamilyWithUiConfirmForTempo : loadSignEvmWithUiConfirm",
    );
    expect(transactionExecutor).toContain('requireRawEip1559ThresholdOwnerNonceSenderIdentity');
    expect(transactionExecutor).toContain('thresholdOwnerNonceSenderIdentity');
    expect(transactionExecutor).toContain(
      'raw EIP-1559 signing requires prepared threshold ECDSA owner address',
    );

    const signEvmFamilyWithUiConfirmForTempo = fs.readFileSync(
      path.join(
        repoRoot,
        'packages/wallet/src/core/signingEngine/flows/signEvmFamily/signEvmFamilyWithUiConfirmForTempo.ts',
      ),
      'utf8',
    );
    expect(signEvmFamilyWithUiConfirmForTempo).toContain("args.request.kind === 'eip1559'");
    expect(signEvmFamilyWithUiConfirmForTempo).toContain(
      'new EvmAdapter(workerCtx).buildIntent(request)',
    );
    expect(signEvmFamilyWithUiConfirmForTempo).toContain("targetKind: 'tempo'");
  });
});
