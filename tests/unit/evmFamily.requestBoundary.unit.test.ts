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

import {
  resetWarmSessionFixtureState,
  seedEcdsaWarmSessionRecord,
  createThresholdEcdsaStoreFixture,
} from './helpers/signingSessionRecord.fixtures';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';
import { testEcdsaChainTarget } from './helpers/ecdsaChainTarget.fixtures';
import { thresholdEcdsaSessionRecordReadModel } from '@/core/signingEngine/session/persistence/records';

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
        'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/transactionExecutor.ts',
      ),
      'utf8',
    );
    expect(transactionExecutor).toContain(
      "args.chainTarget.kind === 'evm' || args.request.kind === 'eip1559'",
    );
    expect(transactionExecutor).toContain(
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
        'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamilyWithUiConfirmForTempo.ts',
      ),
      'utf8',
    );
    expect(signEvmFamilyWithUiConfirmForTempo).toContain("args.request.kind === 'eip1559'");
    expect(signEvmFamilyWithUiConfirmForTempo).toContain(
      'new EvmAdapter(workerCtx).buildIntent(request)',
    );
    expect(signEvmFamilyWithUiConfirmForTempo).toContain("targetKind: 'tempo'");
  });

  test('refreshes step-up ECDSA lanes with the normalized signing target chain', () => {
    const signEvmFamily = fs.readFileSync(
      path.join(
        repoRoot,
        'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
      ),
      'utf8',
    );

    const emailOtpRefreshCall = signEvmFamily.slice(
      signEvmFamily.indexOf('completeEvmFamilyEmailOtpSigningRefresh({'),
      signEvmFamily.indexOf('completeEvmFamilyEmailOtpSigningRefresh({') + 400,
    );
    expect(emailOtpRefreshCall).toContain('chain: requestChain');
    expect(emailOtpRefreshCall).not.toContain('chain: args.request.chain');

    const keyRefRefreshStart = signEvmFamily.lastIndexOf(
      'updateResolvedEvmFamilyEcdsaSigningLaneIdentity({',
      signEvmFamily.indexOf("context: 'EVM-family signing record refresh'"),
    );
    const keyRefRefreshCall = signEvmFamily.slice(keyRefRefreshStart, keyRefRefreshStart + 400);
    expect(keyRefRefreshCall).toContain('chain: requestChain');
    expect(keyRefRefreshCall).not.toContain('chain: args.request.chain');
  });

  test('committed Email OTP ECDSA selection does not probe session records by wallet and chain', () => {
    const ecdsaSelection = fs.readFileSync(
      path.join(
        repoRoot,
        'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts',
      ),
      'utf8',
    );

    expect(ecdsaSelection).not.toContain('getEmailOtpThresholdEcdsaSessionRecordForSigning');
    expect(ecdsaSelection).not.toContain('tryGetEmailOtpThresholdEcdsaSessionRecordForAuthority');
  });
});

