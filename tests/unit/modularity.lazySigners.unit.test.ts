import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

test.describe('modularity lazy signer loading', () => {
  test('signing wiring stays dynamic-import based', async () => {
    const nearSigningSource = fs.readFileSync(
      path.resolve(process.cwd(), '../client/src/core/signingEngine/flows/signNear/signNear.ts'),
      'utf8',
    );
    const nearSigningFlowSource = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../client/src/core/signingEngine/flows/signNear/nearSigningFlow.ts',
      ),
      'utf8',
    );
    const evmSigningSource = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
      ),
      'utf8',
    );
    const signerLoaderSource = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../client/src/core/signingEngine/flows/signEvmFamily/signerLoader.ts',
      ),
      'utf8',
    );

    expect(nearSigningSource).toContain("from '@/web/SeamsWeb/operations/nearSigningFlow'");
    expect(nearSigningFlowSource).toContain(
      'runNearTransactionsWithActionsSigning(request.payload)',
    );
    expect(nearSigningFlowSource).toContain('runNearDelegateActionSigning(request.payload)');
    expect(nearSigningFlowSource).toContain('signNep413Message(request.payload)');
    expect(signerLoaderSource).toContain("import('./signEvmWithUiConfirm')");
    expect(signerLoaderSource).toContain("import('./signEvmFamilyWithUiConfirmForTempo')");
    expect(signerLoaderSource).toContain("import('./signers/secp256k1')");
    expect(signerLoaderSource).toContain("import('./signers/webauthnP256')");

    expect(nearSigningSource).not.toContain("import('../orchestration/signWithIntent')");
    expect(nearSigningSource).not.toContain("import('../signers/algorithms/ed25519')");
    expect(nearSigningFlowSource).not.toContain('NearAdapter');
    expect(nearSigningFlowSource).not.toContain('NearEd25519Engine');
    expect(nearSigningSource).not.toContain("await import('./chainAdaptors/near/walletOrigin')");
    expect(evmSigningSource).not.toContain(
      "from '../flows/signEvmFamily/signEvmFamilyWithUiConfirmForTempo'",
    );
    expect(nearSigningSource).not.toContain("from '../signers/algorithms/ed25519'");
    expect(evmSigningSource).not.toContain("from '../signers/algorithms/secp256k1'");
    expect(evmSigningSource).not.toContain("from '../signers/algorithms/webauthnP256'");
  });

  test('evm and tempo adapters keep chain-specific wasm facades isolated', async () => {
    const evmAdapterSource = fs.readFileSync(
      path.resolve(process.cwd(), '../client/src/core/signingEngine/chains/evm/evmAdapter.ts'),
      'utf8',
    );
    const tempoAdapterSource = fs.readFileSync(
      path.resolve(process.cwd(), '../client/src/core/signingEngine/chains/tempo/tempoAdapter.ts'),
      'utf8',
    );
    const signerLoaderSource = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../client/src/core/signingEngine/flows/signEvmFamily/signerLoader.ts',
      ),
      'utf8',
    );

    expect(evmAdapterSource).toContain("from './ethSignerWasm'");
    expect(evmAdapterSource).not.toContain('tempoSignerWasm');
    expect(evmAdapterSource).not.toContain('tempoSigner-worker');

    expect(tempoAdapterSource).toContain("from '@/web/SeamsWeb/operations/tempoSignerWasm'");
    expect(tempoAdapterSource).not.toContain('ethSignerWasm');
    expect(tempoAdapterSource).not.toContain('ethSigner-worker');

    expect(signerLoaderSource).toContain("import('./signers/secp256k1')");
    expect(signerLoaderSource).toContain("import('./signers/webauthnP256')");
    expect(signerLoaderSource).not.toContain("import('../../signers/algorithms/ed25519')");
  });
});
