import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

test.describe('WebAuthnP256Engine wasm boundary', () => {
  test('routes WebAuthn challenge binding + DER parsing through wasm wrapper', () => {
    const engineSource = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signers/webauthnP256.ts',
      ),
      'utf8',
    );

    expect(engineSource).toContain('buildWebauthnP256SignatureWasm');
    expect(engineSource).toContain('workerCtx is required');
    expect(engineSource).not.toContain('parseDerEcdsaSignatureP256');
    expect(engineSource).not.toContain('readDerLength(');
  });

  test('eth worker exposes buildWebauthnP256Signature operation', () => {
    const workerSource = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../packages/sdk-web/src/core/signingEngine/workerManager/workers/eth-signer.worker.ts',
      ),
      'utf8',
    );

    expect(workerSource).toContain("type: 'buildWebauthnP256Signature'");
    expect(workerSource).toContain('build_webauthn_p256_signature');
  });

  test('eth worker owns WebAuthn COSE P-256 key decoding', () => {
    const workerSource = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../packages/sdk-web/src/core/signingEngine/workerManager/workers/eth-signer.worker.ts',
      ),
      'utf8',
    );
    const keyRefSource = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/webauthnP256KeyRef.ts',
      ),
      'utf8',
    );

    expect(workerSource).toContain("type: 'decodeCoseP256PublicKey'");
    expect(workerSource).toContain('decode_cose_p256_public_key');
    expect(keyRefSource).toContain('decodeCoseP256PublicKeyWasm');
    expect(keyRefSource).not.toContain('coseP256PublicKeyToXY');
  });
});
