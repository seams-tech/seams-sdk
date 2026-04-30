import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const LEGACY_FIELD = 'groupPublicKeyB64u';
const CANONICAL_FIELD = 'thresholdEcdsaPublicKeyB64u';

const SOURCE_FILES = [
  '../client/src/core/rpcClients/relayer/thresholdEcdsa.ts',
  '../client/src/core/SeamsPasskey/evm/linkDeviceThresholdEcdsa.ts',
  '../client/src/core/signingEngine/threshold/workflows/bootstrapEcdsaSession.ts',
  '../client/src/core/SeamsPasskey/login.ts',
];

const DIST_FILES = [
  '../sdk/dist/esm/core/rpcClients/relayer/thresholdEcdsa.js',
  '../sdk/dist/esm/core/SeamsPasskey/evm/linkDeviceThresholdEcdsa.js',
  '../sdk/dist/esm/core/signingEngine/threshold/workflows/bootstrapEcdsaSession.js',
  '../sdk/dist/esm/sdk/wallet-iframe-host-runtime.js',
];

test.describe('threshold ECDSA public-key field regression', () => {
  test('source and built SDK surfaces use only thresholdEcdsaPublicKeyB64u', () => {
    const allFiles = [...SOURCE_FILES, ...DIST_FILES];

    for (const relativeFile of allFiles) {
      const absoluteFile = path.resolve(process.cwd(), relativeFile);
      expect(fs.existsSync(absoluteFile), `${relativeFile} should exist`).toBe(true);
      const source = fs.readFileSync(absoluteFile, 'utf8');
      expect(source.includes(LEGACY_FIELD), `${relativeFile} still references legacy ${LEGACY_FIELD}`).toBe(false);
      expect(source.includes(CANONICAL_FIELD), `${relativeFile} should reference ${CANONICAL_FIELD}`).toBe(true);
    }
  });
});
