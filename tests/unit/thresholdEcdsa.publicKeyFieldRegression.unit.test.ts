import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const LEGACY_FIELD = 'groupPublicKeyB64u';
const CANONICAL_FIELD = 'thresholdEcdsaPublicKeyB64u';

const SOURCE_FILES = [
  '../client/src/core/rpcClients/relayer/thresholdEcdsa.ts',
  '../client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts',
  '../client/src/core/SeamsPasskey/login.ts',
];

const DIST_FILES = [
  '../sdk/dist/esm/core/rpcClients/relayer/thresholdEcdsa.js',
  '../sdk/dist/esm/core/signingEngine/threshold/ecdsa/bootstrapSession.js',
];

test.describe('threshold ECDSA public-key field regression', () => {
  test('source and built SDK surfaces use only thresholdEcdsaPublicKeyB64u', () => {
    const sdkChunkDir = path.resolve(process.cwd(), '../sdk/dist/esm/sdk');
    const sdkRuntimeChunks = fs
      .readdirSync(sdkChunkDir)
      .filter((name) => name.endsWith('.js'))
      .map((name) => path.join(sdkChunkDir, name));
    const allFiles = [
      ...SOURCE_FILES.map((relativeFile) => path.resolve(process.cwd(), relativeFile)),
      ...DIST_FILES.map((relativeFile) => path.resolve(process.cwd(), relativeFile)),
      ...sdkRuntimeChunks,
    ];
    let canonicalFieldReferences = 0;

    for (const absoluteFile of allFiles) {
      expect(fs.existsSync(absoluteFile), `${absoluteFile} should exist`).toBe(true);
      const source = fs.readFileSync(absoluteFile, 'utf8');
      expect(source.includes(LEGACY_FIELD), `${absoluteFile} still references legacy ${LEGACY_FIELD}`).toBe(false);
      if (source.includes(CANONICAL_FIELD)) canonicalFieldReferences += 1;
    }
    expect(canonicalFieldReferences, `${CANONICAL_FIELD} should remain in built ECDSA surfaces`).toBeGreaterThan(0);
  });
});
