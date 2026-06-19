import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sourceRoots = [
  'packages/sdk-server-ts/src',
  'packages/sdk-web/src',
  'packages/shared-ts/src',
  'tests',
] as const;
const selfPath = 'tests/unit/refactor71WalletSessionNaming.guard.unit.test.ts';

function joined(parts: readonly string[]): string {
  return parts.join('');
}

function listSourceFiles(relativePath: string): string[] {
  const absolutePath = path.join(repoRoot, relativePath);
  const stat = fs.statSync(absolutePath);
  if (stat.isFile()) return /\.(ts|tsx)$/.test(relativePath) ? [relativePath] : [];
  return fs.readdirSync(absolutePath, { withFileTypes: true }).flatMap((entry) => {
    const childPath = path.join(relativePath, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === 'test-results') {
        return [];
      }
      return listSourceFiles(childPath);
    }
    return /\.(ts|tsx)$/.test(entry.name) ? [childPath] : [];
  });
}

function activeSourceFiles(): string[] {
  return sourceRoots.flatMap((root) => listSourceFiles(root)).filter((file) => file !== selfPath);
}

function readSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

test.describe('Refactor 71 wallet-session naming source guards', () => {
  test('active package and test sources do not expose the old signing-grant names', () => {
    const forbiddenMarkers = [
      joined(['wallet', 'SigningSessionId']),
      joined(['Wallet', 'SigningSessionId']),
      joined(['wallet_', 'signing_', 'session_id']),
      joined(['wallet-', 'signing-', 'session']),
    ];
    const offenders: string[] = [];
    for (const file of activeSourceFiles()) {
      const source = readSource(file);
      for (const marker of forbiddenMarkers) {
        if (source.includes(marker)) offenders.push(`${file} contains ${marker}`);
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('Router A/B Wallet Session JWT payloads use thresholdSessionId claims', () => {
    const jwtKindMarkers = [
      'ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND',
      'ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND',
      'router_ab_ed25519_wallet_session_v1',
      'router_ab_ecdsa_hss_wallet_session_v1',
    ];
    const offenders: string[] = [];
    for (const file of activeSourceFiles()) {
      const source = readSource(file);
      for (const kind of jwtKindMarkers) {
        const pattern = new RegExp(`${kind}[\\s\\S]{0,320}\\bsessionId\\s*:`);
        if (pattern.test(source)) offenders.push(`${file} uses sessionId near ${kind}`);
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });
});
