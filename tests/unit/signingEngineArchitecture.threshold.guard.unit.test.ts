import fs from 'node:fs';
import path from 'node:path';
import { expect, test } from '@playwright/test';
import {
  repoRoot,
  signingEngineRoot,
  targetTopLevelFolders,
  targetContractFolders,
  readRepoSource,
  listProductionTypeScriptFiles,
  isTypeFixture,
  extractImportSpecifiers,
  resolveSigningEngineImport,
  signingEngineTopLevel,
  sliceTypeAlias,
  stripNeverOptionalGuards
} from './helpers/signingEngineArchitectureGuard';

test.describe('signing-engine threshold architecture guardrails', () => {
  test('Ed25519 HSS lifecycle leaves persistence to caller boundaries', () => {
    const source = readRepoSource(
      'client/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts',
    );

    expect(source).not.toContain('session/records');
    expect(source).not.toContain('persistStoredThresholdEd25519SessionClientBase');
    expect(source).not.toContain('persistToThresholdSessionId');
    expect(source).not.toContain('persistedThresholdSessionId');
  });

  test('threshold session identity types live outside persistence records', () => {
    const records = readRepoSource('client/src/core/signingEngine/session/persistence/records.ts');
    const activation = readRepoSource(
      'client/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts',
    );

    expect(records).not.toContain('export type ThresholdEcdsaSessionStoreSource');
    expect(records).not.toContain('export type ThresholdEd25519SessionStoreSource');
    expect(records).not.toContain('export type ThresholdEcdsaEmailOtpAuthContext');
    expect(activation).not.toContain('session/records');
  });

  test('Ed25519 auth session mint helper has no session lifecycle cache', () => {
    const source = readRepoSource('client/src/core/signingEngine/threshold/ed25519/authSession.ts');

    expect(source).not.toContain('session/records');
    expect(source).not.toContain('persistWarmSessionEd25519Capability');
    expect(source).not.toContain('buildAndCacheEd25519AuthSession');
    expect(source).not.toContain('resolveEd25519AuthSessionBySessionId');
    expect(source).not.toContain('authSessionCache');
  });

  test('Ed25519 connect-session protocol leaves warm-session persistence to callers', () => {
    const source = readRepoSource(
      'client/src/core/signingEngine/threshold/ed25519/connectSession.ts',
    );

    expect(source).not.toContain('persistWarmSessionEd25519Capability');
    expect(source).not.toContain('cacheSigningSessionPrfFirstBestEffort');
    expect(source).not.toContain('session/warmCapabilities');
  });

  test('threshold modules avoid session lifecycle imports', () => {
    const forbiddenMarkers = [
      'session/records',
      'session/warmCapabilities',
      'api/session/signingSessionState',
    ] as const;
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(
      path.join(signingEngineRoot, 'threshold'),
    )) {
      if (isTypeFixture(relativePath)) continue;
      const source = readRepoSource(relativePath);
      for (const marker of forbiddenMarkers) {
        if (source.includes(marker)) {
          offenders.push(`${relativePath} contains ${marker}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('threshold protocol modules do not write warm-session cache material', () => {
    const forbiddenMarkers = [
      'putWarmSessionMaterial',
      'prfFirstCache',
      'WarmSessionMaterial',
    ] as const;
    const offenders: string[] = [];

    for (const protocolFolder of ['ecdsa', 'ed25519'] as const) {
      for (const relativePath of listProductionTypeScriptFiles(
        path.join(signingEngineRoot, 'threshold', protocolFolder),
      )) {
        const source = readRepoSource(relativePath);
        for (const marker of forbiddenMarkers) {
          if (source.includes(marker)) {
            offenders.push(`${relativePath} contains ${marker}`);
          }
        }
      }
    }

    expect(offenders).toEqual([]);
  });
});
