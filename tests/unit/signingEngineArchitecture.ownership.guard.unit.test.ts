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

test.describe('signing-engine ownership architecture guardrails', () => {
  test('session child domains declare ownership READMEs', () => {
    for (const relativePath of [
      'client/src/core/signingEngine/session/identity/README.md',
      'client/src/core/signingEngine/session/availability/README.md',
      'client/src/core/signingEngine/session/persistence/README.md',
      'client/src/core/signingEngine/session/sealedRecovery/README.md',
      'client/src/core/signingEngine/session/warmCapabilities/README.md',
      'client/src/core/signingEngine/session/passkey/README.md',
      'client/src/core/signingEngine/session/emailOtp/README.md',
      'client/src/core/signingEngine/session/operationState/README.md',
      'client/src/core/signingEngine/session/budget/README.md',
      'client/src/core/signingEngine/session/planning/README.md',
    ]) {
      const source = readRepoSource(relativePath);
      for (const heading of ['## Owns', '## May Import', '## Must Not Import', '## Entrypoints']) {
        expect(source, relativePath).toContain(heading);
      }
    }
  });

  test('new target top-level folders must declare ownership before use', () => {
    for (const folder of targetTopLevelFolders) {
      const folderPath = path.join(signingEngineRoot, folder);
      if (!fs.existsSync(folderPath)) continue;

      const readmePath = path.join(folderPath, 'README.md');
      expect(fs.existsSync(readmePath), `${folder}/README.md`).toBe(true);
      const source = fs.readFileSync(readmePath, 'utf8');
      for (const heading of ['## Owns', '## May Import', '## Must Not Import', '## Entrypoints']) {
        expect(source, `${folder}/README.md`).toContain(heading);
      }
    }
  });

  test('target child folders do not import target flows modules', () => {
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
      const sourceTopLevel = signingEngineTopLevel(relativePath);
      if (!sourceTopLevel || !targetTopLevelFolders.includes(sourceTopLevel as never)) continue;
      if (sourceTopLevel === 'assembly' || sourceTopLevel === 'flows') continue;

      const source = readRepoSource(relativePath);
      for (const specifier of extractImportSpecifiers(source)) {
        const resolved = resolveSigningEngineImport(relativePath, specifier);
        if (resolved?.startsWith('client/src/core/signingEngine/flows')) {
          offenders.push(`${relativePath} -> ${specifier}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('session child domains avoid flow and assembly imports', () => {
    const domains = [
      'client/src/core/signingEngine/session/identity',
      'client/src/core/signingEngine/session/availability',
      'client/src/core/signingEngine/session/planning',
      'client/src/core/signingEngine/session/budget',
      'client/src/core/signingEngine/session/persistence',
      'client/src/core/signingEngine/session/sealedRecovery',
      'client/src/core/signingEngine/session/operationState',
      'client/src/core/signingEngine/session/warmCapabilities',
      'client/src/core/signingEngine/session/passkey',
      'client/src/core/signingEngine/session/emailOtp',
    ] as const;
    const forbiddenMarkers = [
      '/flows/',
      '/assembly/',
      "from './SigningEngine'",
      "from '../SigningEngine'",
      "from '@/web/SeamsWeb/assembly/BrowserSigningSurface'",
    ] as const;
    const offenders: string[] = [];

    for (const domain of domains) {
      for (const relativePath of listProductionTypeScriptFiles(path.join(repoRoot, domain))) {
        const source = readRepoSource(relativePath);
        for (const marker of forbiddenMarkers) {
          if (source.includes(marker)) offenders.push(`${relativePath} contains ${marker}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('sealedRecovery stays free of method folders, flows, and assembly surfaces', () => {
    const domainRoot = path.join(repoRoot, 'client/src/core/signingEngine/session/sealedRecovery');
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(domainRoot)) {
      const source = readRepoSource(relativePath);
      for (const specifier of extractImportSpecifiers(source)) {
        const resolved = resolveSigningEngineImport(relativePath, specifier);
        if (!resolved) continue;
        if (
          resolved.startsWith('client/src/core/signingEngine/session/passkey/') ||
          resolved.startsWith('client/src/core/signingEngine/session/emailOtp/') ||
          resolved.startsWith('client/src/core/signingEngine/flows/') ||
          resolved.startsWith('client/src/core/signingEngine/assembly/') ||
          resolved === 'client/src/web/SeamsWeb/assembly/BrowserSigningSurface'
        ) {
          offenders.push(`${relativePath} -> ${specifier}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('session child domains only use allowed sibling domains', () => {
    const allowedSiblingDomains: Record<string, readonly string[]> = {
      identity: ['availability', 'operationState', 'persistence'],
      availability: [
        'identity',
        'operationState',
        'persistence',
        'warmCapabilities',
        'budget',
        'planning',
        'sealedRecovery',
      ],
      planning: ['operationState'],
      budget: ['persistence', 'operationState', 'identity'],
      persistence: ['identity', 'sealedRecovery', 'operationState'],
      sealedRecovery: ['persistence'],
      operationState: ['identity', 'persistence', 'budget', 'planning', 'emailOtp'],
      warmCapabilities: ['availability', 'identity', 'persistence', 'operationState', 'budget'],
      passkey: ['identity', 'persistence', 'operationState', 'sealedRecovery', 'warmCapabilities'],
      emailOtp: [
        'availability',
        'budget',
        'identity',
        'operationState',
        'persistence',
        'sealedRecovery',
        'warmCapabilities',
      ],
    };
    const offenders: string[] = [];

    for (const [sourceDomain, allowedTargets] of Object.entries(allowedSiblingDomains)) {
      const domainRoot = path.join(
        repoRoot,
        `client/src/core/signingEngine/session/${sourceDomain}`,
      );

      for (const relativePath of listProductionTypeScriptFiles(domainRoot)) {
        if (isTypeFixture(relativePath)) continue;
        const source = readRepoSource(relativePath);
        for (const specifier of extractImportSpecifiers(source)) {
          const resolved = resolveSigningEngineImport(relativePath, specifier);
          if (!resolved?.startsWith('client/src/core/signingEngine/session/')) continue;

          const tail = resolved.slice('client/src/core/signingEngine/session/'.length);
          const targetDomain = tail.split('/')[0];
          if (!targetDomain || targetDomain === sourceDomain) continue;
          if (targetDomain === 'public.ts') continue;
          if (!allowedTargets.includes(targetDomain)) {
            offenders.push(`${relativePath} -> ${specifier} (${sourceDomain} -> ${targetDomain})`);
          }
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('child session domains do not import session/SigningSessionCoordinator.ts', () => {
    const childDomains = [
      'identity',
      'availability',
      'planning',
      'budget',
      'persistence',
      'sealedRecovery',
      'operationState',
      'warmCapabilities',
      'passkey',
      'emailOtp',
    ] as const;
    const coordinatorPath = 'client/src/core/signingEngine/session/SigningSessionCoordinator.ts';
    const offenders: string[] = [];

    for (const domain of childDomains) {
      const domainRoot = path.join(repoRoot, `client/src/core/signingEngine/session/${domain}`);
      for (const relativePath of listProductionTypeScriptFiles(domainRoot)) {
        const source = readRepoSource(relativePath);
        for (const specifier of extractImportSpecifiers(source)) {
          const resolved = resolveSigningEngineImport(relativePath, specifier);
          if (resolved === coordinatorPath.replace(/\.ts$/, '')) {
            offenders.push(`${relativePath} -> ${specifier}`);
          }
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('SigningSessionCoordinator.ts stays free of method-specific session domains', () => {
    const source = readRepoSource(
      'client/src/core/signingEngine/session/SigningSessionCoordinator.ts',
    );
    const offenders: string[] = [];

    for (const specifier of extractImportSpecifiers(source)) {
      const resolved = resolveSigningEngineImport(
        'client/src/core/signingEngine/session/SigningSessionCoordinator.ts',
        specifier,
      );
      if (!resolved?.startsWith('client/src/core/signingEngine/session/')) continue;
      if (
        resolved.startsWith('client/src/core/signingEngine/session/passkey/') ||
        resolved.startsWith('client/src/core/signingEngine/session/emailOtp/')
      ) {
        offenders.push(`${specifier} -> ${resolved}`);
      }
    }

    expect(offenders).toEqual([]);
  });

  test('SigningSessionCoordinator.ts only imports orchestration session domains', () => {
    const relativePath = 'client/src/core/signingEngine/session/SigningSessionCoordinator.ts';
    const source = readRepoSource(relativePath);
    const allowedSessionDomains = new Set([
      'planning',
      'availability',
      'budget',
      'persistence',
      'operationState',
      'warmCapabilities',
    ]);
    const offenders: string[] = [];

    for (const specifier of extractImportSpecifiers(source)) {
      const resolved = resolveSigningEngineImport(relativePath, specifier);
      if (!resolved?.startsWith('client/src/core/signingEngine/session/')) continue;
      const tail = resolved.slice('client/src/core/signingEngine/session/'.length);
      const targetDomain = tail.split('/')[0];
      if (!targetDomain || targetDomain === 'SigningSessionCoordinator.ts') continue;
      if (targetDomain === 'public.ts') continue;
      if (!allowedSessionDomains.has(targetDomain)) {
        offenders.push(`${specifier} -> ${resolved}`);
      }
    }

    expect(offenders).toEqual([]);
  });

  test('signing flows only import session/SigningSessionCoordinator.ts as a session coordinator', () => {
    const offenders: string[] = [];
    const allowedCoordinatorPrefix =
      'client/src/core/signingEngine/session/SigningSessionCoordinator';

    for (const relativePath of listProductionTypeScriptFiles(
      path.join(signingEngineRoot, 'flows'),
    )) {
      const source = readRepoSource(relativePath);
      for (const specifier of extractImportSpecifiers(source)) {
        const resolved = resolveSigningEngineImport(relativePath, specifier);
        if (!resolved?.startsWith('client/src/core/signingEngine/session/')) continue;
        if (!resolved.includes('Coordinator')) continue;
        if (
          resolved !== allowedCoordinatorPrefix &&
          resolved !== `${allowedCoordinatorPrefix}.ts`
        ) {
          offenders.push(`${relativePath} -> ${specifier} -> ${resolved}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });
});
