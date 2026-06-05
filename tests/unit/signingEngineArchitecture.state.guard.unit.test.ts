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
  stripNeverOptionalGuards,
} from './helpers/signingEngineArchitectureGuard';

test.describe('signing-engine state architecture guardrails', () => {
  test('ECDSA chain target primitives live in interfaces', () => {
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(path.join(repoRoot, 'client/src'))) {
      const source = readRepoSource(relativePath);
      if (source.includes('signingEngine/session/operationState/ecdsaChainTarget')) {
        offenders.push(relativePath);
      }
    }

    expect(offenders).toEqual([]);
  });

  test('canonical selected lanes and operation states do not use optional lifecycle fields', () => {
    const identity = readRepoSource(
      'client/src/core/signingEngine/session/identity/laneIdentity.ts',
    );
    const signingLanes = readRepoSource(
      'client/src/core/signingEngine/session/operationState/lanes.ts',
    );
    const signingTypes = readRepoSource(
      'client/src/core/signingEngine/session/operationState/types.ts',
    );
    const signingBudget = readRepoSource('client/src/core/signingEngine/session/budget/budget.ts');
    const operationState = readRepoSource(
      'client/src/core/signingEngine/flows/shared/operationState.ts',
    );
    const planner = readRepoSource('client/src/core/signingEngine/session/planning/planner.ts');
    const restoreTypes = readRepoSource(
      'client/src/core/signingEngine/session/sealedRecovery/types.ts',
    );
    const restoreCoordinator = readRepoSource(
      'client/src/core/signingEngine/session/sealedRecovery/restoreCoordinator.ts',
    );

    for (const typeName of [
      'BaseSelectedLane',
      'BaseLaneCandidate',
      'Ed25519LaneCandidate',
      'EcdsaLaneCandidate',
      'SelectedEd25519Lane',
      'SelectedEcdsaLane',
      'SelectedLane',
    ]) {
      const alias = sliceTypeAlias(identity, typeName).replace(
        /\bresolvedKey\?:\s*ResolvedEvmFamilyEcdsaKey;?/g,
        '',
      );
      const normalizedAlias = alias.replace(/\bsourceChainTarget\?:\s*never;?/g, '');
      expect(stripNeverOptionalGuards(normalizedAlias), typeName).not.toMatch(/\w+\?:/);
    }

    for (const typeName of [
      'SigningReadyState',
      'ReadyLane',
      'ReauthRequired',
      'PreparedOperation',
    ]) {
      expect(
        stripNeverOptionalGuards(sliceTypeAlias(operationState, typeName)),
        typeName,
      ).not.toMatch(/\w+\?:/);
    }
    expect(operationState).not.toContain('BudgetAdmission');
    expect(operationState).not.toContain('BudgetAdmittedOperation');
    expect(operationState).not.toContain('SignedOperation');

    expect(signingLanes).not.toContain("kind: 'selected_lane'");
    expect(signingLanes).not.toContain("chain: 'near'");
    expect(signingLanes).not.toContain('chain: input.chainTarget.kind');
    expect(signingLanes).not.toContain('): SigningSessionPlanningLane');
    expect(
      stripNeverOptionalGuards(
        sliceTypeAlias(restoreTypes, 'RestorePersistedSessionForSigningInput'),
      ),
    ).not.toMatch(/\w+\?:/);
    expect(sliceTypeAlias(restoreTypes, 'RestorePersistedSessionForSigningInput')).not.toContain(
      "reason: 'session_status'",
    );
    expect(restoreCoordinator).not.toContain('RestorePersistedSessionForSigningMaintenanceInput');
    expect(
      stripNeverOptionalGuards(sliceTypeAlias(planner, 'SigningSessionReadiness')),
    ).not.toMatch(/\w+\?:/);
    expect(sliceTypeAlias(planner, 'SigningSessionReadiness')).not.toContain(
      'backingMaterialSessionId',
    );
    expect(
      stripNeverOptionalGuards(sliceTypeAlias(signingTypes, 'PasskeyReconnectPlan')),
    ).not.toMatch(/\w+\?:/);
    expect(signingBudget).not.toContain('refs: {');
    expect(signingBudget).not.toContain('refs.thresholdSessionId');
    expect(signingBudget).not.toContain('refs.backingMaterialSessionId');

    for (const relativePath of listProductionTypeScriptFiles(
      path.join(signingEngineRoot, 'flows'),
    )) {
      const source = readRepoSource(relativePath);
      expect(source, relativePath).not.toContain('SelectedSigningSessionPlanningLane');
    }
  });

  test('selected-lane construction stays in session identity', () => {
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
      if (isTypeFixture(relativePath)) continue;
      if (relativePath === 'client/src/core/signingEngine/session/identity/laneIdentity.ts')
        continue;
      const source = readRepoSource(relativePath);
      if (source.includes("kind: 'selected_lane'")) offenders.push(relativePath);
    }

    expect(offenders).toEqual([]);
  });

  test('signing execution boundaries do not receive lane candidates or raw records', () => {
    const executionFiles = [
      'client/src/core/signingEngine/interfaces/near.ts',
      'client/src/core/signingEngine/flows/signNear/signTransactions.ts',
      'client/src/core/signingEngine/flows/signNear/signDelegate.ts',
      'client/src/core/signingEngine/flows/signNear/signNep413.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/transactionExecutor.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/signingFlow.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/signEvmWithUiConfirm.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/signEvmFamilyWithUiConfirmForTempo.ts',
    ] as const;
    const forbiddenMarkers = [
      'LaneCandidate',
      'AvailableSigningLanes',
      'availableLane',
      'selectedLaneCandidate',
      'ThresholdEd25519SessionRecord',
      'ThresholdEcdsaSessionRecord',
      'warmRecord',
      'emailOtpReauthRecord',
      'warmKeyRef',
    ] as const;
    const offenders: string[] = [];

    for (const relativePath of executionFiles) {
      const source = readRepoSource(relativePath);
      for (const marker of forbiddenMarkers) {
        if (source.includes(marker)) {
          offenders.push(`${relativePath} contains ${marker}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('deleted duplicate lane shape names stay out of production signing-engine code', () => {
    const removedDuplicateNames = [
      'ConcreteThresholdEcdsaSessionRecord',
      'EcdsaLaneIdentity',
      'ThresholdEcdsaRuntimeLane',
      'ThresholdEd25519SessionLane',
      'NearEd25519TransactionLane',
      'NearEd25519SelectedIdentity',
      'EvmFamilyEcdsaTransactionLane',
      'SigningLaneContext',
      'SelectedSigningLaneContext',
      'ReadyEcdsaLane',
      'Ed25519NearLaneIdentity',
    ] as const;
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
      const source = readRepoSource(relativePath);
      for (const removedName of removedDuplicateNames) {
        const exactName = new RegExp(`\\b${removedName}\\b`);
        if (exactName.test(source)) offenders.push(`${relativePath}: ${removedName}`);
      }
    }

    expect(offenders).toEqual([]);
  });

  test('threshold session kind has one signing-engine owner', () => {
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(path.join(repoRoot, 'client/src'))) {
      const source = readRepoSource(relativePath);
      if (
        source.includes('Ed25519SessionKind') ||
        source.includes('EcdsaSessionKind') ||
        source.includes('ThresholdEcdsaSessionKind') ||
        source.includes('normalizeThresholdEcdsaSessionKind') ||
        source.includes('ed25519SessionTypes') ||
        source.includes('signingEngine/threshold/session/') ||
        source.includes('signingEngine/threshold/workflows/')
      ) {
        offenders.push(relativePath);
      }
    }

    expect(offenders).toEqual([]);
  });

  test('threshold protocol entrypoints take protocol material instead of broad session shapes', () => {
    const protocolFiles = [
      'client/src/core/signingEngine/threshold/ecdsa/authorize.ts',
      'client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts',
      'client/src/core/signingEngine/threshold/ecdsa/presignPool.ts',
      'client/src/core/signingEngine/threshold/ecdsa/sign.ts',
      'client/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts',
    ] as const;
    const broadShapeMarkers = [
      'ThresholdEcdsaSessionRecord',
      'ThresholdEd25519SessionRecord',
      'SigningSessionPlanningLane',
      'SelectedSigningSessionPlanningLane',
      'AvailableSigningLanes',
      'snapshot',
    ] as const;

    for (const relativePath of protocolFiles) {
      const source = readRepoSource(relativePath);
      for (const marker of broadShapeMarkers) {
        expect(source, `${relativePath} must avoid ${marker}`).not.toContain(marker);
      }
    }
  });

  test('Ed25519 HSS client-base reconstruction receives resolved protocol material', () => {
    const source = readRepoSource(
      'client/src/core/signingEngine/threshold/ed25519/hssClientBase.ts',
    );

    expect(source).not.toContain('session/records');
    expect(source).not.toContain('getStoredThresholdEd25519SessionRecord');
  });
});
