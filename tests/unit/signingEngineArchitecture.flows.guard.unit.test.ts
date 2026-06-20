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

test.describe('signing-engine flow architecture guardrails', () => {
  test('shared signing state machine owns the signing operation runner', () => {
    const source = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/shared/signingStateMachine.ts',
    );

    expect(source).not.toContain('plan?: SigningSessionPlan');
    expect(source).not.toContain('SigningExecution');
    expect(source).not.toContain('ReconnectThreshold');
    expect(source).not.toContain('PrepareNonce');
    expect(source).not.toContain('ThresholdReconnected');
    expect(source).not.toContain('NonceReady');
    expect(source).not.toContain('signing_execution_transition');
    expect(source).not.toMatch(/from ['"][.\/]+api\//);
    expect(source).not.toMatch(/from ['"][.\/]+orchestration\//);
    expect(source).not.toMatch(/from ['"][.\/]+chains\//);
  });

  test('EVM-family runtime command tracing uses the shared machine port directly', () => {
    const runtime = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signingFlowRuntime.ts',
    );
    const uiConfirmFlow = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signingFlow.ts',
    );
    const stateMachine = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/shared/signingStateMachine.ts',
    );

    expect(runtime).not.toContain("from '../passkey/runtimeCommandExecutor'");
    expect(runtime).not.toContain('function executeEvmFamilyRuntimeCommand');
    expect(runtime).not.toContain('function wrapEmailOtpSigningWithRuntimeCommands');
    expect(uiConfirmFlow).not.toContain('for (const command of commands)');
    expect(stateMachine).not.toMatch(/from ['"][.\/]+api\//);
    expect(stateMachine).not.toMatch(/from ['"][.\/]+orchestration\//);
  });

  test('NEAR signing flows use shared machine command steps', () => {
    const transactionFlow = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
    );
    const delegateFlow = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts',
    );
    const nep413Flow = readRepoSource('packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts');
    for (const flow of [transactionFlow, delegateFlow, nep413Flow]) {
      expect(flow).not.toContain('runNearSigningOperationCommand');
      expect(flow).not.toContain('SigningOperationCommandKind.ShowConfirmation');
      expect(flow).not.toContain('confirmSigningOperation(');
      expect(flow).not.toContain('stepUpConfirmation/confirmOperation');
      expect(flow).not.toMatch(/from ['"][.\/]+api\//);
      expect(flow).not.toMatch(/from ['"][.\/]+orchestration\//);
    }
    expect(transactionFlow).not.toContain('NearEd25519TransactionLane');
    expect(transactionFlow).not.toContain('validateActionArgsWasm');
    expect(delegateFlow).not.toContain('validateActionArgsWasm');
    expect(transactionFlow).not.toContain('buildNearDisplayModel');
    expect(delegateFlow).not.toContain('buildNearDisplayModel');
  });

  test('available signing lanes own signing-session availability terminology', () => {
    const forbiddenMarkers = [
      'SigningSessionSnapshot',
      'readSigningSessionSnapshot',
      'session/snapshot',
      'snapshotReader',
      'persistedSigningSessionSnapshot',
    ] as const;
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
      const source = readRepoSource(relativePath);
      for (const marker of forbiddenMarkers) {
        if (source.includes(marker)) {
          offenders.push(`${relativePath} contains ${marker}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('confirmation shared contracts are owned outside uiConfirm runtime internals', () => {
    const confirmationChannelTypes = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/stepUpConfirmation/channel/confirmTypes.ts',
    );
    const signingConfirmation = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/shared/signingConfirmation.ts',
    );
    const emailOtpCoordinator = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator.ts',
    );

    expect(confirmationChannelTypes).not.toContain('export const SigningAuthPlanKind');
    expect(confirmationChannelTypes).not.toContain('export type SigningAuthPlan');
    expect(signingConfirmation).not.toContain('formatEmailOtpSentText');
    expect(signingConfirmation).not.toContain('touchConfirm/shared/emailOtpPromptCopy');
    expect(emailOtpCoordinator).not.toContain('requestExportAuthorization');
    expect(emailOtpCoordinator).not.toContain('requestUserConfirmation');
    expect(emailOtpCoordinator).not.toContain('UserConfirmationType');
    for (const relativePath of listProductionTypeScriptFiles(
      path.join(signingEngineRoot, 'flows'),
    )) {
      const source = readRepoSource(relativePath);
      const isSharedConfirmation = relativePath.endsWith('flows/shared/signingConfirmation.ts');
      expect(source, relativePath).not.toContain('stepUpConfirmation/channel/confirmTypes');
      expect(source, relativePath).not.toContain('touchConfirm/shared/displayModel');
      expect(source, relativePath).not.toContain('touchConfirm/handlers/flowOrchestrator');
      expect(source, relativePath).not.toContain('touchConfirm/intentDigestPreparationRegistry');
      expect(source, relativePath).not.toContain('.orchestrateSigningConfirmation(');
      if (!isSharedConfirmation) {
        expect(source, relativePath).not.toContain('stepUpConfirmation/confirmOperation');
        expect(source, relativePath).not.toContain('confirmSigningOperation(');
      }
      expect(source, relativePath).not.toContain('formatEmailOtpSentText');
      expect(source, relativePath).not.toContain('Enter email code to sign');
      expect(source, relativePath).not.toContain('emailOtpSigning.prepare()');
    }
  });

  test('EVM-family post-sign finalization commands live under flows', () => {
    const transactionExecutor = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/transactionExecutor.ts',
    );
    const postSignFinalization = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/postSignFinalization.ts',
    );

    expect(transactionExecutor).not.toContain('thresholdEcdsaRecord?:');
    expect(transactionExecutor).not.toContain('thresholdEcdsaKeyRef?:');
    expect(transactionExecutor).not.toContain('ThresholdEcdsaSessionRecord');
    expect(transactionExecutor).not.toContain('ThresholdEcdsaSecp256k1KeyRef');
    expect(transactionExecutor).not.toContain('warmRecord');
    expect(transactionExecutor).not.toContain('emailOtpReauthRecord');
    expect(transactionExecutor).not.toContain('warmKeyRef');
    expect(transactionExecutor).not.toContain(
      'async function runSuccessfulEvmFamilyPostSignCommands',
    );
    expect(postSignFinalization).not.toMatch(/from ['"][.\/]+api\//);
    expect(postSignFinalization).not.toMatch(/from ['"][.\/]+orchestration\//);
  });

  test('EVM-family threshold admission lives under flows', () => {
    const admission = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/thresholdAdmission.ts',
    );

    expect(admission).not.toMatch(/from ['"][.\/]+api\//);
    expect(admission).not.toMatch(/from ['"][.\/]+orchestration\//);
  });

  test('operation modules do not import SigningEngine or assembly construction', () => {
    const offenders: string[] = [];
    const operationsRoot = path.join(signingEngineRoot, 'flows');

    for (const relativePath of listProductionTypeScriptFiles(operationsRoot)) {
      const source = readRepoSource(relativePath);
      for (const specifier of extractImportSpecifiers(source)) {
        const resolved = resolveSigningEngineImport(relativePath, specifier);
        if (
          resolved === 'packages/sdk-web/src/core/signingEngine' ||
          resolved === 'packages/sdk-web/src/core/signingEngine/SigningEngine' ||
          resolved === 'packages/sdk-web/src/core/signingEngine/SigningEngine.ts' ||
          resolved === 'packages/sdk-web/src/SeamsWeb/assembly/BrowserSigningSurface' ||
          resolved?.startsWith('packages/sdk-web/src/core/signingEngine/assembly')
        ) {
          offenders.push(`${relativePath} -> ${specifier}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('assembly createPorts stays a thin typed aggregator', () => {
    const aggregator = readRepoSource('packages/sdk-web/src/core/signingEngine/assembly/createPorts.ts');
    const operationSpecificMarkers = [
      'resolveThresholdEd25519SessionId',
      'getEmailOtpThresholdEcdsaKeyRefForSigning',
      'requestExportPrivateKeysWithUi',
      'extractCosePublicKey',
      'resolveAccountAuthMethodForSigning',
    ];

    for (const marker of operationSpecificMarkers) {
      expect(aggregator).not.toContain(marker);
    }
  });

  test('WebAuthn P-256 COSE decoding stays behind the eth signer WASM boundary', () => {
    const offenders: string[] = [];
    for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
      const source = readRepoSource(relativePath);
      if (source.includes('webauthnAuth/cose')) offenders.push(relativePath);
      if (source.includes('coseP256PublicKeyToXY')) offenders.push(relativePath);
    }

    expect(offenders).toEqual([]);
  });

  test('new target folders follow the signing-engine import direction contract', () => {
    const offenders: string[] = [];
    const allowedBySourceTopLevel: Record<string, readonly string[]> = {
      assembly: [
        'flows',
        'session',
        'stepUpConfirmation',
        'threshold',
        'chains',
        'workers',
        'workerManager',
        'uiConfirm',
        'webauthnAuth',
        'interfaces',
        'nonce',
        'useCases',
      ],
      flows: [
        'flows',
        'session',
        'stepUpConfirmation',
        'threshold',
        'chains',
        'workers',
        'nonce',
        'interfaces',
        'uiConfirm',
        'webauthnAuth',
        'workerManager',
        'useCases',
      ],
      chains: ['workers', 'workerManager', 'session', 'signers', 'interfaces'],
      stepUpConfirmation: ['interfaces', 'webauthnAuth'],
      uiConfirm: [
        'chains',
        'stepUpConfirmation',
        'interfaces',
        'nonce',
        'session',
        'threshold',
        'webauthnAuth',
        'workerManager',
      ],
      webauthnAuth: [],
      useCases: ['chains', 'interfaces', 'session', 'threshold'],
      workers: [],
    };

    for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
      const sourceTopLevel = signingEngineTopLevel(relativePath);
      if (!sourceTopLevel || !targetContractFolders.includes(sourceTopLevel as never)) continue;

      const source = readRepoSource(relativePath);
      for (const specifier of extractImportSpecifiers(source)) {
        const resolved = resolveSigningEngineImport(relativePath, specifier);
        if (!resolved) continue;
        const targetTopLevel = signingEngineTopLevel(resolved);
        if (!targetTopLevel) continue;
        if (targetTopLevel === sourceTopLevel) continue;

        const allowed = allowedBySourceTopLevel[sourceTopLevel] || [];
        if (!allowed.includes(targetTopLevel)) {
          offenders.push(`${relativePath} -> ${specifier}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('auth prompt and UI runtime boundaries stay one-way', () => {
    const forbiddenByRoot: Record<string, readonly string[]> = {
      webauthnAuth: [
        'stepUpConfirmation',
        'uiConfirm',
        'session',
        'flows',
        'threshold',
        'chains',
        'nonce',
        'workerManager',
      ],
      stepUpConfirmation: [
        'uiConfirm',
        'session',
        'flows',
        'assembly',
        'threshold',
        'chains',
        'nonce',
        'workerManager',
      ],
      uiConfirm: ['flows', 'assembly', 'SigningEngine.ts'],
    };
    const offenders: string[] = [];

    for (const [root, forbiddenTargets] of Object.entries(forbiddenByRoot)) {
      for (const relativePath of listProductionTypeScriptFiles(
        path.join(signingEngineRoot, root),
      )) {
        const source = readRepoSource(relativePath);
        for (const specifier of extractImportSpecifiers(source)) {
          const resolved = resolveSigningEngineImport(relativePath, specifier);
          if (!resolved) continue;
          const targetTopLevel = signingEngineTopLevel(resolved);
          if (targetTopLevel && forbiddenTargets.includes(targetTopLevel)) {
            offenders.push(`${relativePath} -> ${specifier}`);
          }
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('operation flows use uiConfirm only through documented runtime ports', () => {
    const allowedUiConfirmImports = [
      'packages/sdk-web/src/core/signingEngine/uiConfirm/uiConfirm.types',
      'packages/sdk-web/src/core/signingEngine/uiConfirm/ui/export-viewer-host',
    ] as const;
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(
      path.join(signingEngineRoot, 'flows'),
    )) {
      const source = readRepoSource(relativePath);
      for (const specifier of extractImportSpecifiers(source)) {
        const resolved = resolveSigningEngineImport(relativePath, specifier);
        if (!resolved?.startsWith('packages/sdk-web/src/core/signingEngine/uiConfirm')) continue;
        if (!allowedUiConfirmImports.includes(resolved as never)) {
          offenders.push(`${relativePath} -> ${specifier}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('auth-method prompt builders stay under stepUpConfirmation prompt folders', () => {
    const forbiddenPromptOwnerMarkers = [
      'export function formatEmailOtpSentText',
      'export async function prepareEmailOtpSigningPrompt',
      'export async function requestEmailOtpExportAuthorization',
      'Enter email code to sign',
    ] as const;
    const roots = ['flows', 'session'] as const;
    const offenders: string[] = [];

    for (const root of roots) {
      for (const relativePath of listProductionTypeScriptFiles(
        path.join(signingEngineRoot, root),
      )) {
        const source = readRepoSource(relativePath);
        for (const marker of forbiddenPromptOwnerMarkers) {
          if (source.includes(marker)) offenders.push(`${relativePath} contains ${marker}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });
});
