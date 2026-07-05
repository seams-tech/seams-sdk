#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../..');
const signingEngineRoot = path.join(repoRoot, 'packages/sdk-web/src/core/signingEngine');

const targetTopLevelFolders = [
  'assembly',
  'flows',
  'session',
  'stepUpConfirmation',
  'threshold',
  'chains',
  'uiConfirm',
  'workers',
  'nonce',
  'webauthnAuth',
  'useCases',
];

const targetContractFolders = [
  'assembly',
  'flows',
  'chains',
  'stepUpConfirmation',
  'uiConfirm',
  'workers',
  'webauthnAuth',
  'useCases',
];

const allowedSessionFlowImports = new Set([
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/companionSessions.ts -> ../../flows/signEvmFamily/ecdsaMaterialState',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/companionSessions.ts -> ../../flows/signEvmFamily/ecdsaSelection',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts -> ../../flows/signEvmFamily/ecdsaSelection',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecovery.ts -> ../../flows/recovery/ecdsaExportMaterial',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecoveryRuntime.ts -> ../../flows/recovery/ecdsaExportMaterial',
]);

const allowedSessionFlowImportFiles = new Set();
for (const entry of allowedSessionFlowImports) {
  allowedSessionFlowImportFiles.add(entry.split(' -> ')[0] || '');
}

function absolutePath(relativePath) {
  return path.join(repoRoot, relativePath);
}

function readRepoSource(relativePath) {
  return fs.readFileSync(absolutePath(relativePath), 'utf8');
}

function listProductionTypeScriptFiles(dir) {
  if (!fs.existsSync(dir)) {
    return [];
  }

  const files = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listProductionTypeScriptFiles(fullPath));
      continue;
    }
    if (entry.isFile() && fullPath.endsWith('.ts')) {
      files.push(path.relative(repoRoot, fullPath).split(path.sep).join('/'));
    }
  }
  return files;
}

function isTypeFixture(relativePath) {
  return relativePath.endsWith('.typecheck.ts');
}

function extractImportSpecifiers(source) {
  const specifiers = [];
  for (const match of source.matchAll(/\bfrom\s+['"]([^'"]+)['"]|import\s*\(\s*['"]([^'"]+)['"]\s*\)/g)) {
    const specifier = match[1] || match[2];
    if (specifier) {
      specifiers.push(specifier);
    }
  }
  return specifiers;
}

function resolveSigningEngineImport(fromRelativePath, specifier) {
  if (specifier === '@/SeamsWeb/signingSurface/BrowserSigningSurface') {
    return 'packages/sdk-web/src/SeamsWeb/assembly/BrowserSigningSurface';
  }
  if (specifier.startsWith('@/core/signingEngine/')) {
    return `packages/sdk-web/src/core/signingEngine/${specifier.slice(
      '@/core/signingEngine/'.length,
    )}`;
  }
  if (specifier === '@/core/signingEngine') {
    return 'packages/sdk-web/src/core/signingEngine';
  }
  if (!specifier.startsWith('.')) {
    return null;
  }

  const resolved = path.resolve(path.join(repoRoot, path.dirname(fromRelativePath)), specifier);
  const relative = path.relative(repoRoot, resolved).split(path.sep).join('/');
  if (relative === 'packages/sdk-web/src/SeamsWeb/assembly/BrowserSigningSurface') {
    return relative;
  }
  if (!relative.startsWith('packages/sdk-web/src/core/signingEngine')) {
    return null;
  }
  return relative;
}

function signingEngineTopLevel(relativePath) {
  const prefix = 'packages/sdk-web/src/core/signingEngine/';
  if (!relativePath.startsWith(prefix)) {
    return null;
  }
  const first = relativePath.slice(prefix.length).split('/')[0] || null;
  if (first === 'SigningEngine') {
    return 'SigningEngine.ts';
  }
  if (first === 'index') {
    return 'index.ts';
  }
  return first;
}

function sliceTypeAlias(source, name) {
  const start = source.indexOf(`export type ${name}`);
  if (start < 0) {
    throw new Error(`missing exported type ${name}`);
  }
  const next = source.indexOf('\nexport type ', start + 1);
  return source.slice(start, next < 0 ? source.length : next);
}

function stripNeverOptionalGuards(source) {
  return source.replace(/\b\w+\?:\s*never;?/g, '');
}

function assertTrue(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function assertContains(source, marker, context) {
  assertTrue(source.includes(marker), `${context} must contain ${marker}`);
}

function assertNotContains(source, marker, context) {
  assertTrue(!source.includes(marker), `${context} must not contain ${marker}`);
}

function assertNotMatches(source, pattern, context) {
  assertTrue(!pattern.test(source), `${context} must not match ${pattern}`);
}

function assertNoOffenders(offenders, context) {
  if (offenders.length > 0) {
    throw new Error(`${context}:\n${offenders.join('\n')}`);
  }
}

function checkSharedSigningStateMachineOwnsRunner() {
  const source = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/flows/shared/signingStateMachine.ts',
  );

  for (const marker of [
    'plan?: SigningSessionPlan',
    'SigningExecution',
    'ReconnectThreshold',
    'PrepareNonce',
    'ThresholdReconnected',
    'NonceReady',
    'signing_execution_transition',
  ]) {
    assertNotContains(source, marker, 'signingStateMachine.ts');
  }
  assertNotMatches(source, /from ['"][.\/]+api\//, 'signingStateMachine.ts');
  assertNotMatches(source, /from ['"][.\/]+orchestration\//, 'signingStateMachine.ts');
  assertNotMatches(source, /from ['"][.\/]+chains\//, 'signingStateMachine.ts');
}

function checkEvmRuntimeCommandTracingUsesSharedMachinePort() {
  const runtime = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signingFlowRuntime.ts',
  );
  const uiConfirmFlow = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signingFlow.ts',
  );
  const stateMachine = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/flows/shared/signingStateMachine.ts',
  );

  assertNotContains(runtime, "from '../passkey/runtimeCommandExecutor'", 'signingFlowRuntime.ts');
  assertNotContains(runtime, 'function executeEvmFamilyRuntimeCommand', 'signingFlowRuntime.ts');
  assertNotContains(
    runtime,
    'function wrapEmailOtpSigningWithRuntimeCommands',
    'signingFlowRuntime.ts',
  );
  assertNotContains(uiConfirmFlow, 'for (const command of commands)', 'signingFlow.ts');
  assertNotMatches(stateMachine, /from ['"][.\/]+api\//, 'signingStateMachine.ts');
  assertNotMatches(stateMachine, /from ['"][.\/]+orchestration\//, 'signingStateMachine.ts');
}

function checkNearSigningFlowsUseSharedMachineCommandSteps() {
  const flowPaths = [
    'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts',
  ];
  const flowSources = [];
  for (const relativePath of flowPaths) {
    flowSources.push([relativePath, readRepoSource(relativePath)]);
  }

  for (const [relativePath, source] of flowSources) {
    for (const marker of [
      'runNearSigningOperationCommand',
      'SigningOperationCommandKind.ShowConfirmation',
      'confirmSigningOperation(',
      'stepUpConfirmation/confirmOperation',
    ]) {
      assertNotContains(source, marker, relativePath);
    }
    assertNotMatches(source, /from ['"][.\/]+api\//, relativePath);
    assertNotMatches(source, /from ['"][.\/]+orchestration\//, relativePath);
  }

  const transactionFlow = flowSources[0][1];
  const delegateFlow = flowSources[1][1];
  assertNotContains(transactionFlow, 'NearEd25519TransactionLane', flowPaths[0]);
  assertNotContains(transactionFlow, 'validateActionArgsWasm', flowPaths[0]);
  assertNotContains(delegateFlow, 'validateActionArgsWasm', flowPaths[1]);
  assertNotContains(transactionFlow, 'buildNearDisplayModel', flowPaths[0]);
  assertNotContains(delegateFlow, 'buildNearDisplayModel', flowPaths[1]);
}

function checkAvailableSigningLanesOwnAvailabilityTerminology() {
  const forbiddenMarkers = [
    'SigningSessionSnapshot',
    'readSigningSessionSnapshot',
    'session/snapshot',
    'snapshotReader',
    'persistedSigningSessionSnapshot',
  ];
  const offenders = [];

  for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
    const source = readRepoSource(relativePath);
    for (const marker of forbiddenMarkers) {
      if (source.includes(marker)) {
        offenders.push(`${relativePath} contains ${marker}`);
      }
    }
  }

  assertNoOffenders(offenders, 'available signing lanes own availability terminology');
}

function checkConfirmationContractsOwnedOutsideUiRuntimeInternals() {
  const confirmationChannelTypes = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/stepUpConfirmation/channel/confirmTypes.ts',
  );
  const signingConfirmation = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/flows/shared/signingConfirmation.ts',
  );
  const emailOtpCoordinator = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator.ts',
  );

  assertNotContains(
    confirmationChannelTypes,
    'export const SigningAuthPlanKind',
    'confirmTypes.ts',
  );
  assertNotContains(confirmationChannelTypes, 'export type SigningAuthPlan', 'confirmTypes.ts');
  assertNotContains(signingConfirmation, 'formatEmailOtpSentText', 'signingConfirmation.ts');
  assertNotContains(
    signingConfirmation,
    'touchConfirm/shared/emailOtpPromptCopy',
    'signingConfirmation.ts',
  );
  for (const marker of [
    'requestExportAuthorization',
    'requestUserConfirmation',
    'UserConfirmationType',
  ]) {
    assertNotContains(emailOtpCoordinator, marker, 'EmailOtpWalletSessionCoordinator.ts');
  }

  for (const relativePath of listProductionTypeScriptFiles(path.join(signingEngineRoot, 'flows'))) {
    const source = readRepoSource(relativePath);
    const isSharedConfirmation = relativePath.endsWith('flows/shared/signingConfirmation.ts');
    for (const marker of [
      'stepUpConfirmation/channel/confirmTypes',
      'touchConfirm/shared/displayModel',
      'touchConfirm/handlers/flowOrchestrator',
      'touchConfirm/intentDigestPreparationRegistry',
      '.orchestrateSigningConfirmation(',
      'formatEmailOtpSentText',
      'Enter email code to sign',
      'emailOtpSigning.prepare()',
    ]) {
      assertNotContains(source, marker, relativePath);
    }
    if (!isSharedConfirmation) {
      assertNotContains(source, 'stepUpConfirmation/confirmOperation', relativePath);
      assertNotContains(source, 'confirmSigningOperation(', relativePath);
    }
  }
}

function checkEvmPostSignFinalizationCommandsLiveUnderFlows() {
  const transactionExecutor = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/transactionExecutor.ts',
  );
  const postSignFinalization = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/postSignFinalization.ts',
  );

  for (const marker of [
    'thresholdEcdsaRecord?:',
    'thresholdEcdsaKeyRef?:',
    'ThresholdEcdsaSessionRecord',
    'ThresholdEcdsaSecp256k1KeyRef',
    'warmRecord',
    'emailOtpReauthRecord',
    'warmKeyRef',
    'async function runSuccessfulEvmFamilyPostSignCommands',
  ]) {
    assertNotContains(transactionExecutor, marker, 'transactionExecutor.ts');
  }
  assertNotMatches(postSignFinalization, /from ['"][.\/]+api\//, 'postSignFinalization.ts');
  assertNotMatches(postSignFinalization, /from ['"][.\/]+orchestration\//, 'postSignFinalization.ts');
}

function checkEvmThresholdAdmissionLivesUnderFlows() {
  const admission = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/thresholdAdmission.ts',
  );

  assertNotMatches(admission, /from ['"][.\/]+api\//, 'thresholdAdmission.ts');
  assertNotMatches(admission, /from ['"][.\/]+orchestration\//, 'thresholdAdmission.ts');
}

function checkOperationModulesAvoidSigningEngineAssemblyConstruction() {
  const offenders = [];
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

  assertNoOffenders(offenders, 'operation modules must not import SigningEngine or assembly');
}

function checkAssemblyCreatePortsStaysThinAggregator() {
  const aggregator = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/assembly/createPorts.ts',
  );
  const operationSpecificMarkers = [
    'resolveThresholdEd25519SessionId',
    'getEmailOtpThresholdEcdsaKeyRefForSigning',
    'requestExportPrivateKeysWithUi',
    'resolveAccountAuthMethodForSigning',
  ];

  for (const marker of operationSpecificMarkers) {
    assertNotContains(aggregator, marker, 'createPorts.ts');
  }
}

function checkWebAuthnP256CoseDecodingStaysBehindWasmBoundary() {
  const offenders = [];
  for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
    const source = readRepoSource(relativePath);
    if (source.includes('webauthnAuth/cose')) {
      offenders.push(relativePath);
    }
    if (source.includes('coseP256PublicKeyToXY')) {
      offenders.push(relativePath);
    }
  }

  assertNoOffenders(offenders, 'WebAuthn P-256 COSE decoding must stay behind WASM boundary');
}

function checkTargetFoldersFollowImportDirectionContract() {
  const offenders = [];
  const allowedBySourceTopLevel = {
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
      'routerAb',
      'useCases',
    ],
    chains: ['workers', 'workerManager', 'session', 'signers', 'interfaces', 'threshold'],
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
    webauthnAuth: ['interfaces'],
    useCases: ['chains', 'interfaces', 'session', 'threshold'],
    workers: [],
  };

  for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
    const sourceTopLevel = signingEngineTopLevel(relativePath);
    if (!sourceTopLevel || !targetContractFolders.includes(sourceTopLevel)) {
      continue;
    }

    const source = readRepoSource(relativePath);
    for (const specifier of extractImportSpecifiers(source)) {
      const resolved = resolveSigningEngineImport(relativePath, specifier);
      if (!resolved) {
        continue;
      }
      const targetTopLevel = signingEngineTopLevel(resolved);
      if (!targetTopLevel || targetTopLevel === sourceTopLevel) {
        continue;
      }

      const allowed = allowedBySourceTopLevel[sourceTopLevel] || [];
      if (!allowed.includes(targetTopLevel)) {
        offenders.push(`${relativePath} -> ${specifier}`);
      }
    }
  }

  assertNoOffenders(offenders, 'signing-engine import direction contract');
}

function checkAuthPromptAndUiRuntimeBoundariesStayOneWay() {
  const forbiddenByRoot = {
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
  const offenders = [];

  for (const [root, forbiddenTargets] of Object.entries(forbiddenByRoot)) {
    for (const relativePath of listProductionTypeScriptFiles(path.join(signingEngineRoot, root))) {
      const source = readRepoSource(relativePath);
      for (const specifier of extractImportSpecifiers(source)) {
        const resolved = resolveSigningEngineImport(relativePath, specifier);
        if (!resolved) {
          continue;
        }
        const targetTopLevel = signingEngineTopLevel(resolved);
        if (targetTopLevel && forbiddenTargets.includes(targetTopLevel)) {
          offenders.push(`${relativePath} -> ${specifier}`);
        }
      }
    }
  }

  assertNoOffenders(offenders, 'auth prompt and UI runtime boundaries');
}

function checkOperationFlowsUseUiConfirmThroughRuntimePorts() {
  const allowedUiConfirmImports = [
    'packages/sdk-web/src/core/signingEngine/uiConfirm/uiConfirm.types',
    'packages/sdk-web/src/core/signingEngine/uiConfirm/ui/export-viewer-host',
  ];
  const offenders = [];

  for (const relativePath of listProductionTypeScriptFiles(path.join(signingEngineRoot, 'flows'))) {
    const source = readRepoSource(relativePath);
    for (const specifier of extractImportSpecifiers(source)) {
      const resolved = resolveSigningEngineImport(relativePath, specifier);
      if (!resolved?.startsWith('packages/sdk-web/src/core/signingEngine/uiConfirm')) {
        continue;
      }
      if (!allowedUiConfirmImports.includes(resolved)) {
        offenders.push(`${relativePath} -> ${specifier}`);
      }
    }
  }

  assertNoOffenders(offenders, 'operation flows must use uiConfirm through runtime ports');
}

function checkAuthMethodPromptBuildersStayUnderPromptFolders() {
  const forbiddenPromptOwnerMarkers = [
    'export function formatEmailOtpSentText',
    'export async function prepareEmailOtpSigningPrompt',
    'export async function requestEmailOtpExportAuthorization',
    'Enter email code to sign',
  ];
  const roots = ['flows', 'session'];
  const offenders = [];

  for (const root of roots) {
    for (const relativePath of listProductionTypeScriptFiles(path.join(signingEngineRoot, root))) {
      const source = readRepoSource(relativePath);
      for (const marker of forbiddenPromptOwnerMarkers) {
        if (source.includes(marker)) {
          offenders.push(`${relativePath} contains ${marker}`);
        }
      }
    }
  }

  assertNoOffenders(offenders, 'auth-method prompt builders must stay under prompt folders');
}

function checkEcdsaChainTargetPrimitivesLiveInInterfaces() {
  const offenders = [];

  for (const relativePath of listProductionTypeScriptFiles(path.join(repoRoot, 'packages/sdk-web/src'))) {
    const source = readRepoSource(relativePath);
    if (source.includes('signingEngine/session/operationState/ecdsaChainTarget')) {
      offenders.push(relativePath);
    }
  }

  assertNoOffenders(offenders, 'ECDSA chain target primitives must live in interfaces');
}

function checkSelectedLanesAndOperationStatesAvoidOptionalLifecycleFields() {
  const identity = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity.ts',
  );
  const signingLanes = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/operationState/lanes.ts',
  );
  const signingTypes = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/operationState/types.ts',
  );
  const signingBudget = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/budget/budget.ts',
  );
  const signingStateMachine = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/flows/shared/signingStateMachine.ts',
  );
  const planner = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/planning/planner.ts',
  );
  const restoreTypes = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/sealedRecovery/sealedRecovery.types.ts',
  );
  const restoreCoordinator = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/sealedRecovery/restoreCoordinator.ts',
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
    assertNotMatches(stripNeverOptionalGuards(normalizedAlias), /\w+\?:/, typeName);
  }

  const sharedFlowFiles = listProductionTypeScriptFiles(path.join(signingEngineRoot, 'flows/shared'));
  assertTrue(
    !sharedFlowFiles.includes('packages/sdk-web/src/core/signingEngine/flows/shared/operationState.ts'),
    'flows/shared/operationState.ts must stay deleted',
  );
  assertNotContains(signingStateMachine, 'PreparedOperation', 'signingStateMachine.ts');
  assertNotContains(signingStateMachine, 'preparedOperation', 'signingStateMachine.ts');

  for (const marker of [
    "kind: 'selected_lane'",
    "chain: 'near'",
    'chain: input.chainTarget.kind',
    '): SigningSessionPlanningLane',
  ]) {
    assertNotContains(signingLanes, marker, 'operationState/lanes.ts');
  }
  assertNotMatches(
    stripNeverOptionalGuards(sliceTypeAlias(restoreTypes, 'RestorePersistedSessionForSigningInput')),
    /\w+\?:/,
    'RestorePersistedSessionForSigningInput',
  );
  assertNotContains(
    sliceTypeAlias(restoreTypes, 'RestorePersistedSessionForSigningInput'),
    "reason: 'session_status'",
    'RestorePersistedSessionForSigningInput',
  );
  assertNotContains(
    restoreCoordinator,
    'RestorePersistedSessionForSigningMaintenanceInput',
    'restoreCoordinator.ts',
  );
  assertNotMatches(
    stripNeverOptionalGuards(sliceTypeAlias(planner, 'SigningSessionReadiness')),
    /\w+\?:/,
    'SigningSessionReadiness',
  );
  assertNotContains(
    sliceTypeAlias(planner, 'SigningSessionReadiness'),
    'backingMaterialSessionId',
    'SigningSessionReadiness',
  );
  assertNotMatches(
    stripNeverOptionalGuards(sliceTypeAlias(signingTypes, 'PasskeyReconnectPlan')),
    /\w+\?:/,
    'PasskeyReconnectPlan',
  );
  for (const marker of ['refs: {', 'refs.thresholdSessionId', 'refs.backingMaterialSessionId']) {
    assertNotContains(signingBudget, marker, 'budget.ts');
  }

  for (const relativePath of listProductionTypeScriptFiles(path.join(signingEngineRoot, 'flows'))) {
    const source = readRepoSource(relativePath);
    assertNotContains(source, 'SelectedSigningSessionPlanningLane', relativePath);
  }
}

function checkSelectedLaneConstructionStaysInSessionIdentity() {
  const offenders = [];

  for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
    if (isTypeFixture(relativePath)) {
      continue;
    }
    if (relativePath === 'packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity.ts') {
      continue;
    }
    const source = readRepoSource(relativePath);
    if (source.includes("kind: 'selected_lane'")) {
      offenders.push(relativePath);
    }
  }

  assertNoOffenders(offenders, 'selected-lane construction must stay in session identity');
}

function checkSigningExecutionBoundariesAvoidCandidatesAndRawRecords() {
  const executionFiles = [
    'packages/sdk-web/src/core/signingEngine/interfaces/near.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/transactionExecutor.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signingFlow.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmWithUiConfirm.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamilyWithUiConfirmForTempo.ts',
  ];
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
  ];
  const offenders = [];

  for (const relativePath of executionFiles) {
    const source = readRepoSource(relativePath);
    for (const marker of forbiddenMarkers) {
      if (source.includes(marker)) {
        offenders.push(`${relativePath} contains ${marker}`);
      }
    }
  }

  assertNoOffenders(offenders, 'signing execution boundaries must avoid candidates and raw records');
}

function checkDeletedDuplicateLaneNamesStayDeleted() {
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
  ];
  const offenders = [];

  for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
    const source = readRepoSource(relativePath);
    for (const removedName of removedDuplicateNames) {
      const exactName = new RegExp(`\\b${removedName}\\b`);
      if (exactName.test(source)) {
        offenders.push(`${relativePath}: ${removedName}`);
      }
    }
  }

  assertNoOffenders(offenders, 'deleted duplicate lane shape names must stay deleted');
}

function checkThresholdSessionKindHasOneSigningEngineOwner() {
  const offenders = [];

  for (const relativePath of listProductionTypeScriptFiles(path.join(repoRoot, 'packages/sdk-web/src'))) {
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

  assertNoOffenders(offenders, 'threshold session kind must have one signing-engine owner');
}

function checkThresholdProtocolEntrypointsTakeProtocolMaterial() {
  const protocolFiles = [
    'packages/sdk-web/src/core/signingEngine/threshold/ecdsa/activation.ts',
    'packages/sdk-web/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts',
    'packages/sdk-web/src/core/signingEngine/threshold/ecdsa/connectSession.ts',
    'packages/sdk-web/src/core/signingEngine/threshold/ecdsa/keygen.ts',
    'packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/presignaturePool.ts',
    'packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/poolFillRoutes.ts',
    'packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts',
  ];
  const broadShapeMarkers = [
    'ThresholdEcdsaSessionRecord',
    'ThresholdEd25519SessionRecord',
    'SigningSessionPlanningLane',
    'SelectedSigningSessionPlanningLane',
    'AvailableSigningLanes',
    'snapshot',
  ];

  for (const relativePath of protocolFiles) {
    const source = readRepoSource(relativePath);
    for (const marker of broadShapeMarkers) {
      assertNotContains(source, marker, relativePath);
    }
  }
}

function checkEd25519HssClientBaseReconstructionReceivesResolvedProtocolMaterial() {
  const source = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/threshold/ed25519/workerMaterialHandle.ts',
  );

  assertNotContains(source, 'session/records', 'workerMaterialHandle.ts');
  assertNotContains(source, 'getStoredThresholdEd25519SessionRecord', 'workerMaterialHandle.ts');
}

function checkEd25519HssLifecycleLeavesPersistenceToCallers() {
  const source = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts',
  );

  for (const marker of [
    'session/records',
    'persistStoredThresholdEd25519SessionClientBase',
    'persistToThresholdSessionId',
    'persistedThresholdSessionId',
  ]) {
    assertNotContains(source, marker, 'hssLifecycle.ts');
  }
}

function checkThresholdSessionIdentityTypesLiveOutsidePersistenceRecords() {
  const records = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/persistence/records.ts',
  );
  const activation = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts',
  );

  for (const marker of [
    'export type ThresholdEcdsaSessionStoreSource',
    'export type ThresholdEd25519SessionStoreSource',
    'export type ThresholdEcdsaEmailOtpAuthContext',
  ]) {
    assertNotContains(records, marker, 'session/persistence/records.ts');
  }
  assertNotContains(activation, 'session/records', 'passkey/ecdsaBootstrap.ts');
}

function checkEd25519WalletSessionMintHelperHasNoLifecycleCache() {
  const source = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/threshold/ed25519/walletSession.ts',
  );

  for (const marker of [
    'session/records',
    'persistWarmSessionEd25519Capability',
    'buildAndCacheEd25519WalletSession',
    'resolveEd25519WalletSessionBySessionId',
    'walletSessionCache',
  ]) {
    assertNotContains(source, marker, 'threshold/ed25519/walletSession.ts');
  }
}

function checkEd25519ConnectSessionLeavesPersistenceToCallers() {
  const source = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/threshold/ed25519/connectSession.ts',
  );

  for (const marker of [
    'persistWarmSessionEd25519Capability',
    'cacheSigningSessionPrfFirstBestEffort',
    'session/warmCapabilities',
  ]) {
    assertNotContains(source, marker, 'threshold/ed25519/connectSession.ts');
  }
}

function checkThresholdModulesAvoidSessionLifecycleImports() {
  const forbiddenMarkers = [
    'session/records',
    'session/warmCapabilities',
    'api/session/signingSessionState',
  ];
  const offenders = [];

  for (const relativePath of listProductionTypeScriptFiles(path.join(signingEngineRoot, 'threshold'))) {
    if (isTypeFixture(relativePath)) {
      continue;
    }
    const source = readRepoSource(relativePath);
    for (const marker of forbiddenMarkers) {
      if (source.includes(marker)) {
        offenders.push(`${relativePath} contains ${marker}`);
      }
    }
  }

  assertNoOffenders(offenders, 'threshold modules must avoid session lifecycle imports');
}

function checkThresholdProtocolModulesDoNotWriteWarmSessionCacheMaterial() {
  const forbiddenMarkers = ['putWarmSessionMaterial', 'prfFirstCache', 'WarmSessionMaterial'];
  const offenders = [];

  for (const protocolFolder of ['ecdsa', 'ed25519']) {
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

  assertNoOffenders(offenders, 'threshold protocol modules must not write warm-session cache material');
}

function checkSessionChildDomainsDeclareOwnershipReadmes() {
  const requiredHeadings = ['## Owns', '## May Import', '## Must Not Import', '## Entrypoints'];
  const readmePaths = [
    'packages/sdk-web/src/core/signingEngine/session/identity/README.md',
    'packages/sdk-web/src/core/signingEngine/session/availability/README.md',
    'packages/sdk-web/src/core/signingEngine/session/persistence/README.md',
    'packages/sdk-web/src/core/signingEngine/session/sealedRecovery/README.md',
    'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/README.md',
    'packages/sdk-web/src/core/signingEngine/session/passkey/README.md',
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/README.md',
    'packages/sdk-web/src/core/signingEngine/session/operationState/README.md',
    'packages/sdk-web/src/core/signingEngine/session/budget/README.md',
    'packages/sdk-web/src/core/signingEngine/session/planning/README.md',
  ];

  for (const relativePath of readmePaths) {
    const source = readRepoSource(relativePath);
    for (const heading of requiredHeadings) {
      assertContains(source, heading, relativePath);
    }
  }
}

function checkTargetTopLevelFoldersDeclareOwnershipBeforeUse() {
  const requiredHeadings = ['## Owns', '## May Import', '## Must Not Import', '## Entrypoints'];

  for (const folder of targetTopLevelFolders) {
    const folderPath = path.join(signingEngineRoot, folder);
    if (!fs.existsSync(folderPath)) {
      continue;
    }

    const readmePath = path.join(folderPath, 'README.md');
    assertTrue(fs.existsSync(readmePath), `${folder}/README.md must exist`);
    const source = fs.readFileSync(readmePath, 'utf8');
    for (const heading of requiredHeadings) {
      assertContains(source, heading, `${folder}/README.md`);
    }
  }
}

function checkTargetChildFoldersDoNotImportTargetFlowsModules() {
  const offenders = [];

  for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
    if (isTypeFixture(relativePath)) {
      continue;
    }
    const sourceTopLevel = signingEngineTopLevel(relativePath);
    if (!sourceTopLevel || !targetTopLevelFolders.includes(sourceTopLevel)) {
      continue;
    }
    if (sourceTopLevel === 'assembly' || sourceTopLevel === 'flows') {
      continue;
    }

    const source = readRepoSource(relativePath);
    for (const specifier of extractImportSpecifiers(source)) {
      const resolved = resolveSigningEngineImport(relativePath, specifier);
      if (resolved?.startsWith('packages/sdk-web/src/core/signingEngine/flows')) {
        const offender = `${relativePath} -> ${specifier}`;
        if (!allowedSessionFlowImports.has(offender)) {
          offenders.push(offender);
        }
      }
    }
  }

  assertNoOffenders(offenders, 'target child folders must not import target flows modules');
}

function checkSessionChildDomainsAvoidFlowAndAssemblyImports() {
  const domains = [
    'packages/sdk-web/src/core/signingEngine/session/identity',
    'packages/sdk-web/src/core/signingEngine/session/availability',
    'packages/sdk-web/src/core/signingEngine/session/planning',
    'packages/sdk-web/src/core/signingEngine/session/budget',
    'packages/sdk-web/src/core/signingEngine/session/persistence',
    'packages/sdk-web/src/core/signingEngine/session/sealedRecovery',
    'packages/sdk-web/src/core/signingEngine/session/operationState',
    'packages/sdk-web/src/core/signingEngine/session/warmCapabilities',
    'packages/sdk-web/src/core/signingEngine/session/passkey',
    'packages/sdk-web/src/core/signingEngine/session/emailOtp',
  ];
  const forbiddenMarkers = [
    '/flows/',
    '/assembly/',
    "from './SigningEngine'",
    "from '../SigningEngine'",
    "from '@/SeamsWeb/signingSurface/BrowserSigningSurface'",
  ];
  const offenders = [];

  for (const domain of domains) {
    for (const relativePath of listProductionTypeScriptFiles(path.join(repoRoot, domain))) {
      if (isTypeFixture(relativePath)) {
        continue;
      }
      const source = readRepoSource(relativePath);
      for (const marker of forbiddenMarkers) {
        if (marker === '/flows/' && allowedSessionFlowImportFiles.has(relativePath)) {
          continue;
        }
        if (source.includes(marker)) {
          offenders.push(`${relativePath} contains ${marker}`);
        }
      }
    }
  }

  assertNoOffenders(offenders, 'session child domains must avoid flow and assembly imports');
}

function checkSealedRecoveryStaysFreeOfMethodFoldersFlowsAndAssembly() {
  const domainRoot = path.join(
    repoRoot,
    'packages/sdk-web/src/core/signingEngine/session/sealedRecovery',
  );
  const offenders = [];

  for (const relativePath of listProductionTypeScriptFiles(domainRoot)) {
    const source = readRepoSource(relativePath);
    for (const specifier of extractImportSpecifiers(source)) {
      const resolved = resolveSigningEngineImport(relativePath, specifier);
      if (!resolved) {
        continue;
      }
      if (
        resolved.startsWith('packages/sdk-web/src/core/signingEngine/session/passkey/') ||
        resolved.startsWith('packages/sdk-web/src/core/signingEngine/session/emailOtp/') ||
        resolved.startsWith('packages/sdk-web/src/core/signingEngine/flows/') ||
        resolved.startsWith('packages/sdk-web/src/core/signingEngine/assembly/') ||
        resolved === 'packages/sdk-web/src/SeamsWeb/assembly/BrowserSigningSurface'
      ) {
        offenders.push(`${relativePath} -> ${specifier}`);
      }
    }
  }

  assertNoOffenders(offenders, 'sealedRecovery must stay free of method folders, flows, and assembly');
}

function checkSessionChildDomainsUseAllowedSiblingDomains() {
  const allowedSiblingDomains = {
    identity: [
      'availability',
      'keyMaterialBrands',
      'operationState',
      'persistence',
      'routerAbSigningWalletSession',
    ],
    availability: [
      'keyMaterialBrands',
      'identity',
      'operationState',
      'persistence',
      'routerAbSigningWalletSession',
      'warmCapabilities',
      'budget',
      'planning',
      'sealedRecovery',
    ],
    planning: ['identity', 'operationState'],
    budget: ['persistence', 'operationState', 'identity'],
    persistence: [
      'identity',
      'keyMaterialBrands',
      'sealedRecovery',
      'operationState',
      'warmCapabilities',
    ],
    sealedRecovery: ['identity', 'keyMaterialBrands', 'persistence'],
    operationState: [
      'budget',
      'emailOtp',
      'identity',
      'persistence',
      'planning',
      'routerAbSigningWalletSession',
      'warmCapabilities',
    ],
    warmCapabilities: [
      'availability',
      'budget',
      'emailOtp',
      'identity',
      'keyMaterialBrands',
      'operationState',
      'persistence',
      'routerAbSigningWalletSession',
    ],
    passkey: [
      'identity',
      'keyMaterialBrands',
      'persistence',
      'operationState',
      'routerAbSigningWalletSession',
      'sealedRecovery',
      'warmCapabilities',
    ],
    emailOtp: [
      'availability',
      'budget',
      'identity',
      'keyMaterialBrands',
      'operationState',
      'persistence',
      'routerAbSigningWalletSession',
      'sealedRecovery',
      'warmCapabilities',
    ],
  };
  const offenders = [];

  for (const [sourceDomain, allowedTargets] of Object.entries(allowedSiblingDomains)) {
    const domainRoot = path.join(
      repoRoot,
      `packages/sdk-web/src/core/signingEngine/session/${sourceDomain}`,
    );

    for (const relativePath of listProductionTypeScriptFiles(domainRoot)) {
      if (isTypeFixture(relativePath)) {
        continue;
      }
      const source = readRepoSource(relativePath);
      for (const specifier of extractImportSpecifiers(source)) {
        const resolved = resolveSigningEngineImport(relativePath, specifier);
        if (!resolved?.startsWith('packages/sdk-web/src/core/signingEngine/session/')) {
          continue;
        }

        const tail = resolved.slice('packages/sdk-web/src/core/signingEngine/session/'.length);
        const targetDomain = tail.split('/')[0];
        if (!targetDomain || targetDomain === sourceDomain || targetDomain === 'public.ts') {
          continue;
        }
        if (!allowedTargets.includes(targetDomain)) {
          offenders.push(`${relativePath} -> ${specifier} (${sourceDomain} -> ${targetDomain})`);
        }
      }
    }
  }

  assertNoOffenders(offenders, 'session child domains must use allowed sibling domains');
}

function checkChildSessionDomainsDoNotImportCoordinator() {
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
  ];
  const coordinatorPath = 'packages/sdk-web/src/core/signingEngine/session/SigningSessionCoordinator.ts';
  const offenders = [];

  for (const domain of childDomains) {
    const domainRoot = path.join(
      repoRoot,
      `packages/sdk-web/src/core/signingEngine/session/${domain}`,
    );
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

  assertNoOffenders(offenders, 'child session domains must not import SigningSessionCoordinator');
}

function checkCoordinatorStaysFreeOfMethodSpecificSessionDomains() {
  const source = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/SigningSessionCoordinator.ts',
  );
  const offenders = [];

  for (const specifier of extractImportSpecifiers(source)) {
    const resolved = resolveSigningEngineImport(
      'packages/sdk-web/src/core/signingEngine/session/SigningSessionCoordinator.ts',
      specifier,
    );
    if (!resolved?.startsWith('packages/sdk-web/src/core/signingEngine/session/')) {
      continue;
    }
    if (
      resolved.startsWith('packages/sdk-web/src/core/signingEngine/session/passkey/') ||
      resolved.startsWith('packages/sdk-web/src/core/signingEngine/session/emailOtp/')
    ) {
      offenders.push(`${specifier} -> ${resolved}`);
    }
  }

  assertNoOffenders(offenders, 'SigningSessionCoordinator must stay free of method-specific domains');
}

function checkCoordinatorOnlyImportsOrchestrationSessionDomains() {
  const relativePath = 'packages/sdk-web/src/core/signingEngine/session/SigningSessionCoordinator.ts';
  const source = readRepoSource(relativePath);
  const allowedSessionDomains = new Set([
    'planning',
    'availability',
    'budget',
    'persistence',
    'operationState',
    'warmCapabilities',
    'identity',
  ]);
  const offenders = [];

  for (const specifier of extractImportSpecifiers(source)) {
    const resolved = resolveSigningEngineImport(relativePath, specifier);
    if (!resolved?.startsWith('packages/sdk-web/src/core/signingEngine/session/')) {
      continue;
    }
    const tail = resolved.slice('packages/sdk-web/src/core/signingEngine/session/'.length);
    const targetDomain = tail.split('/')[0];
    if (!targetDomain || targetDomain === 'SigningSessionCoordinator.ts') {
      continue;
    }
    if (targetDomain === 'public.ts') {
      continue;
    }
    if (!allowedSessionDomains.has(targetDomain)) {
      offenders.push(`${specifier} -> ${resolved}`);
    }
  }

  assertNoOffenders(offenders, 'SigningSessionCoordinator must only import orchestration domains');
}

function checkSigningFlowsOnlyImportCoordinatorAsSessionCoordinator() {
  const offenders = [];
  const allowedCoordinatorPrefix =
    'packages/sdk-web/src/core/signingEngine/session/SigningSessionCoordinator';

  for (const relativePath of listProductionTypeScriptFiles(path.join(signingEngineRoot, 'flows'))) {
    const source = readRepoSource(relativePath);
    for (const specifier of extractImportSpecifiers(source)) {
      const resolved = resolveSigningEngineImport(relativePath, specifier);
      if (!resolved?.startsWith('packages/sdk-web/src/core/signingEngine/session/')) {
        continue;
      }
      if (!resolved.includes('Coordinator')) {
        continue;
      }
      if (resolved !== allowedCoordinatorPrefix && resolved !== `${allowedCoordinatorPrefix}.ts`) {
        offenders.push(`${relativePath} -> ${specifier} -> ${resolved}`);
      }
    }
  }

  assertNoOffenders(offenders, 'signing flows must only import SigningSessionCoordinator as coordinator');
}

function runChecks() {
  checkSharedSigningStateMachineOwnsRunner();
  checkEvmRuntimeCommandTracingUsesSharedMachinePort();
  checkNearSigningFlowsUseSharedMachineCommandSteps();
  checkAvailableSigningLanesOwnAvailabilityTerminology();
  checkConfirmationContractsOwnedOutsideUiRuntimeInternals();
  checkEvmPostSignFinalizationCommandsLiveUnderFlows();
  checkEvmThresholdAdmissionLivesUnderFlows();
  checkOperationModulesAvoidSigningEngineAssemblyConstruction();
  checkAssemblyCreatePortsStaysThinAggregator();
  checkWebAuthnP256CoseDecodingStaysBehindWasmBoundary();
  checkTargetFoldersFollowImportDirectionContract();
  checkAuthPromptAndUiRuntimeBoundariesStayOneWay();
  checkOperationFlowsUseUiConfirmThroughRuntimePorts();
  checkAuthMethodPromptBuildersStayUnderPromptFolders();
  checkEcdsaChainTargetPrimitivesLiveInInterfaces();
  checkSelectedLanesAndOperationStatesAvoidOptionalLifecycleFields();
  checkSelectedLaneConstructionStaysInSessionIdentity();
  checkSigningExecutionBoundariesAvoidCandidatesAndRawRecords();
  checkDeletedDuplicateLaneNamesStayDeleted();
  checkThresholdSessionKindHasOneSigningEngineOwner();
  checkThresholdProtocolEntrypointsTakeProtocolMaterial();
  checkEd25519HssClientBaseReconstructionReceivesResolvedProtocolMaterial();
  checkEd25519HssLifecycleLeavesPersistenceToCallers();
  checkThresholdSessionIdentityTypesLiveOutsidePersistenceRecords();
  checkEd25519WalletSessionMintHelperHasNoLifecycleCache();
  checkEd25519ConnectSessionLeavesPersistenceToCallers();
  checkThresholdModulesAvoidSessionLifecycleImports();
  checkThresholdProtocolModulesDoNotWriteWarmSessionCacheMaterial();
  checkSessionChildDomainsDeclareOwnershipReadmes();
  checkTargetTopLevelFoldersDeclareOwnershipBeforeUse();
  checkTargetChildFoldersDoNotImportTargetFlowsModules();
  checkSessionChildDomainsAvoidFlowAndAssemblyImports();
  checkSealedRecoveryStaysFreeOfMethodFoldersFlowsAndAssembly();
  checkSessionChildDomainsUseAllowedSiblingDomains();
  checkChildSessionDomainsDoNotImportCoordinator();
  checkCoordinatorStaysFreeOfMethodSpecificSessionDomains();
  checkCoordinatorOnlyImportsOrchestrationSessionDomains();
  checkSigningFlowsOnlyImportCoordinatorAsSessionCoordinator();
}

runChecks();
console.log('[check-signing-engine-architecture-boundaries] passed');
