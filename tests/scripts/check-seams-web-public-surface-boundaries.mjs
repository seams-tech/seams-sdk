#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../..');
const seamsWebImplementationPath = 'packages/sdk-web/src/SeamsWeb/SeamsWeb.ts';

const topLevelWalletSessionMethods = [
  'unlock',
  'lock',
  'getWalletSession',
  'getRecentUnlocks',
  'hasPasskeyCredential',
  'prefillRouterAbEcdsaDerivationPresignaturePool',
];

const topLevelRegistrationMethods = [
  'registerWallet',
  'addWalletSigner',
  'registerWithEmailOtp',
  'registerPasskey',
];

const authMethods = [
  'requestEmailOtpChallenge',
  'requestEmailOtpSigningSessionChallenge',
  'exchangeGoogleEmailOtpSession',
  'loginWithEmailOtpEcdsaCapability',
  'refreshEmailOtpSigningSession',
];

const registrationMethods = [
  'requestEmailOtpEnrollmentChallenge',
  'enrollEmailOtp',
  'enrollAndLoginWithEmailOtpEcdsaCapability',
];

const recoveryMethods = ['getEmailOtpRecoveryCodeStatus', 'rotateEmailOtpRecoveryCodes'];

const deviceMethodFragments = [
  'startDevice2LinkingFlow',
  'stopDevice2LinkingFlow',
  'linkDeviceWithScannedQRData',
  'viewAccessKeyList',
  'deleteDeviceKey',
];

const preferencesMethodFragments = [
  'setConfirmBehavior',
  'setConfirmationConfig',
  'getConfirmationConfig',
];

const advancedSymbols = [
  'MinimalNearClient',
  'createEvmClient',
  'parseEvmRpcHexQuantity',
  'base64UrlEncode',
  'base64UrlDecode',
  'createIntentId',
  'TEMPO_FEE_MANAGER_CONTRACT',
  'encodeTempoSetUserTokenCalldata',
  'nearAccountRefFromAccountId',
  'thresholdEcdsaChainTargetFromConfig',
  'walletSessionRefFromSession',
  'toWalletId',
  'walletIdFromWalletProfile',
];

const deletedLifecycleNames = [
  'initializeCurrentUser',
  'storeWalletEd25519SignerRecord',
  'storeWalletEcdsaRegistrationData',
  'persistWalletRegistrationEcdsaSessions',
];

const allowedCoreWalletIframePrimitiveFiles = [
  'packages/sdk-web/src/core/browser/walletIframe/csp-stylesheet.ts',
  'packages/sdk-web/src/core/browser/walletIframe/events.ts',
  'packages/sdk-web/src/core/browser/walletIframe/host-mode.ts',
  'packages/sdk-web/src/core/browser/walletIframe/hostVariant.ts',
];

function absolutePath(relativePath) {
  return path.join(repoRoot, relativePath);
}

function readRepoSource(relativePath) {
  return fs.readFileSync(absolutePath(relativePath), 'utf8');
}

function readRepoJson(relativePath) {
  return JSON.parse(readRepoSource(relativePath));
}

function listTypeScriptFiles(relativeDir) {
  const absoluteDir = absolutePath(relativeDir);
  if (!fs.existsSync(absoluteDir)) return [];
  return fs.readdirSync(absoluteDir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry.name).split(path.sep).join('/');
    if (entry.isDirectory()) return listTypeScriptFiles(relativePath);
    return /\.(ts|tsx)$/.test(entry.name) ? [relativePath] : [];
  });
}

function sourceBlock(source, pattern, label) {
  const block = source.match(pattern)?.[0] ?? '';
  if (!block) {
    throw new Error(`Missing source block: ${label}`);
  }
  return block;
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function collectWebModulesRuntimeServiceViolations() {
  const allowedPrefixes = ['packages/sdk-web/src/SeamsWeb/assembly/'];
  const sourceFiles = [
    ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb'),
    ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb/walletIframe'),
  ].filter((relativePath) => !allowedPrefixes.some((prefix) => relativePath.startsWith(prefix)));

  return sourceFiles
    .filter((relativePath) => /signingRuntime\.services/.test(readRepoSource(relativePath)))
    .map((relativePath) => `${relativePath}: accesses signingRuntime.services outside assembly`);
}

function collectSigningRuntimeEscapeViolations() {
  const violations = [];
  const interfacesSource = readRepoSource('packages/sdk-web/src/SeamsWeb/signingSurface/types.ts');
  const contextBlock = sourceBlock(
    interfacesSource,
    /export type SeamsWebContext\s*=[^;]+;/m,
    'SeamsWebContext',
  );
  if (/\bsigningRuntime\b/.test(contextBlock)) {
    violations.push('SeamsWebContext exposes signingRuntime');
  }

  const surfaceBlock = sourceBlock(
    interfacesSource,
    /export interface SeamsWebSigningSurface[\s\S]*?^}/m,
    'SeamsWebSigningSurface',
  );
  if (/\bsigningRuntime\b/.test(surfaceBlock)) {
    violations.push('SeamsWebSigningSurface exposes signingRuntime');
  }

  const assemblySource = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts',
  );
  if (/^\s*readonly\s+signingRuntime\b/m.test(assemblySource)) {
    violations.push('BrowserSigningSurface exposes signingRuntime as a public readonly field');
  }
  if (!/\bprivate\s+readonly\s+signingRuntime\b/.test(assemblySource)) {
    violations.push('BrowserSigningSurface no longer keeps signingRuntime private readonly');
  }

  const sourceFiles = [
    ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb'),
    ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb/walletIframe'),
  ].filter(
    (relativePath) =>
      !relativePath.startsWith('packages/sdk-web/src/SeamsWeb/assembly/') &&
      relativePath !== 'packages/sdk-web/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts',
  );

  for (const relativePath of sourceFiles) {
    const source = readRepoSource(relativePath);
    if (/signingEngine\.signingRuntime/.test(source)) {
      violations.push(`${relativePath}: accesses signingEngine.signingRuntime`);
    }
    if (/from\s+['"]@\/core\/runtime\/types['"]/.test(source)) {
      violations.push(`${relativePath}: imports core runtime types`);
    }
  }

  return violations;
}

function collectInternalRegistrationMethodViolations() {
  const violations = [];
  const legacyRegistrationMethodPattern = new RegExp(`\\bregisterPasskey${'Internal'}\\b`);
  const interfacesSource = readRepoSource('packages/sdk-web/src/SeamsWeb/publicApi/types.ts');
  const registrationCapabilityBlock = sourceBlock(
    interfacesSource,
    /export interface RegistrationCapability\s*{[\s\S]*?^}/m,
    'RegistrationCapability',
  );

  if (legacyRegistrationMethodPattern.test(registrationCapabilityBlock)) {
    violations.push('RegistrationCapability exposes legacy internal registration method');
  }

  for (const relativePath of [
    seamsWebImplementationPath,
    'packages/sdk-web/src/SeamsWeb/walletIframe/SeamsWebIframe.ts',
  ]) {
    if (legacyRegistrationMethodPattern.test(readRepoSource(relativePath))) {
      violations.push(`${relativePath}: references legacy internal registration method`);
    }
  }

  return violations;
}

function collectNamespaceViolations() {
  return [
    ...collectMethodNamespaceViolations({
      capability: 'auth',
      declaration: /readonly auth: AuthCapability;/,
      methods: topLevelWalletSessionMethods,
    }),
    ...collectMethodNamespaceViolations({
      capability: 'registration',
      declaration: /readonly registration: RegistrationCapability;/,
      methods: topLevelRegistrationMethods,
    }),
    ...collectEmailOtpNamespaceViolations(),
    ...collectDeviceNamespaceViolations(),
    ...collectPreferenceNamespaceViolations(),
  ];
}

function collectMethodNamespaceViolations(input) {
  const violations = [];
  const seamsWebSource = readRepoSource(seamsWebImplementationPath);
  const iframeFacadeSource = readRepoSource('packages/sdk-web/src/SeamsWeb/walletIframe/SeamsWebIframe.ts');

  for (const methodName of input.methods) {
    if (new RegExp(`^\\s*async\\s+${methodName}\\s*\\(`, 'm').test(seamsWebSource)) {
      violations.push(`SeamsWeb exposes top-level ${input.capability} method ${methodName}`);
    }
    if (new RegExp(`^\\s*async\\s+${methodName}\\s*\\(`, 'm').test(iframeFacadeSource)) {
      violations.push(`SeamsWebIframe exposes top-level ${input.capability} method ${methodName}`);
    }
  }

  if (!input.declaration.test(seamsWebSource)) {
    violations.push(`SeamsWeb missing ${input.capability} capability declaration`);
  }
  if (!input.declaration.test(iframeFacadeSource)) {
    violations.push(`SeamsWebIframe missing ${input.capability} capability declaration`);
  }

  return violations;
}

function collectEmailOtpNamespaceViolations() {
  const violations = [];
  const seamsWebSource = readRepoSource(seamsWebImplementationPath);
  const interfacesSource = readRepoSource('packages/sdk-web/src/SeamsWeb/publicApi/types.ts');
  const authCapabilityBlock = sourceBlock(
    interfacesSource,
    /export interface AuthCapability\s*{[\s\S]*?^}/m,
    'AuthCapability',
  );
  const registrationCapabilityBlock = sourceBlock(
    interfacesSource,
    /export interface RegistrationCapability\s*{[\s\S]*?^}/m,
    'RegistrationCapability',
  );
  const recoveryCapabilityBlock = sourceBlock(
    interfacesSource,
    /export interface RecoveryCapability\s*{[\s\S]*?^}/m,
    'RecoveryCapability',
  );

  for (const methodName of authMethods) {
    if (!authCapabilityBlock.includes(methodName)) {
      violations.push(`AuthCapability missing Email OTP method ${methodName}`);
    }
  }
  for (const methodName of registrationMethods) {
    if (!registrationCapabilityBlock.includes(methodName)) {
      violations.push(`RegistrationCapability missing Email OTP method ${methodName}`);
    }
  }
  for (const methodName of recoveryMethods) {
    if (!recoveryCapabilityBlock.includes(methodName)) {
      violations.push(`RecoveryCapability missing Email OTP method ${methodName}`);
    }
  }
  for (const methodName of [...authMethods, ...registrationMethods, ...recoveryMethods]) {
    if (new RegExp(`^\\s*async\\s+${methodName}\\s*\\(`, 'm').test(seamsWebSource)) {
      violations.push(`SeamsWeb exposes top-level Email OTP method ${methodName}`);
    }
  }
  if (/export interface EmailOtpCapability\s*{/.test(interfacesSource)) {
    violations.push('public API reintroduced EmailOtpCapability');
  }
  if (/readonly emailOtp:/.test(seamsWebSource)) {
    violations.push('SeamsWeb reintroduced readonly emailOtp capability');
  }

  return violations;
}

function collectDeviceNamespaceViolations() {
  const violations = [];
  const seamsWebSource = readRepoSource(seamsWebImplementationPath);
  const interfacesSource = readRepoSource('packages/sdk-web/src/SeamsWeb/publicApi/types.ts');
  const recoveryCapabilityBlock = sourceBlock(
    interfacesSource,
    /export interface RecoveryCapability\s*{[\s\S]*?^}/m,
    'RecoveryCapability',
  );
  const devicesCapabilityBlock = sourceBlock(
    interfacesSource,
    /export interface DevicesCapability\s*{[\s\S]*?^}/m,
    'DevicesCapability',
  );

  for (const methodName of deviceMethodFragments) {
    if (recoveryCapabilityBlock.includes(methodName)) {
      violations.push(`RecoveryCapability contains device method ${methodName}`);
    }
    if (!devicesCapabilityBlock.includes(methodName)) {
      violations.push(`DevicesCapability missing device method ${methodName}`);
    }
    if (new RegExp(`^\\s*async\\s+${methodName}\\s*\\(`, 'm').test(seamsWebSource)) {
      violations.push(`SeamsWeb exposes top-level device method ${methodName}`);
    }
  }
  if (!/readonly devices: DevicesCapability;/.test(seamsWebSource)) {
    violations.push('SeamsWeb missing devices capability declaration');
  }

  return violations;
}

function collectPreferenceNamespaceViolations() {
  const violations = [];
  const seamsWebSource = readRepoSource(seamsWebImplementationPath);
  const iframeFacadeSource = readRepoSource('packages/sdk-web/src/SeamsWeb/walletIframe/SeamsWebIframe.ts');

  for (const methodName of preferencesMethodFragments) {
    if (new RegExp(`^\\s*${methodName}\\s*\\(`, 'm').test(seamsWebSource)) {
      violations.push(`SeamsWeb exposes top-level preference method ${methodName}`);
    }
    if (new RegExp(`^\\s*async\\s+${methodName}\\s*\\(`, 'm').test(seamsWebSource)) {
      violations.push(`SeamsWeb exposes async top-level preference method ${methodName}`);
    }
    if (new RegExp(`^\\s*${methodName}\\s*\\(`, 'm').test(iframeFacadeSource)) {
      violations.push(`SeamsWebIframe exposes top-level preference method ${methodName}`);
    }
  }
  if (!/readonly preferences: PreferencesCapability;/.test(seamsWebSource)) {
    violations.push('SeamsWeb missing preferences capability declaration');
  }
  if (!/readonly preferences: PreferencesCapability;/.test(iframeFacadeSource)) {
    violations.push('SeamsWebIframe missing preferences capability declaration');
  }

  return violations;
}

function collectAdvancedExportViolations() {
  const violations = [];
  const rootSource = readRepoSource('packages/sdk-web/src/index.ts');
  const advancedSource = readRepoSource('packages/sdk-web/src/advanced.ts');
  const packageJson = readRepoJson('packages/sdk-web/package.json');

  for (const symbol of advancedSymbols) {
    if (rootSource.includes(symbol)) {
      violations.push(`root SDK export exposes advanced symbol ${symbol}`);
    }
    if (!advancedSource.includes(symbol)) {
      violations.push(`advanced SDK subpath missing symbol ${symbol}`);
    }
  }
  if (!Object.prototype.hasOwnProperty.call(packageJson.exports, './advanced')) {
    violations.push('package exports missing ./advanced');
  }

  return violations;
}

function collectRpcFacadeImportViolations() {
  return listTypeScriptFiles('packages/sdk-web/src/core/rpcClients')
    .filter((relativePath) => /from\s+['"]@\/SeamsWeb(?:['"/])/.test(readRepoSource(relativePath)))
    .map((relativePath) => `${relativePath}: imports SeamsWeb facade types`);
}

function collectLocalSignerClassViolations() {
  const sourceFiles = [
    ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb/operations/near'),
    ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb/operations/tempo'),
    ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb/operations/evm'),
    'packages/sdk-web/src/SeamsWeb/publicApi/near.ts',
    'packages/sdk-web/src/SeamsWeb/publicApi/tempo.ts',
    'packages/sdk-web/src/SeamsWeb/publicApi/evm.ts',
  ];

  return sourceFiles
    .filter((relativePath) =>
      /\b(?:class|new)\s+(?:NearSigner|TempoSigner|EvmSigner)\b/.test(readRepoSource(relativePath)),
    )
    .map((relativePath) => `${relativePath}: reintroduced local signer class`);
}

function collectLifecycleNameViolations() {
  const violations = [];
  const sourceFiles = [
    ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb'),
    ...listTypeScriptFiles('packages/sdk-web/src/core/signingEngine/flows/registration'),
  ];
  for (const relativePath of sourceFiles) {
    const source = readRepoSource(relativePath);
    for (const name of deletedLifecycleNames) {
      if (new RegExp(`\\b${name}\\b`).test(source)) {
        violations.push(`${relativePath}: ${name}`);
      }
    }
  }

  const browserSurfaceSource = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts',
  );
  if (!/\basync\s+signEvmFamily\s*\(/.test(browserSurfaceSource)) {
    violations.push('BrowserSigningSurface missing signEvmFamily method');
  }
  if (/\basync\s+signTempo\s*\(/.test(browserSurfaceSource)) {
    violations.push('BrowserSigningSurface reintroduced signTempo method');
  }

  const tempoCapabilitySource = readRepoSource('packages/sdk-web/src/SeamsWeb/publicApi/tempo.ts');
  if (!tempoCapabilitySource.includes('TempoSigningSurface')) {
    violations.push('tempo public API no longer uses TempoSigningSurface');
  }
  if (tempoCapabilitySource.includes("SeamsWebContext['signingEngine']")) {
    violations.push('tempo public API depends on broad SeamsWebContext signingEngine');
  }
  if (!tempoCapabilitySource.includes('deps.signingEngine.signEvmFamily')) {
    violations.push('tempo public API no longer delegates through signEvmFamily');
  }
  if (/lifecycle:\s*tempoCapability\b/.test(tempoCapabilitySource)) {
    violations.push('tempo public API reintroduced tempoCapability lifecycle name');
  }

  return violations;
}

function collectBroadDependencyViolations() {
  const violations = [];
  for (const relativePath of listTypeScriptFiles('packages/sdk-web/src/SeamsWeb')) {
    if (/SeamsWebContext\['signingEngine'\]/.test(readRepoSource(relativePath))) {
      violations.push(`${relativePath}: uses broad SeamsWebContext signingEngine dependency`);
    }
  }

  const operationRoots = [
    'packages/sdk-web/src/SeamsWeb/operations',
    'packages/sdk-web/src/SeamsWeb/publicApi',
  ];
  for (const root of operationRoots) {
    for (const relativePath of listTypeScriptFiles(root)) {
      const source = readRepoSource(relativePath);
      for (const pattern of [/\bSeamsWebSigningSurface\b/, /Pick\s*<\s*SeamsWebSigningSurface\b/]) {
        if (pattern.test(source)) {
          violations.push(`${relativePath}: ${pattern.source}`);
        }
      }
    }
  }

  const signingSurfaceTypes = readRepoSource('packages/sdk-web/src/SeamsWeb/signingSurface/types.ts');
  const signingSurfacePorts = readRepoSource('packages/sdk-web/src/SeamsWeb/signingSurface/ports.ts');
  const aggregateMatch =
    signingSurfaceTypes.match(/export interface SeamsWebSigningSurface[\s\S]*?^}/m)?.[0] ?? '';
  if (!/extends[\s\S]*?\bRpIdSurface\b/.test(aggregateMatch)) {
    violations.push('SeamsWebSigningSurface no longer extends RpIdSurface');
  }
  if (aggregateMatch.includes('storeWalletEcdsaSignerRecords(')) {
    violations.push('SeamsWebSigningSurface reintroduced storeWalletEcdsaSignerRecords');
  }
  if (/Pick\s*<\s*SeamsWebSigningSurface\b/.test(signingSurfaceTypes)) {
    violations.push('signing surface types reintroduced Pick<SeamsWebSigningSurface>');
  }
  if (
    /export interface (Auth|Registration|NearSigner|TempoSigner|EvmSigner|Recovery|Devices|KeyExport|Preferences)Capability\b/.test(
      signingSurfaceTypes,
    )
  ) {
    violations.push('signing surface types own public capability interfaces');
  }
  if (!signingSurfaceTypes.includes("export type * from '../publicApi/types'")) {
    violations.push('signing surface types no longer re-export public API types');
  }
  if (!signingSurfacePorts.includes('export type SeamsWebBaseContext<TSigningEngine>')) {
    violations.push('signing surface ports missing SeamsWebBaseContext');
  }
  if (/Omit\s*<\s*SeamsWebContext\b/.test(signingSurfacePorts)) {
    violations.push('signing surface ports reintroduced Omit<SeamsWebContext>');
  }

  return violations;
}

function collectRawContextViolations() {
  const violations = [];
  const allowedFiles = [
    seamsWebImplementationPath,
    'packages/sdk-web/src/SeamsWeb/signingSurface/types.ts',
  ];
  const rawContextPatterns = [
    /\bcontext\s*:\s*SeamsWebContext\b/,
    /\bgetContext\s*:\s*\(\)\s*=>\s*SeamsWebContext\b/,
  ];

  for (const relativePath of listTypeScriptFiles('packages/sdk-web/src/SeamsWeb')) {
    if (allowedFiles.includes(relativePath)) continue;
    const source = readRepoSource(relativePath);
    for (const pattern of rawContextPatterns) {
      if (pattern.test(source)) {
        violations.push(`${relativePath}: ${pattern.source}`);
      }
    }
    if (/\bSeamsWebContext\b/.test(source)) {
      violations.push(`${relativePath}: references broad SeamsWebContext`);
    }
  }

  return violations;
}

function collectImportDirectionViolations() {
  const violations = [];

  violations.push(
    ...listTypeScriptFiles('packages/sdk-web/src/core')
      .filter((relativePath) => /from\s+['"](?:@\/web\/|\.\.?\/.*web\/)/.test(readRepoSource(relativePath)))
      .map((relativePath) => `${relativePath}: core imports web layer`),
  );
  violations.push(
    ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb/operations')
      .filter((relativePath) =>
        /from\s+['"](?:@\/SeamsWeb\/facade\/|\.\.?\/.*facade\/)/.test(readRepoSource(relativePath)),
      )
      .map((relativePath) => `${relativePath}: operations import facade layer`),
  );
  violations.push(
    ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb/signingSurface')
      .filter((relativePath) => relativePath !== 'packages/sdk-web/src/SeamsWeb/signingSurface/types.ts')
      .filter((relativePath) =>
        /from\s+['"](?:@\/SeamsWeb\/publicApi\/|\.\.?\/.*publicApi\/)/.test(readRepoSource(relativePath)),
      )
      .map((relativePath) => `${relativePath}: signing surface imports public API implementation`),
  );
  violations.push(
    ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb/publicApi')
      .filter((relativePath) =>
        /from\s+['"](?:@\/SeamsWeb\/assembly\/|\.\.?\/.*assembly\/)/.test(readRepoSource(relativePath)),
      )
      .map((relativePath) => `${relativePath}: public API imports assembly layer`),
  );

  if (fs.existsSync(absolutePath('packages/sdk-web/src/core/WalletIframe'))) {
    violations.push('packages/sdk-web/src/core/WalletIframe exists');
  }
  if (!fs.existsSync(absolutePath('packages/sdk-web/src/SeamsWeb/walletIframe'))) {
    violations.push('packages/sdk-web/src/SeamsWeb/walletIframe missing');
  }

  return violations;
}

function collectCoreWalletIframePrimitiveViolations() {
  const violations = [];
  const primitiveFiles = listTypeScriptFiles('packages/sdk-web/src/core/browser/walletIframe').sort();
  if (JSON.stringify(primitiveFiles) !== JSON.stringify(allowedCoreWalletIframePrimitiveFiles)) {
    violations.push(
      `core browser wallet iframe primitives changed: ${JSON.stringify(primitiveFiles)}`,
    );
  }

  const forbiddenImplementationTerms = [
    /\bWalletIframeRouter\b/,
    /\bWalletIframeCoordinator\b/,
    /\bIframeTransport\b/,
    /\bOverlayController\b/,
    /\bSeamsWebIframe\b/,
    /\bnew\s+SeamsWeb\b/,
  ];
  for (const relativePath of allowedCoreWalletIframePrimitiveFiles) {
    const source = readRepoSource(relativePath);
    for (const pattern of forbiddenImplementationTerms) {
      if (pattern.test(source)) {
        violations.push(`${relativePath}: ${pattern.source}`);
      }
    }
  }

  return violations;
}

function collectAuthMethodFolderViolations() {
  const violations = [];
  for (const relativePath of [
    'packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp',
    'packages/sdk-web/src/SeamsWeb/operations/authMethods/passkey',
  ]) {
    if (!fs.existsSync(absolutePath(relativePath))) {
      violations.push(`${relativePath}: missing auth method root`);
    }
  }

  for (const relativePath of [
    'packages/sdk-web/src/SeamsWeb/operations/emailOtp',
    'packages/sdk-web/src/SeamsWeb/operations/registration/emailOtpRegistrationAuthority.ts',
    'packages/sdk-web/src/SeamsWeb/operations/registration/passkeyRegistrationAuthority.ts',
  ]) {
    if (fs.existsSync(absolutePath(relativePath))) {
      violations.push(`${relativePath}: deleted auth method path returned`);
    }
  }

  const forbiddenImportPatterns = [
    /from\s+['"]@\/SeamsWeb\/operations\/emailOtp\//,
    /from\s+['"]@\/SeamsWeb\/operations\/registration\/(?:emailOtpRegistrationAuthority|passkeyRegistrationAuthority)['"]/,
  ];
  for (const relativePath of listTypeScriptFiles('packages/sdk-web/src/SeamsWeb')) {
    const source = readRepoSource(relativePath);
    for (const pattern of forbiddenImportPatterns) {
      if (pattern.test(source)) {
        violations.push(`${relativePath}: ${pattern.source}`);
      }
    }
  }

  return violations;
}

function collectDeletedForwarderViolations() {
  const violations = [];
  for (const relativePath of [
    'packages/sdk-web/src/SeamsWeb/publicApi/keys.ts',
    'packages/sdk-web/src/SeamsWeb/publicApi/registration.ts',
    'packages/sdk-web/src/SeamsWeb/publicApi/walletIframe.ts',
  ]) {
    if (fs.existsSync(absolutePath(relativePath))) {
      violations.push(`${relativePath}: pure public API forwarder returned`);
    }
  }

  const createPublicApiPath = 'packages/sdk-web/src/SeamsWeb/publicApi/createPublicApi.ts';
  if (!fs.existsSync(absolutePath(createPublicApiPath))) {
    violations.push(`${createPublicApiPath}: missing`);
  }
  if (fs.existsSync(absolutePath('packages/sdk-web/src/SeamsWeb/createPublicApi.ts'))) {
    violations.push('packages/sdk-web/src/SeamsWeb/createPublicApi.ts: deleted path returned');
  }

  return violations;
}

function collectNativeFacadeViolations() {
  const violations = [];
  const packageJson = readRepoJson('packages/sdk-web/package.json');
  if (packageJson.exports['./ios'] !== undefined) violations.push('package exports ./ios');
  if (packageJson.exports['./embedded'] !== undefined) violations.push('package exports ./embedded');
  if (packageJson.typesVersions?.['*']?.ios !== undefined) {
    violations.push('package typesVersions exposes ios');
  }
  if (packageJson.typesVersions?.['*']?.embedded !== undefined) {
    violations.push('package typesVersions exposes embedded');
  }
  if (packageJson.keywords.includes('native')) violations.push('package keyword native returned');
  if (packageJson.keywords.includes('embedded')) violations.push('package keyword embedded returned');

  for (const relativePath of [
    'packages/sdk-web/src/ios',
    'packages/sdk-web/src/embedded',
    'packages/sdk-web/src/ios.ts',
    'packages/sdk-web/src/embedded.ts',
  ]) {
    if (fs.existsSync(absolutePath(relativePath))) {
      violations.push(`${relativePath}: TypeScript native facade returned`);
    }
  }

  const forbiddenNativeFacadeNamePattern =
    /(?:SeamsIOS|IoSSigningSurface|SeamsEmbedded|EmbeddedSigningSurface)/;
  for (const relativePath of listTypeScriptFiles('packages/sdk-web/src')) {
    if (forbiddenNativeFacadeNamePattern.test(relativePath)) {
      violations.push(`${relativePath}: fake native facade file`);
    }
  }

  const runtimePortsSource = readRepoSource('packages/sdk-web/src/core/platform/runtime.ts');
  if (!runtimePortsSource.includes("export type RuntimePortsKind = 'browser';")) {
    violations.push('runtime ports no longer restrict RuntimePortsKind to browser');
  }
  for (const forbidden of ['EmbeddedPlatformRuntime', 'linux_embedded', "'ios'"]) {
    if (runtimePortsSource.includes(forbidden)) {
      violations.push(`runtime ports reintroduced ${forbidden}`);
    }
  }

  const runtimeEntrySource = readRepoSource('packages/sdk-web/src/runtime.ts');
  if (runtimeEntrySource.includes('EmbeddedPlatformRuntime')) {
    violations.push('runtime entry reintroduced EmbeddedPlatformRuntime');
  }

  return violations;
}

function collectViolations() {
  return [
    ...collectWebModulesRuntimeServiceViolations(),
    ...collectSigningRuntimeEscapeViolations(),
    ...collectInternalRegistrationMethodViolations(),
    ...collectNamespaceViolations(),
    ...collectAdvancedExportViolations(),
    ...collectRpcFacadeImportViolations(),
    ...collectLocalSignerClassViolations(),
    ...collectLifecycleNameViolations(),
    ...collectBroadDependencyViolations(),
    ...collectRawContextViolations(),
    ...collectImportDirectionViolations(),
    ...collectCoreWalletIframePrimitiveViolations(),
    ...collectAuthMethodFolderViolations(),
    ...collectDeletedForwarderViolations(),
    ...collectNativeFacadeViolations(),
  ];
}

function main() {
  assert(fs.existsSync(repoRoot), 'repo root does not exist');
  const violations = collectViolations();
  if (violations.length > 0) {
    console.error(`[seams-web-public-surface-boundaries] failed with ${violations.length} violation(s):`);
    for (const violation of violations) {
      console.error(`- ${violation}`);
    }
    process.exit(1);
  }
  console.log('[seams-web-public-surface-boundaries] ok');
}

main();
