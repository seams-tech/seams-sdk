import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const seamsWebImplementationPath = 'packages/sdk-web/src/SeamsWeb/SeamsWeb.ts';

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function readRepoJson(relativePath: string): Record<string, any> {
  return JSON.parse(readRepoSource(relativePath));
}

function listTypeScriptFiles(relativeDir: string): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  if (!fs.existsSync(absoluteDir)) return [];
  return fs.readdirSync(absoluteDir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) return listTypeScriptFiles(relativePath);
    return /\.(ts|tsx)$/.test(entry.name) ? [relativePath] : [];
  });
}

test.describe('refactor 54 web signing surface guards', () => {
  test('web modules reach runtime services only from SeamsWeb assembly', () => {
    const allowedPrefixes = ['packages/sdk-web/src/SeamsWeb/assembly/'];
    const sourceFiles = [
      ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb'),
      ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb/walletIframe'),
    ].filter((relativePath) => !allowedPrefixes.some((prefix) => relativePath.startsWith(prefix)));

    const offenders = sourceFiles.filter((relativePath) =>
      /signingRuntime\.services/.test(readRepoSource(relativePath)),
    );

    expect(offenders).toEqual([]);
  });

  test('SeamsWebContext does not expose the runtime service graph', () => {
    const source = readRepoSource('packages/sdk-web/src/SeamsWeb/signingSurface/types.ts');
    const contextBlock = source.match(/export type SeamsWebContext\s*=[^;]+;/m)?.[0];

    expect(contextBlock).toBeTruthy();
    expect(contextBlock).not.toMatch(/\bsigningRuntime\b/);
  });

  test('web signing surface does not expose SigningRuntime escape hatches', () => {
    const interfacesSource = readRepoSource('packages/sdk-web/src/SeamsWeb/signingSurface/types.ts');
    const surfaceBlock = interfacesSource.match(
      /export interface SeamsWebSigningSurface[\s\S]*?^}/m,
    )?.[0];

    expect(surfaceBlock).toBeTruthy();
    expect(surfaceBlock).not.toMatch(/\bsigningRuntime\b/);

    const assemblySource = readRepoSource(
      'packages/sdk-web/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts',
    );
    expect(assemblySource).not.toMatch(/^\s*readonly\s+signingRuntime\b/m);
    expect(assemblySource).toMatch(/\bprivate\s+readonly\s+signingRuntime\b/);

    const sourceFiles = [
      ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb'),
      ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb/walletIframe'),
    ].filter(
      (relativePath) =>
        !relativePath.startsWith('packages/sdk-web/src/SeamsWeb/assembly/') &&
        relativePath !== 'packages/sdk-web/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts',
    );

    const runtimeAccessOffenders = sourceFiles.filter((relativePath) =>
      /signingEngine\.signingRuntime/.test(readRepoSource(relativePath)),
    );
    expect(runtimeAccessOffenders).toEqual([]);

    const runtimeTypeOffenders = sourceFiles.filter((relativePath) =>
      /from\s+['"]@\/core\/runtime\/types['"]/.test(readRepoSource(relativePath)),
    );
    expect(runtimeTypeOffenders).toEqual([]);
  });

  test('public registration surfaces do not expose internal registration methods', () => {
    const legacyRegistrationMethodPattern = new RegExp(`\\bregisterPasskey${'Internal'}\\b`);
    const interfacesSource = readRepoSource('packages/sdk-web/src/SeamsWeb/publicApi/types.ts');
    const registrationCapabilityBlock = interfacesSource.match(
      /export interface RegistrationCapability\s*{[\s\S]*?^}/m,
    )?.[0];

    expect(registrationCapabilityBlock).toBeTruthy();
    expect(registrationCapabilityBlock).not.toMatch(legacyRegistrationMethodPattern);

    const seamsWebSource = readRepoSource(seamsWebImplementationPath);
    expect(seamsWebSource).not.toMatch(legacyRegistrationMethodPattern);

    const iframeFacadeSource = readRepoSource('packages/sdk-web/src/SeamsWeb/walletIframe/SeamsWebIframe.ts');
    expect(iframeFacadeSource).not.toMatch(legacyRegistrationMethodPattern);
  });

  test('SeamsWeb wallet session methods live under the auth namespace', () => {
    const seamsWebSource = readRepoSource(seamsWebImplementationPath);
    const iframeFacadeSource = readRepoSource('packages/sdk-web/src/SeamsWeb/walletIframe/SeamsWebIframe.ts');
    const topLevelWalletSessionMethods = [
      'unlock',
      'lock',
      'getWalletSession',
      'getRecentUnlocks',
      'hasPasskeyCredential',
      'prefillRouterAbEcdsaHssPresignaturePool',
    ];

    for (const methodName of topLevelWalletSessionMethods) {
      expect(seamsWebSource).not.toMatch(new RegExp(`^\\s*async\\s+${methodName}\\s*\\(`, 'm'));
      expect(iframeFacadeSource).not.toMatch(new RegExp(`^\\s*async\\s+${methodName}\\s*\\(`, 'm'));
    }
    expect(seamsWebSource).toMatch(/readonly auth: AuthCapability;/);
    expect(iframeFacadeSource).toMatch(/readonly auth: AuthCapability;/);
  });

  test('SeamsWeb registration methods live under the registration namespace', () => {
    const seamsWebSource = readRepoSource(seamsWebImplementationPath);
    const iframeFacadeSource = readRepoSource('packages/sdk-web/src/SeamsWeb/walletIframe/SeamsWebIframe.ts');
    const topLevelRegistrationMethods = [
      'registerWallet',
      'addWalletSigner',
      'registerWithEmailOtp',
      'registerPasskey',
    ];

    for (const methodName of topLevelRegistrationMethods) {
      expect(seamsWebSource).not.toMatch(new RegExp(`^\\s*async\\s+${methodName}\\s*\\(`, 'm'));
      expect(iframeFacadeSource).not.toMatch(new RegExp(`^\\s*async\\s+${methodName}\\s*\\(`, 'm'));
    }
    expect(seamsWebSource).toMatch(/readonly registration: RegistrationCapability;/);
    expect(iframeFacadeSource).toMatch(/readonly registration: RegistrationCapability;/);
  });

  test('Email OTP methods live under task namespaces', () => {
    const seamsWebSource = readRepoSource(seamsWebImplementationPath);
    const interfacesSource = readRepoSource('packages/sdk-web/src/SeamsWeb/publicApi/types.ts');
    const authCapabilityBlock = interfacesSource.match(
      /export interface AuthCapability\s*{[\s\S]*?^}/m,
    )?.[0];
    const registrationCapabilityBlock = interfacesSource.match(
      /export interface RegistrationCapability\s*{[\s\S]*?^}/m,
    )?.[0];
    const recoveryCapabilityBlock = interfacesSource.match(
      /export interface RecoveryCapability\s*{[\s\S]*?^}/m,
    )?.[0];
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

    expect(authCapabilityBlock).toBeTruthy();
    expect(registrationCapabilityBlock).toBeTruthy();
    expect(recoveryCapabilityBlock).toBeTruthy();
    for (const methodName of authMethods) {
      expect(authCapabilityBlock).toContain(methodName);
    }
    for (const methodName of registrationMethods) {
      expect(registrationCapabilityBlock).toContain(methodName);
    }
    for (const methodName of recoveryMethods) {
      expect(recoveryCapabilityBlock).toContain(methodName);
    }
    for (const methodName of [...authMethods, ...registrationMethods, ...recoveryMethods]) {
      expect(seamsWebSource).not.toMatch(new RegExp(`^\\s*async\\s+${methodName}\\s*\\(`, 'm'));
    }
    expect(interfacesSource).not.toMatch(/export interface EmailOtpCapability\s*{/);
    expect(seamsWebSource).not.toMatch(/readonly emailOtp:/);
  });

  test('device lifecycle methods live under the devices namespace', () => {
    const seamsWebSource = readRepoSource(seamsWebImplementationPath);
    const interfacesSource = readRepoSource('packages/sdk-web/src/SeamsWeb/publicApi/types.ts');
    const recoveryCapabilityBlock = interfacesSource.match(
      /export interface RecoveryCapability\s*{[\s\S]*?^}/m,
    )?.[0];
    const devicesCapabilityBlock = interfacesSource.match(
      /export interface DevicesCapability\s*{[\s\S]*?^}/m,
    )?.[0];
    const deviceMethodFragments = [
      'startDevice2LinkingFlow',
      'stopDevice2LinkingFlow',
      'linkDeviceWithScannedQRData',
      'viewAccessKeyList',
      'deleteDeviceKey',
    ];

    expect(recoveryCapabilityBlock).toBeTruthy();
    expect(devicesCapabilityBlock).toBeTruthy();
    for (const methodName of deviceMethodFragments) {
      expect(recoveryCapabilityBlock).not.toContain(methodName);
      expect(devicesCapabilityBlock).toContain(methodName);
      expect(seamsWebSource).not.toMatch(new RegExp(`^\\s*async\\s+${methodName}\\s*\\(`, 'm'));
    }
    expect(seamsWebSource).toMatch(/readonly devices: DevicesCapability;/);
  });

  test('confirmation preference methods live under the preferences namespace', () => {
    const seamsWebSource = readRepoSource(seamsWebImplementationPath);
    const iframeFacadeSource = readRepoSource('packages/sdk-web/src/SeamsWeb/walletIframe/SeamsWebIframe.ts');
    const preferencesMethodFragments = [
      'setConfirmBehavior',
      'setConfirmationConfig',
      'getConfirmationConfig',
    ];

    for (const methodName of preferencesMethodFragments) {
      expect(seamsWebSource).not.toMatch(new RegExp(`^\\s*${methodName}\\s*\\(`, 'm'));
      expect(seamsWebSource).not.toMatch(new RegExp(`^\\s*async\\s+${methodName}\\s*\\(`, 'm'));
      expect(iframeFacadeSource).not.toMatch(new RegExp(`^\\s*${methodName}\\s*\\(`, 'm'));
    }
    expect(seamsWebSource).toMatch(/readonly preferences: PreferencesCapability;/);
    expect(iframeFacadeSource).toMatch(/readonly preferences: PreferencesCapability;/);
  });

  test('root SDK export surface stays small and advanced helpers use the advanced subpath', () => {
    const rootSource = readRepoSource('packages/sdk-web/src/index.ts');
    const advancedSource = readRepoSource('packages/sdk-web/src/advanced.ts');
    const packageJson = JSON.parse(readRepoSource('packages/sdk-web/package.json')) as {
      exports?: Record<string, unknown>;
    };
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

    for (const symbol of advancedSymbols) {
      expect(rootSource).not.toContain(symbol);
      expect(advancedSource).toContain(symbol);
    }
    expect(Object.prototype.hasOwnProperty.call(packageJson.exports, './advanced')).toBe(true);
  });

  test('core RPC modules do not import SeamsWeb facade types', () => {
    const sourceFiles = listTypeScriptFiles('packages/sdk-web/src/core/rpcClients');

    const offenders = sourceFiles.filter((relativePath) =>
      /from\s+['"]@\/SeamsWeb(?:['"/])/.test(readRepoSource(relativePath)),
    );

    expect(offenders).toEqual([]);
  });

  test('signing namespaces do not reintroduce local signer classes', () => {
    const sourceFiles = [
      ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb/operations/near'),
      ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb/operations/tempo'),
      ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb/operations/evm'),
      'packages/sdk-web/src/SeamsWeb/publicApi/near.ts',
      'packages/sdk-web/src/SeamsWeb/publicApi/tempo.ts',
      'packages/sdk-web/src/SeamsWeb/publicApi/evm.ts',
    ];

    const offenders = sourceFiles.filter((relativePath) =>
      /\b(?:class|new)\s+(?:NearSigner|TempoSigner|EvmSigner)\b/.test(readRepoSource(relativePath)),
    );

    expect(offenders).toEqual([]);
  });

  test('browser signing surface uses lifecycle names for internal registration and EVM-family signing', () => {
    const forbiddenNames = [
      'initializeCurrentUser',
      'storeWalletEd25519SignerRecord',
      'storeWalletEcdsaRegistrationData',
      'persistWalletRegistrationEcdsaSessions',
    ];
    const sourceFiles = [
      ...listTypeScriptFiles('packages/sdk-web/src/SeamsWeb'),
      ...listTypeScriptFiles('packages/sdk-web/src/core/signingEngine/flows/registration'),
    ];
    const offenders = sourceFiles.flatMap((relativePath) => {
      const source = readRepoSource(relativePath);
      return forbiddenNames
        .filter((name) => new RegExp(`\\b${name}\\b`).test(source))
        .map((name) => `${relativePath}: ${name}`);
    });

    expect(offenders).toEqual([]);

    const browserSurfaceSource = readRepoSource(
      'packages/sdk-web/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts',
    );
    expect(browserSurfaceSource).toMatch(/\basync\s+signEvmFamily\s*\(/);
    expect(browserSurfaceSource).not.toMatch(/\basync\s+signTempo\s*\(/);

    const tempoCapabilitySource = readRepoSource('packages/sdk-web/src/SeamsWeb/publicApi/tempo.ts');
    expect(tempoCapabilitySource).toContain('TempoSigningSurface');
    expect(tempoCapabilitySource).not.toContain("SeamsWebContext['signingEngine']");
    expect(tempoCapabilitySource).toContain('deps.signingEngine.signEvmFamily');
    expect(tempoCapabilitySource).not.toMatch(/lifecycle:\s*tempoCapability\b/);
  });

  test('broad browser signing-surface dependencies stay limited to documented remaining domains', () => {
    const allowedRemainingBroadDeps: string[] = [];
    const sourceFiles = listTypeScriptFiles('packages/sdk-web/src/SeamsWeb');
    const offenders = sourceFiles.filter((relativePath) => {
      if (allowedRemainingBroadDeps.includes(relativePath)) return false;
      return /SeamsWebContext\['signingEngine'\]/.test(readRepoSource(relativePath));
    });

    expect(offenders).toEqual([]);
  });

  test('web operations and public API use narrow signing-surface ports', () => {
    const operationRoots = [
      'packages/sdk-web/src/SeamsWeb/operations',
      'packages/sdk-web/src/SeamsWeb/publicApi',
    ];
    const offenders = operationRoots.flatMap((root) =>
      listTypeScriptFiles(root).flatMap((relativePath) => {
        const source = readRepoSource(relativePath);
        return [
          /\bSeamsWebSigningSurface\b/,
          /Pick\s*<\s*SeamsWebSigningSurface\b/,
        ]
          .filter((pattern) => pattern.test(source))
          .map((pattern) => `${relativePath}: ${pattern.source}`);
      }),
    );

    expect(offenders).toEqual([]);

    const signingSurfaceTypes = readRepoSource('packages/sdk-web/src/SeamsWeb/signingSurface/types.ts');
    const signingSurfacePorts = readRepoSource('packages/sdk-web/src/SeamsWeb/signingSurface/ports.ts');
    const aggregateMatch = signingSurfaceTypes.match(
      /export interface SeamsWebSigningSurface[\s\S]*?^}/m,
    );
    expect(aggregateMatch?.[0] ?? '').toContain('extends RpIdSurface');
    expect(aggregateMatch?.[0] ?? '').not.toContain('storeWalletEcdsaSignerRecords(');
    expect(signingSurfaceTypes).not.toMatch(/Pick\s*<\s*SeamsWebSigningSurface\b/);
    expect(signingSurfaceTypes).not.toMatch(/export interface (Auth|Registration|NearSigner|TempoSigner|EvmSigner|Recovery|Devices|KeyExport|Preferences)Capability\b/);
    expect(signingSurfaceTypes).toContain("export type * from '../publicApi/types'");
    expect(signingSurfacePorts).toContain('export type SeamsWebBaseContext<TSigningEngine>');
    expect(signingSurfacePorts).not.toMatch(/Omit\s*<\s*SeamsWebContext\b/);
  });

  test('web helpers do not accept raw SeamsWebContext inputs', () => {
    const allowedRawContextFiles = [
      seamsWebImplementationPath,
      'packages/sdk-web/src/SeamsWeb/signingSurface/types.ts',
    ];
    const sourceFiles = listTypeScriptFiles('packages/sdk-web/src/SeamsWeb').filter(
      (relativePath) => !allowedRawContextFiles.includes(relativePath),
    );
    const rawContextPatterns = [
      /\bcontext\s*:\s*SeamsWebContext\b/,
      /\bgetContext\s*:\s*\(\)\s*=>\s*SeamsWebContext\b/,
    ];
    const offenders = sourceFiles.flatMap((relativePath) => {
      const source = readRepoSource(relativePath);
      return rawContextPatterns
        .filter((pattern) => pattern.test(source))
        .map((pattern) => `${relativePath}: ${pattern.source}`);
    });

    expect(offenders).toEqual([]);
  });

  test('broad SeamsWebContext stays facade-only', () => {
    const allowedFiles = [
      seamsWebImplementationPath,
      'packages/sdk-web/src/SeamsWeb/signingSurface/types.ts',
    ];
    const offenders = listTypeScriptFiles('packages/sdk-web/src/SeamsWeb')
      .filter((relativePath) => !allowedFiles.includes(relativePath))
      .filter((relativePath) => /\bSeamsWebContext\b/.test(readRepoSource(relativePath)));

    expect(offenders).toEqual([]);
  });

  test('linear SeamsWeb layout enforces import direction', () => {
    const coreWebImportOffenders = listTypeScriptFiles('packages/sdk-web/src/core').filter((relativePath) =>
      /from\s+['"](?:@\/web\/|\.\.?\/.*web\/)/.test(readRepoSource(relativePath)),
    );
    expect(coreWebImportOffenders).toEqual([]);

    const operationsFacadeOffenders = listTypeScriptFiles(
      'packages/sdk-web/src/SeamsWeb/operations',
    ).filter((relativePath) =>
      /from\s+['"](?:@\/SeamsWeb\/facade\/|\.\.?\/.*facade\/)/.test(
        readRepoSource(relativePath),
      ),
    );
    expect(operationsFacadeOffenders).toEqual([]);

    const surfacePublicApiOffenders = listTypeScriptFiles(
      'packages/sdk-web/src/SeamsWeb/signingSurface',
    )
      .filter((relativePath) => relativePath !== 'packages/sdk-web/src/SeamsWeb/signingSurface/types.ts')
      .filter((relativePath) =>
        /from\s+['"](?:@\/SeamsWeb\/publicApi\/|\.\.?\/.*publicApi\/)/.test(
          readRepoSource(relativePath),
        ),
      );
    expect(surfacePublicApiOffenders).toEqual([]);

    const publicApiAssemblyOffenders = listTypeScriptFiles(
      'packages/sdk-web/src/SeamsWeb/publicApi',
    ).filter((relativePath) =>
      /from\s+['"](?:@\/SeamsWeb\/assembly\/|\.\.?\/.*assembly\/)/.test(
        readRepoSource(relativePath),
      ),
    );
    expect(publicApiAssemblyOffenders).toEqual([]);

    expect(fs.existsSync(path.join(repoRoot, 'packages/sdk-web/src/core/WalletIframe'))).toBe(false);
    expect(fs.existsSync(path.join(repoRoot, 'packages/sdk-web/src/SeamsWeb/walletIframe'))).toBe(true);
  });

  test('core wallet iframe browser primitives stay limited', () => {
    const allowedPrimitiveFiles = [
      'packages/sdk-web/src/core/browser/walletIframe/csp-stylesheet.ts',
      'packages/sdk-web/src/core/browser/walletIframe/events.ts',
      'packages/sdk-web/src/core/browser/walletIframe/host-mode.ts',
      'packages/sdk-web/src/core/browser/walletIframe/hostVariant.ts',
    ];

    expect(listTypeScriptFiles('packages/sdk-web/src/core/browser/walletIframe').sort()).toEqual(
      allowedPrimitiveFiles,
    );

    const forbiddenImplementationTerms = [
      /\bWalletIframeRouter\b/,
      /\bWalletIframeCoordinator\b/,
      /\bIframeTransport\b/,
      /\bOverlayController\b/,
      /\bSeamsWebIframe\b/,
      /\bnew\s+SeamsWeb\b/,
    ];
    const offenders = allowedPrimitiveFiles.flatMap((relativePath) => {
      const source = readRepoSource(relativePath);
      return forbiddenImplementationTerms
        .filter((pattern) => pattern.test(source))
        .map((pattern) => `${relativePath}: ${pattern.source}`);
    });

    expect(offenders).toEqual([]);
  });

  test('auth method browser operations stay under symmetric authMethods folders', () => {
    const authMethodRoots = [
      'packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp',
      'packages/sdk-web/src/SeamsWeb/operations/authMethods/passkey',
    ];
    for (const relativePath of authMethodRoots) {
      expect(fs.existsSync(path.join(repoRoot, relativePath))).toBe(true);
    }

    const forbiddenPaths = [
      'packages/sdk-web/src/SeamsWeb/operations/emailOtp',
      'packages/sdk-web/src/SeamsWeb/operations/registration/emailOtpRegistrationAuthority.ts',
      'packages/sdk-web/src/SeamsWeb/operations/registration/passkeyRegistrationAuthority.ts',
    ];
    for (const relativePath of forbiddenPaths) {
      expect(fs.existsSync(path.join(repoRoot, relativePath))).toBe(false);
    }

    const sourceFiles = listTypeScriptFiles('packages/sdk-web/src/SeamsWeb');
    const forbiddenImportPatterns = [
      /from\s+['"]@\/SeamsWeb\/operations\/emailOtp\//,
      /from\s+['"]@\/SeamsWeb\/operations\/registration\/(?:emailOtpRegistrationAuthority|passkeyRegistrationAuthority)['"]/,
    ];
    const offenders = sourceFiles.flatMap((relativePath) => {
      const source = readRepoSource(relativePath);
      return forbiddenImportPatterns
        .filter((pattern) => pattern.test(source))
        .map((pattern) => `${relativePath}: ${pattern.source}`);
    });

    expect(offenders).toEqual([]);
  });

  test('pure public API forwarding modules stay deleted', () => {
    const deletedForwarderFiles = [
      'packages/sdk-web/src/SeamsWeb/publicApi/keys.ts',
      'packages/sdk-web/src/SeamsWeb/publicApi/registration.ts',
      'packages/sdk-web/src/SeamsWeb/publicApi/walletIframe.ts',
    ];
    const existingDeletedForwarders = deletedForwarderFiles.filter((relativePath) =>
      fs.existsSync(path.join(repoRoot, relativePath)),
    );
    expect(existingDeletedForwarders).toEqual([]);

    const createPublicApiPath = 'packages/sdk-web/src/SeamsWeb/publicApi/createPublicApi.ts';
    expect(fs.existsSync(path.join(repoRoot, createPublicApiPath))).toBe(true);
    expect(fs.existsSync(path.join(repoRoot, 'packages/sdk-web/src/SeamsWeb/createPublicApi.ts'))).toBe(
      false,
    );
  });

  test('native SDKs are not modeled as TypeScript npm facades', () => {
    const packageJson = readRepoJson('packages/sdk-web/package.json');
    expect(packageJson.exports['./ios']).toBeUndefined();
    expect(packageJson.exports['./embedded']).toBeUndefined();
    expect(packageJson.typesVersions?.['*']?.ios).toBeUndefined();
    expect(packageJson.typesVersions?.['*']?.embedded).toBeUndefined();
    expect(packageJson.keywords).not.toContain('native');
    expect(packageJson.keywords).not.toContain('embedded');

    const forbiddenPaths = [
      'packages/sdk-web/src/ios',
      'packages/sdk-web/src/embedded',
      'packages/sdk-web/src/ios.ts',
      'packages/sdk-web/src/embedded.ts',
    ];
    const existingForbiddenPaths = forbiddenPaths.filter((relativePath) =>
      fs.existsSync(path.join(repoRoot, relativePath)),
    );
    expect(existingForbiddenPaths).toEqual([]);

    const forbiddenNativeFacadeNamePattern =
      /(?:SeamsIOS|IoSSigningSurface|SeamsEmbedded|EmbeddedSigningSurface)/;
    const fakeNativeFacadeFiles = listTypeScriptFiles('packages/sdk-web/src').filter((relativePath) =>
      forbiddenNativeFacadeNamePattern.test(relativePath),
    );
    expect(fakeNativeFacadeFiles).toEqual([]);

    const runtimePortsSource = readRepoSource('packages/sdk-web/src/core/platform/runtime.ts');
    expect(runtimePortsSource).toContain("export type RuntimePortsKind = 'browser';");
    expect(runtimePortsSource).not.toContain('EmbeddedPlatformRuntime');
    expect(runtimePortsSource).not.toContain('linux_embedded');
    expect(runtimePortsSource).not.toContain("'ios'");

    const runtimeEntrySource = readRepoSource('packages/sdk-web/src/runtime.ts');
    expect(runtimeEntrySource).not.toContain('EmbeddedPlatformRuntime');
  });
});
