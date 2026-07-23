#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function test(_name, fn) {
  fn();
}

function expect(actual, message) {
  return {
    toBe(expected) {
      assert.equal(actual, expected, message);
    },
    toEqual(expected) {
      assert.deepEqual(actual, expected, message);
    },
    toContain(expected) {
      assert.ok(
        actual.includes(expected),
        message ?? `expected value to contain ${String(expected)}`,
      );
    },
    toMatch(expected) {
      assert.match(actual, expected, message);
    },
    toBeGreaterThan(expected) {
      assert.ok(actual > expected, message ?? `expected ${String(actual)} > ${String(expected)}`);
    },
    toBeTruthy() {
      assert.ok(actual, message ?? 'expected value to be truthy');
    },
    toBeUndefined() {
      assert.equal(actual, undefined, message);
    },
    not: {
      toBeNull() {
        assert.notEqual(actual, null, message);
      },
      toContain(expected) {
        assert.ok(
          !actual.includes(expected),
          message ?? `expected value not to contain ${String(expected)}`,
        );
      },
      toMatch(expected) {
        assert.ok(
          !expected.test(actual),
          message ?? `expected value not to match ${String(expected)}`,
        );
      },
    },
  };
}

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const standaloneCheckerPath = 'tests/scripts/check-intended-behaviour-contract-boundaries.mjs';
const intendedRoot = 'tests/e2e/intended-behaviours';
const intendedHarnessPath = path.join(repoRoot, intendedRoot, 'harness.ts');
const intendedConfigPath = path.join(repoRoot, 'tests/playwright.intended.config.ts');
const intendedCiConfigPath = path.join(repoRoot, 'tests/playwright.intended.ci.config.ts');
const genericPlaywrightConfigPath = path.join(repoRoot, 'tests/playwright.config.ts');
const intendedCiStartupPath = path.join(repoRoot, 'tests/scripts/start-intended-services.mjs');
const seamsSiteConfigPath = path.join(repoRoot, 'apps/seams-site/src/config.ts');
const seamsSiteAppPath = path.join(repoRoot, 'apps/seams-site/src/app/App.tsx');
const intendedMutationSelfCheckScriptPath = path.join(
  repoRoot,
  'tests/scripts/check-intended-mutation-self-check.mjs',
);
const intendedGoogleOidcEnvModulePath = path.join(
  repoRoot,
  'tests/scripts/intended-google-oidc-env.mjs',
);
const intendedGoogleOidcSetupScriptPath = path.join(
  repoRoot,
  'tests/scripts/setup-intended-google-oidc.mjs',
);
const intendedGoogleTokenRefreshScriptPath = path.join(
  repoRoot,
  'tests/scripts/refresh-intended-google-token.mjs',
);
const intendedGoogleTokenEnsureScriptPath = path.join(
  repoRoot,
  'tests/scripts/ensure-intended-google-token.mjs',
);
const intendedLocalConsoleSeedScriptPath = path.join(
  repoRoot,
  'tests/scripts/seed-intended-local-console.mjs',
);
const warmSessionTestServicesFixturePath = path.join(
  repoRoot,
  'tests/unit/helpers/warmSessionTestServices.fixtures.ts',
);
const signingSessionRecordFixturePath = path.join(
  repoRoot,
  'tests/unit/helpers/signingSessionRecord.fixtures.ts',
);
const warmSessionUiConfirmFixturePath = path.join(
  repoRoot,
  'tests/unit/helpers/warmSessionUiConfirm.fixtures.ts',
);
const ecdsaChainTargetFixturePath = path.join(
  repoRoot,
  'tests/unit/helpers/ecdsaChainTarget.fixtures.ts',
);
const ecdsaBootstrapFixturePath = path.join(
  repoRoot,
  'tests/unit/helpers/ecdsaBootstrap.fixtures.ts',
);
const rootPackageJsonPath = path.join(repoRoot, 'package.json');
const testsPackageJsonPath = path.join(repoRoot, 'tests/package.json');
const testsReadmePath = path.join(repoRoot, 'tests/README.md');
const walletServiceHeadersTestPath = path.join(
  repoRoot,
  'tests/e2e/wallet-service-headers.test.ts',
);
const refactor88PlanPath = path.join(repoRoot, 'docs/refactor-88-intended-behaviour-e2e.md');
const refactor53PlanPath = path.join(repoRoot, 'docs/refactor-53-cleanup-tests.md');
const registrationFlowBenchmarkReportPath = path.join(
  repoRoot,
  'docs/benchmarks/registration-flow.md',
);
const expectedContractFiles = [
  'email-otp.registration.contract.test.ts',
  'email-otp.unlock.contract.test.ts',
  'passkey.ed25519-yao-local.contract.test.ts',
  'passkey.registration.contract.test.ts',
  'passkey.unlock.contract.test.ts',
];
const expectedContractActionSequences = {
  'email-otp.registration.contract.test.ts': [
    'registerEmailOtpWallet()',
    'refreshPagePreservingWalletStorage()',
    'exportEd25519Key()',
    'exportEcdsaKey()',
    'signNearTransactionAfterRefresh()',
    "signTempoAndArcEvmConcurrently('after_refresh_recovery')",
    'refreshPagePreservingWalletStorage()',
    "signArcEvmTransaction('step_up_required')",
    "signTempoTransaction('step_up_required')",
    "signNearTransaction('step_up_required')",
    'registerEmailOtpWallet()',
    'exportEd25519Key()',
    'exportEcdsaKey()',
    "signNearTransaction('post_registration')",
    "signTempoAndArcEvmConcurrently('post_registration')",
    "signNearTransaction('step_up_required')",
  ],
  'email-otp.unlock.contract.test.ts': [
    'registerEmailOtpWallet()',
    'unlockEmailOtpWallet()',
    'exportEd25519Key()',
    'exportEcdsaKey()',
    "signNearTransaction('post_unlock')",
    "signTempoAndArcEvmConcurrently('post_unlock')",
    "signNearTransaction('step_up_required')",
    'registerEmailOtpWallet()',
    'unlockEmailOtpWallet()',
    'refreshPagePreservingWalletStorage()',
    'exportEd25519Key()',
    'exportEcdsaKey()',
    'signNearTransactionAfterRefresh()',
    "signTempoAndArcEvmConcurrently('after_refresh_recovery')",
    'refreshPagePreservingWalletStorage()',
    "signNearTransaction('step_up_required')",
    "signTempoTransaction('step_up_required')",
    "signArcEvmTransaction('step_up_required')",
  ],
  'passkey.ed25519-yao-local.contract.test.ts': [
    'registerPasskeyEd25519YaoWallet()',
    "signNearTransaction('post_registration')",
  ],
  'passkey.registration.contract.test.ts': [
    'registerPasskeyWallet()',
    "signTempoTransaction('post_registration')",
  ],
  'passkey.unlock.contract.test.ts': [
    'registerPasskeyWallet()',
    'unlockPasskeyWallet()',
    'exportEd25519Key()',
    'exportEcdsaKey()',
    "signNearTransaction('post_unlock')",
    "signTempoAndArcEvmConcurrently('post_unlock')",
    "signNearTransaction('step_up_required')",
    'registerPasskeyWallet()',
    'unlockPasskeyWallet()',
    'refreshPagePreservingWalletStorage()',
    'exportEd25519Key()',
    'exportEcdsaKey()',
    'signNearTransactionAfterRefresh()',
    "signTempoTransaction('after_refresh_recovery')",
    "signArcEvmTransaction('after_refresh_recovery')",
    'exhaustSigningBudget()',
    "signNearTransaction('step_up_required')",
    "signTempoTransaction('step_up_required')",
    "signArcEvmTransaction('step_up_required')",
  ],
};
const expectedIntendedActionResultKinds = [
  'arc_evm_sign_success',
  'ecdsa_export_success',
  'ed25519_export_success',
  'email_otp_registration_success',
  'email_otp_unlock_success',
  'near_ed25519_signer_added',
  'near_sign_success',
  'passkey_registration_success',
  'passkey_unlock_success',
  'tempo_sign_success',
];
const expectedIntendedPageActionResultTypes = [
  'PasskeyRegistrationResultSummary',
  'Ed25519AddSignerResultSummary',
  'EmailOtpRegistrationResultSummary',
  'NearSigningResultSummary',
  'PasskeyUnlockResultSummary',
  'EmailOtpUnlockResultSummary',
  'TempoSigningResultSummary',
  'ArcEvmSigningResultSummary',
  'Ed25519ExportResultSummary',
  'EcdsaExportResultSummary',
];
const expectedHarnessActionResultTypes = [
  'PasskeyRegistrationResultSnapshot',
  'Ed25519AddSignerResultSnapshot',
  'EmailOtpRegistrationResultSnapshot',
  'NearSigningResultSnapshot',
  'PasskeyUnlockResultSnapshot',
  'EmailOtpUnlockResultSnapshot',
  'TempoSigningResultSnapshot',
  'ArcEvmSigningResultSnapshot',
  'Ed25519ExportResultSnapshot',
  'EcdsaExportResultSnapshot',
];
const expectedIntendedHarnessSetupTokens = [
  'export const intendedTest = base.extend',
  'installFailureCollectors',
  "this.page.on('console'",
  "this.context.on('requestfailed'",
  "this.context.on('response'",
  'installExternalNetworkStubs',
  "this.context.route('**/*'",
  'installWebAuthnVirtualAuthenticator',
  "client.send('WebAuthn.addVirtualAuthenticator'",
  'hasPrf: true',
  'resetBrowserStorage',
  'assertServicesReady',
  '`${this.config.routerUrl}/healthz`',
  '`${this.config.routerUrl}/readyz`',
  'runIntendedPageAction',
  'autoConfirmWalletIframeUntil',
  'fulfillExternalStub',
];
const retiredMockedRuntimeFiles = [
  'benchmarks/registration-flow/playwright.config.ts',
  'benchmarks/registration-flow/src/report.mjs',
  'benchmarks/registration-flow/src/runner.mjs',
  'benchmarks/registration-flow/src/scenario-harness.ts',
  'benchmarks/registration-flow/src/scenarios.mjs',
  'tests/e2e/docs.thresholdRegisterAndSigning.integration.test.ts',
  'tests/e2e/docs.thresholdSigningActions.smoke.test.ts',
  'tests/setup/fixtures.ts',
  'tests/setup/flows.ts',
  'tests/setup/test-utils.ts',
  'tests/setup/webauthn-mocks.ts',
  'tests/unit/helpers/warmSessionStore.fixtures.ts',
  'tests/unit/passkeyLoginMenu.thresholdProvision.unit.test.ts',
  'tests/unit/seamsWeb.loginThresholdWarm.unit.test.ts',
];
const retiredFakeRelayServerFiles = [
  'tests/scripts/provision-router-api-server.mjs',
  'tests/scripts/start-servers.mjs',
  'tests/scripts/test-router-api-server.mjs',
];
const demoSurfaceFiles = [
  'apps/seams-site/src/flows/demo/DemoPage.tsx',
  'apps/seams-site/src/flows/demo/PasskeyLoginMenu.tsx',
];
const setupSurfaceFiles = ['tests/setup/index.ts', 'tests/setup/logging.ts'];
const activeSourceRootsForRetiredSetupImports = ['apps', 'packages', 'tests'];
function isIntendedBehaviourBoundaryChecker(relativePath) {
  return (
    relativePath === 'tests/unit/intendedBehaviourContracts.guard.unit.test.ts' ||
    relativePath === standaloneCheckerPath
  );
}
const allowedE2eLegacySetupBootstrapFiles = ['tests/e2e/cancel_overlay_specs.test.ts'];
const allowedE2eLegacySetupBootstrapFileSet = new Set(allowedE2eLegacySetupBootstrapFiles);
const fakeAuthServiceQuarantineTokens = ['makeFakeAuthService', 'test-router-api-server.mjs'];
const fakeRelayServerScriptTokens = [
  'USE_RELAY_SERVER',
  'start-servers.mjs',
  'test-router-api-server.mjs',
  'provision-router-api-server.mjs',
];
const retiredBrowserTestUtils = [
  'failureMocks',
  'rollbackVerification',
  'verifyAccountExists',
  'webAuthnUtils',
  'loginStatus',
  'testUtils',
  'createConsoleCapture',
];
const retiredRegistrationFlowBenchmarkTokens = [
  'benchmark:registration-flow',
  'benchmarks/registration-flow/playwright.config.ts',
  'benchmarks/registration-flow/src/runner.mjs',
];
const registrationFlowBenchmarkArchiveTokens = [
  'Status: archived historical report from the retired registration-flow benchmark.',
  'Commands embedded below are provenance only.',
  'Refactor 88 intended-behaviour topology',
];
const forbiddenIntendedHarnessPatterns = [
  {
    pattern: /from\s+['"]\.\.\/setup(?:\/|['"])/,
    message: 'imports legacy tests/setup barrel',
  },
  {
    pattern: /from\s+['"].*tests\/setup(?:\/|['"])/,
    message: 'imports legacy tests/setup helpers',
  },
  {
    pattern: /\bsetupBasicPasskeyTest\b/,
    message: 'uses legacy setupBasicPasskeyTest',
  },
  {
    pattern: /\bsetupRouterApiServerTest\b/,
    message: 'uses legacy fake Router API setup',
  },
  {
    pattern: /\bsetupTestUtilities\b/,
    message: 'installs window.testUtils',
  },
  {
    pattern: /\bwindow\.testUtils\b/,
    message: 'uses testUtils instead of public SDK/UI flow',
  },
  {
    pattern: /\b__testOverrides\b/,
    message: 'uses SDK internal test overrides',
  },
  {
    pattern: /\bsetupRouterApiMock\b/,
    message: 'mocks Router API responses',
  },
  {
    pattern: /\binstall(RouterApiProxy|WalletSdkCors)Shim\b/,
    message: 'installs legacy same-origin routing shims',
  },
  {
    pattern: /\bforceSameOrigin(SdkBase|Workers)\b/,
    message: 'uses legacy same-origin SDK or worker rewrites',
  },
  {
    pattern: /\b__W3A_WALLET_SDK_BASE__\b/,
    message: 'overrides wallet SDK asset origin',
  },
  {
    pattern: /\btest-router-api-server\.mjs\b/,
    message: 'depends on fake AuthService router server',
  },
];
const forbiddenIntendedContractFlakePatterns = [
  {
    pattern: /\btest\.skip\b/,
    message: 'uses test.skip',
  },
  {
    pattern: /\btest\.fixme\b/,
    message: 'uses test.fixme',
  },
  {
    pattern: /\btest\.only\b/,
    message: 'uses test.only',
  },
  {
    pattern: /\btest\.describe\.skip\b/,
    message: 'uses test.describe.skip',
  },
  {
    pattern: /\btest\.describe\.only\b/,
    message: 'uses test.describe.only',
  },
  {
    pattern: /\btest\.describe\.configure\b/,
    message: 'overrides suite execution policy',
  },
  {
    pattern: /\.skip\s*\(/,
    message: 'uses a skip annotation',
  },
  {
    pattern: /\.only\s*\(/,
    message: 'uses a focused annotation',
  },
  {
    pattern: /\bretries\s*:/,
    message: 'overrides retry policy',
  },
];
const forbiddenPrivateIntendedImportPatterns = [
  {
    pattern: /packages\/(?:sdk-web|sdk-server-ts)\//,
    message: 'imports SDK package source by filesystem path',
  },
  {
    pattern: /@\/core\/signingEngine(?:\/|$)/,
    message: 'imports private signing-engine internals',
  },
  {
    pattern: /@\/SeamsWeb(?:\/|$)/,
    message: 'imports private SeamsWeb operation internals',
  },
  {
    pattern: /@seams\/sdk\/(?:core|internal|src|dist)(?:\/|$)/,
    message: 'imports private SDK internals',
  },
  {
    pattern: /@seams-internal\//,
    message: 'imports internal SDK packages',
  },
  {
    pattern: /(?:^|\/)flows\/demo(?:\/|$)|^@\/flows\/demo(?:\/|$)/,
    message: 'imports demo app helpers',
  },
  {
    pattern: /(?:^|\/)signingEngine(?:\/|$)/,
    message: 'imports signing-engine internals',
  },
  {
    pattern: /(?:^|\/)ThresholdService(?:\/|$)/,
    message: 'imports server threshold service internals',
  },
  {
    pattern: /thresholdEd25519/i,
    message: 'imports legacy threshold Ed25519 test/runtime internals',
  },
  {
    pattern: /walletRegistrationRoutes/,
    message: 'imports Router wallet registration route internals',
  },
];
test('Refactor 88 intended contracts expose the lifecycle specs', () => {
  const files = listTypeScriptFiles(path.join(repoRoot, intendedRoot))
    .map((file) => path.basename(file))
    .filter((file) => file.endsWith('.contract.test.ts'))
    .sort();
  expect(files).toEqual([...expectedContractFiles].sort());
});
test('Refactor 88 intended contracts reject local flake escape hatches', () => {
  const violations = [];
  for (const relativePath of listTypeScriptFiles(path.join(repoRoot, intendedRoot))) {
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    for (const forbidden of forbiddenIntendedContractFlakePatterns) {
      if (!forbidden.pattern.test(source)) continue;
      violations.push(`${relativePath}: ${forbidden.message}`);
    }
  }
  expect(violations, violations.join('\n')).toEqual([]);
});
test('Refactor 88 lifecycle specs keep required public action sequence', () => {
  for (const [contractFile, expectedActions] of Object.entries(expectedContractActionSequences)) {
    const source = fs.readFileSync(path.join(repoRoot, intendedRoot, contractFile), 'utf8');
    assertTokensAppearInOrder(source, expectedActions, contractFile);
  }
});
test('Refactor 88 intended contract specs stay high-level harness scripts', () => {
  const violations = [];
  for (const contractFile of expectedContractFiles) {
    const source = fs.readFileSync(path.join(repoRoot, intendedRoot, contractFile), 'utf8');
    const imports = extractModuleSpecifiers(source);
    if (imports.length !== 1 || imports[0] !== './harness') {
      violations.push(`${contractFile}: imports ${imports.join(', ') || '<none>'}`);
    }
    for (const token of ['page.', 'context.', 'request.', 'expect(', '.route(', '.evaluate(']) {
      if (!source.includes(token)) continue;
      violations.push(`${contractFile}: uses ${token}`);
    }
  }
  expect(violations, violations.join('\n')).toEqual([]);
});
test('Refactor 88 intended contracts avoid mocked runtime setup helpers', () => {
  const violations = [];
  for (const relativePath of listTypeScriptFiles(path.join(repoRoot, intendedRoot))) {
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    for (const forbidden of forbiddenIntendedHarnessPatterns) {
      if (!forbidden.pattern.test(source)) continue;
      violations.push(`${relativePath}: ${forbidden.message}`);
    }
  }
  expect(violations, violations.join('\n')).toEqual([]);
});
test('Refactor 88 intended public flow files avoid private SDK runtime imports', () => {
  const checkedFiles = [
    path.join(repoRoot, 'apps/seams-site/src/pages/intended-e2e/page.tsx'),
    intendedHarnessPath,
  ];
  const violations = [];
  for (const filePath of checkedFiles) {
    const relativePath = path.relative(repoRoot, filePath).replaceAll(path.sep, '/');
    const source = fs.readFileSync(filePath, 'utf8');
    for (const specifier of extractModuleSpecifiers(source)) {
      for (const forbidden of forbiddenPrivateIntendedImportPatterns) {
        if (!forbidden.pattern.test(specifier)) continue;
        violations.push(`${relativePath}: ${specifier}: ${forbidden.message}`);
      }
    }
  }
  expect(violations, violations.join('\n')).toEqual([]);
});
test('Refactor 88 intended harness owns setup primitives outside legacy setup', () => {
  const harnessSource = fs.readFileSync(intendedHarnessPath, 'utf8');
  const imports = extractModuleSpecifiers(harnessSource);
  const violations = [];
  for (const token of expectedIntendedHarnessSetupTokens) {
    if (harnessSource.includes(token)) continue;
    violations.push(`missing intended setup token: ${token}`);
  }
  for (const specifier of imports) {
    if (!specifier.includes('tests/setup') && !specifier.includes('../setup')) continue;
    violations.push(`imports legacy setup helper: ${specifier}`);
  }
  expect(violations, violations.join('\n')).toEqual([]);
});
test('Refactor 88 intended action result discriminants stay aligned', () => {
  const pageSource = fs.readFileSync(
    path.join(repoRoot, 'apps/seams-site/src/pages/intended-e2e/page.tsx'),
    'utf8',
  );
  const harnessSource = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(extractUnionMembers(pageSource, 'IntendedActionResult')).toEqual([
    ...expectedIntendedPageActionResultTypes,
  ]);
  expect(extractUnionMembers(harnessSource, 'IntendedActionResultSnapshot')).toEqual([
    ...expectedHarnessActionResultTypes,
  ]);
  expect(
    extractUniqueSwitchCasesBeforeDefault(
      extractDelimitedSource(
        harnessSource,
        'function parseIntendedActionResultSnapshot',
        'function parseEcdsaEnabledSnapshot',
      ),
      'switch (kind)',
    ),
  ).toEqual([...expectedIntendedActionResultKinds]);
  expect(
    extractUniqueSwitchCasesBeforeDefault(
      extractDelimitedSource(
        pageSource,
        'function intendedActionResultWalletId',
        'function intendedActionResultNearAccountId',
      ),
      'switch (result.kind)',
    ),
  ).toEqual([...expectedIntendedActionResultKinds]);
  expect(
    extractUniqueSwitchCasesBeforeDefault(
      extractDelimitedSource(
        pageSource,
        'function intendedActionResultNearAccountId',
        'function readIntendedPageQuery',
      ),
      'switch (result.kind)',
    ),
  ).toEqual([...expectedIntendedActionResultKinds]);
});
test('Refactor 88 retired mocked runtime files stay deleted', () => {
  const presentFiles = retiredMockedRuntimeFiles.filter((relativePath) =>
    fs.existsSync(path.join(repoRoot, relativePath)),
  );
  expect(presentFiles, presentFiles.join('\n')).toEqual([]);
});
test('Refactor 88 fake relay server launcher files stay deleted', () => {
  const presentFiles = retiredFakeRelayServerFiles.filter((relativePath) =>
    fs.existsSync(path.join(repoRoot, relativePath)),
  );
  expect(presentFiles, presentFiles.join('\n')).toEqual([]);
});
test('Refactor 88 active source does not import retired setup wrapper files', () => {
  const retiredSetupTokens = [
    'tests/setup/fixtures',
    'tests/setup/flows',
    'tests/setup/test-utils',
  ];
  const violations = [];
  for (const relativePath of listSourceTextFiles(activeSourceRootsForRetiredSetupImports)) {
    if (isIntendedBehaviourBoundaryChecker(relativePath)) continue;
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    for (const token of retiredSetupTokens) {
      if (!source.includes(token)) continue;
      violations.push(`${relativePath}: ${token}`);
    }
  }
  expect(violations, violations.join('\n')).toEqual([]);
});
test('Refactor 88 retired browser mutation hooks stay out of active source', () => {
  const retiredBrowserMutationTokens = ['__testOverrides', 'window.testUtils'];
  const violations = [];
  for (const relativePath of listSourceTextFiles(activeSourceRootsForRetiredSetupImports)) {
    if (isIntendedBehaviourBoundaryChecker(relativePath)) continue;
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    for (const token of retiredBrowserMutationTokens) {
      if (!source.includes(token)) continue;
      violations.push(`${relativePath}: ${token}`);
    }
  }
  expect(violations, violations.join('\n')).toEqual([]);
});
test('Refactor 88 generic setup bootstrap stays out of lifecycle e2e tests', () => {
  const violations = [];
  const allowedMatches = [];
  for (const relativePath of allowedE2eLegacySetupBootstrapFiles) {
    if (hasRefactor88KeepClassification(relativePath)) continue;
    violations.push(`${relativePath}: setupBasicPasskeyTest allowlist must stay audited`);
  }
  for (const relativePath of listSourceTextFiles(['tests/e2e'])) {
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    if (!source.includes('setupBasicPasskeyTest')) continue;
    if (allowedE2eLegacySetupBootstrapFileSet.has(relativePath)) {
      allowedMatches.push(relativePath);
      continue;
    }
    violations.push(`${relativePath}: setupBasicPasskeyTest`);
  }
  expect(allowedMatches.sort()).toEqual([...allowedE2eLegacySetupBootstrapFiles].sort());
  expect(violations, violations.join('\n')).toEqual([]);
});
test('Refactor 88 remaining generic browser bootstrap consumers stay audited', () => {
  const violations = [];
  for (const relativePath of listTypeScriptFiles(path.join(repoRoot, 'tests'))) {
    if (relativePath === 'tests/setup/index.ts') continue;
    if (isIntendedBehaviourBoundaryChecker(relativePath)) continue;
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    if (!source.includes('setupBasicPasskeyTest')) continue;
    if (hasRefactor88KeepClassification(relativePath)) continue;
    violations.push(`${relativePath}: setupBasicPasskeyTest usage must have a retained audit row`);
  }
  expect(violations, violations.join('\n')).toEqual([]);
});
test('Refactor 88 fake AuthService helpers stay deleted', () => {
  const violations = [];
  for (const relativePath of listSourceTextFiles(['tests'])) {
    if (isIntendedBehaviourBoundaryChecker(relativePath)) continue;
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    for (const token of fakeAuthServiceQuarantineTokens) {
      if (!source.includes(token)) continue;
      violations.push(`${relativePath}: ${token}`);
    }
  }
  expect(violations, violations.join('\n')).toEqual([]);
});
test('Refactor 88 test README advertises intended contracts instead of retired lifecycle tests', () => {
  const source = fs.readFileSync(testsReadmePath, 'utf8');
  expect(source).toContain('e2e/intended-behaviours/*.contract.test.ts');
  expect(source).toContain('intended registration,');
  expect(source).toContain('unlock, signing, step-up, and export lifecycle contracts');
  expect(source).toContain('Intended Behaviour Contracts: registration, unlock, signing');
  expect(source).toContain('Registration, unlock,');
  expect(source).toContain('lifecycle authority belongs there');
  expect(source).toContain('for generic SDK/browser bootstrap');
  expect(source).toContain('only; do not use it as a lifecycle oracle');
  expect(source).toContain('SEAMS_INTENDED_GOOGLE_ID_TOKEN');
  expect(source).toContain('pnpm test:intended:ci');
  expect(source).toContain('pnpm check:intended-mutation-self-check:complete');
  expect(source).toContain('The generic config excludes');
  expect(source).toContain('The generic Playwright config excludes those contracts');
  expect(source).toContain('on the intended runner');
  expect(source).toContain(
    '`test`, `test:lite`, and `test:inline` use the Vite-only browser setup',
  );
  expect(source).toContain(
    '`test:e2e` uses the same generic config and excludes intended contracts',
  );
  expect(source).toContain('The fake relay server launcher has been removed');
  expect(source).not.toContain('End‑to‑End: registration, login, actions');
  expect(source).not.toContain('orchestrates the 5 steps');
  expect(source).not.toContain('e2e/thresholdEd25519.*.test.ts');
  expect(source).not.toContain('tests/setup/fixtures.ts');
  expect(source).not.toContain('tests/setup/flows.ts');
  expect(source).not.toContain('tests/setup/test-utils.ts');
  expect(source).not.toContain('window.testUtils');
  expect(source).not.toContain('USE_RELAY_SERVER');
});
test('Refactor 88 cleanup docs advertise Vite-only integration signing scripts', () => {
  const source = fs.readFileSync(refactor53PlanPath, 'utf8');
  expect(source).toContain(
    '"test:integration:signing": "pnpm -C .. build:sdk-full && playwright test -c playwright.integration.config.ts --reporter=line"',
  );
  expect(source).not.toContain('USE_RELAY_SERVER');
});
test('Refactor 88 demo surfaces do not expose SDK test override hooks', () => {
  const violations = demoSurfaceFiles.filter((relativePath) => {
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    return source.includes('__testOverrides');
  });
  expect(violations, violations.join('\n')).toEqual([]);
});
test('Refactor 88 browser test utilities do not expose retired mock hooks', () => {
  const violations = [];
  for (const relativePath of setupSurfaceFiles) {
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    for (const retiredField of retiredBrowserTestUtils) {
      if (!source.includes(retiredField)) continue;
      violations.push(`${relativePath}: ${retiredField}`);
    }
  }
  expect(violations, violations.join('\n')).toEqual([]);
});
test('Refactor 88 generic setup does not expose same-origin rewrite flags', () => {
  const setupIndexSource = fs.readFileSync(path.join(repoRoot, 'tests/setup/index.ts'), 'utf8');
  const setupBootstrapSource = fs.readFileSync(
    path.join(repoRoot, 'tests/setup/bootstrap.ts'),
    'utf8',
  );
  const setupTypesSource = fs.readFileSync(path.join(repoRoot, 'tests/setup/types.ts'), 'utf8');
  const combinedSource = `${setupIndexSource}\n${setupBootstrapSource}\n${setupTypesSource}`;
  expect(combinedSource).not.toContain('forceSameOrigin');
  expect(combinedSource).not.toContain('W3A_FORCE_SAME_ORIGIN_WORKERS');
  expect(combinedSource).not.toContain('useRelayer');
  expect(combinedSource).not.toContain('relayServerUrl');
  expect(combinedSource).not.toContain('5-step');
  expect(combinedSource).not.toContain('mocked Router server');
  expect(combinedSource).not.toContain('LackBalanceForState');
  expect(combinedSource).not.toContain('NotEnoughBalance');
  expect(combinedSource).not.toContain('Atomic registration failed');
  expect(combinedSource).not.toContain('EADDRINUSE');
  expect(combinedSource).not.toContain('On-chain access key mismatch');
});
test('Refactor 88 ECDSA chain target fixtures stay split from warm-session runtime fixtures', () => {
  const warmSessionTestServicesFixtureSource = fs.readFileSync(
    warmSessionTestServicesFixturePath,
    'utf8',
  );
  const signingSessionRecordFixtureSource = fs.readFileSync(
    signingSessionRecordFixturePath,
    'utf8',
  );
  const warmSessionUiConfirmFixtureSource = fs.readFileSync(
    warmSessionUiConfirmFixturePath,
    'utf8',
  );
  const chainTargetFixtureSource = fs.readFileSync(ecdsaChainTargetFixturePath, 'utf8');
  const bootstrapFixtureSource = fs.readFileSync(ecdsaBootstrapFixturePath, 'utf8');
  expect(warmSessionTestServicesFixtureSource).not.toMatch(
    /export function testEcdsaChain(Target|Id)\b/,
  );
  expect(warmSessionTestServicesFixtureSource).not.toContain(
    'export function createThresholdEcdsaBootstrapFixture',
  );
  expect(warmSessionTestServicesFixtureSource).not.toContain(
    'export function createThresholdEcdsaStoreFixture',
  );
  expect(warmSessionTestServicesFixtureSource).not.toContain(
    'export function seedEd25519WarmSessionRecord',
  );
  expect(warmSessionTestServicesFixtureSource).not.toContain(
    'export function seedEcdsaWarmSessionRecord',
  );
  expect(warmSessionTestServicesFixtureSource).not.toContain(
    'export function createWarmSessionStatusReader',
  );
  expect(warmSessionTestServicesFixtureSource).not.toContain(
    'export function createWarmSessionUiConfirmFixture',
  );
  expect(warmSessionTestServicesFixtureSource).toContain(
    'export function createWarmSessionTestServices',
  );
  expect(signingSessionRecordFixtureSource).toContain(
    'export function createThresholdEcdsaStoreFixture',
  );
  expect(signingSessionRecordFixtureSource).toContain(
    'export function seedEd25519WarmSessionRecord',
  );
  expect(signingSessionRecordFixtureSource).toContain('export function seedEcdsaWarmSessionRecord');
  expect(warmSessionUiConfirmFixtureSource).toContain(
    'export function createWarmSessionStatusReader',
  );
  expect(warmSessionUiConfirmFixtureSource).toContain(
    'export function createWarmSessionUiConfirmFixture',
  );
  expect(chainTargetFixtureSource).toContain('export function testEcdsaChainId');
  expect(chainTargetFixtureSource).toContain('export function testEcdsaChainTarget');
  expect(bootstrapFixtureSource).toContain('export function createThresholdEcdsaBootstrapFixture');
});
test('Refactor 88 intended command is wired as a named pre-merge gate', () => {
  const rootPackage = readJsonRecord(rootPackageJsonPath);
  const testsPackage = readJsonRecord(testsPackageJsonPath);
  expect(readScript(rootPackage, 'test:intended')).toBe('pnpm -C tests test:intended');
  expect(readScript(testsPackage, 'type-check:intended')).toBe('tsc -p tsconfig.intended.json');
  expect(readScript(testsPackage, 'test:intended')).toBe(
    'pnpm run type-check:intended && pnpm run ensure:intended-google-token && playwright test -c playwright.intended.config.ts --reporter=line',
  );
  expect(readScript(rootPackage, 'test:intended:ci')).toBe('pnpm -C tests test:intended:ci');
  expect(readScript(testsPackage, 'test:intended:ci')).toBe(
    'pnpm run type-check:intended && pnpm run ensure:intended-google-token && playwright test -c playwright.intended.ci.config.ts --reporter=line',
  );
  expect(readScript(rootPackage, 'ensure:intended-google-token')).toBe(
    'pnpm -C tests ensure:intended-google-token',
  );
  expect(readScript(testsPackage, 'ensure:intended-google-token')).toBe(
    'node scripts/ensure-intended-google-token.mjs',
  );
  expect(readScript(rootPackage, 'setup:intended-google-oidc')).toBe(
    'pnpm -C tests setup:intended-google-oidc',
  );
  expect(readScript(testsPackage, 'setup:intended-google-oidc')).toBe(
    'node scripts/setup-intended-google-oidc.mjs',
  );
  expect(readScript(rootPackage, 'refresh:intended-google-token')).toBe(
    'pnpm -C tests refresh:intended-google-token',
  );
  expect(readScript(testsPackage, 'refresh:intended-google-token')).toBe(
    'node scripts/refresh-intended-google-token.mjs',
  );
  expect(readScript(rootPackage, 'seed:intended-local-console')).toBe(
    'pnpm -C tests seed:intended-local-console',
  );
  expect(readScript(testsPackage, 'seed:intended-local-console')).toBe(
    'node scripts/seed-intended-local-console.mjs',
  );
  expect(readScript(rootPackage, 'check:intended-mutation-self-check')).toBe(
    'pnpm -C tests check:intended-mutation-self-check',
  );
  expect(readScript(testsPackage, 'check:intended-mutation-self-check')).toBe(
    'node scripts/check-intended-mutation-self-check.mjs',
  );
  expect(readScript(rootPackage, 'check:intended-mutation-self-check:complete')).toBe(
    'pnpm -C tests check:intended-mutation-self-check:complete',
  );
  expect(readScript(testsPackage, 'check:intended-mutation-self-check:complete')).toBe(
    'node scripts/check-intended-mutation-self-check.mjs --require-detected',
  );
  expect(readScript(rootPackage, 'preflight:intended-mutation-self-check')).toBe(
    'pnpm -C tests preflight:intended-mutation-self-check',
  );
  expect(readScript(testsPackage, 'preflight:intended-mutation-self-check')).toBe(
    'pnpm run ensure:intended-google-token && node scripts/check-intended-mutation-self-check.mjs --preflight',
  );
  expect(readScript(rootPackage, 'preflight:intended-mutation-self-check:ci')).toBe(
    'pnpm -C tests preflight:intended-mutation-self-check:ci',
  );
  expect(readScript(testsPackage, 'preflight:intended-mutation-self-check:ci')).toBe(
    'pnpm run ensure:intended-google-token && node scripts/check-intended-mutation-self-check.mjs --preflight --ci',
  );
});
test('Refactor 88 intended Google OIDC helper uses service-account impersonation', () => {
  const envSource = fs.readFileSync(intendedGoogleOidcEnvModulePath, 'utf8');
  const setupSource = fs.readFileSync(intendedGoogleOidcSetupScriptPath, 'utf8');
  const refreshSource = fs.readFileSync(intendedGoogleTokenRefreshScriptPath, 'utf8');
  const ensureSource = fs.readFileSync(intendedGoogleTokenEnsureScriptPath, 'utf8');
  const seedSource = fs.readFileSync(intendedLocalConsoleSeedScriptPath, 'utf8');
  const intendedConfigSource = fs.readFileSync(intendedConfigPath, 'utf8');
  const preflightSource = fs.readFileSync(intendedMutationSelfCheckScriptPath, 'utf8');
  const startupSource = fs.readFileSync(intendedCiStartupPath, 'utf8');
  expect(envSource).toContain("export const defaultEnvFile = '.env.intended.local'");
  expect(envSource).toContain('export const defaultGoogleProjectId =');
  expect(envSource).toContain('export const defaultGoogleClientId =');
  expect(envSource).toContain('fs.chmodSync(envFilePath, 0o600)');
  expect(setupSource).toContain('iamcredentials.googleapis.com');
  expect(setupSource).toContain('roles/iam.serviceAccountTokenCreator');
  expect(setupSource).toContain('add-iam-policy-binding');
  expect(setupSource).toContain('SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT');
  expect(setupSource).toContain('GOOGLE_OIDC_CLIENT_ID');
  expect(setupSource).toContain('SEAMS_INTENDED_GOOGLE_CLIENT_SECRET');
  expect(setupSource).toContain('GOOGLE_OIDC_CLIENT_SECRET');
  expect(setupSource).toContain('--client-secret');
  expect(setupSource).toContain('refresh-intended-google-token.mjs');
  expect(refreshSource).toContain('--impersonate-service-account=');
  expect(refreshSource).toContain('--audiences=');
  expect(refreshSource).toContain('validateGoogleIdTokenClaims');
  expect(refreshSource).toContain('SEAMS_INTENDED_GOOGLE_ID_TOKEN');
  expect(refreshSource).not.toContain('console.log(token');
  expect(ensureSource).toContain('refresh-intended-google-token.mjs');
  expect(ensureSource).toContain('SEAMS_INTENDED_GOOGLE_ID_TOKEN');
  expect(ensureSource).toContain('SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT');
  expect(ensureSource).toContain('minimumTtlSeconds');
  expect(ensureSource).not.toContain('console.log(token');
  expect(seedSource).toContain('ak_intended_local_publishable');
  expect(seedSource).toContain('hashApiKeySecret');
  expect(seedSource).toContain('SEAMS_INTENDED_PUBLISHABLE_KEY');
  expect(seedSource).toContain('SEAMS_INTENDED_PROJECT_ENVIRONMENT_ID');
  expect(seedSource).toContain('dotenv.config({ path: envFilePath, override: true })');
  expect(intendedConfigSource).toContain(
    "dotenv.config({ path: path.join(repoRoot, '.env.intended.local'), override: false })",
  );
  expect(preflightSource).toContain(
    "dotenv.config({ path: path.join(repoRoot, '.env.intended.local'), override: true })",
  );
  expect(startupSource).toContain(
    "dotenv.config({ path: path.join(repoRoot, '.env.intended.local'), override: true })",
  );
  expect(startupSource).toContain('seed:intended-local-console');
});
test('Refactor 88 retired registration-flow benchmark commands stay absent', () => {
  const rootPackage = readJsonRecord(rootPackageJsonPath);
  const testsPackage = readJsonRecord(testsPackageJsonPath);
  const violations = [];
  collectRetiredScriptViolations('package.json', rootPackage, violations);
  collectRetiredScriptViolations('tests/package.json', testsPackage, violations);
  expect(violations, violations.join('\n')).toEqual([]);
});
test('Refactor 88 generic Playwright config excludes intended contracts', () => {
  const source = fs.readFileSync(genericPlaywrightConfigPath, 'utf8');
  expect(source).toContain("'**/e2e/**/*.test.ts'");
  expect(source).toContain("testIgnore: ['**/e2e/intended-behaviours/**']");
});
test('Refactor 88 registration-flow benchmark report stays marked historical', () => {
  const source = fs.readFileSync(registrationFlowBenchmarkReportPath, 'utf8');
  const violations = [];
  if (
    !source.startsWith('# Registration Flow Benchmark Report\n\nStatus: archived historical report')
  ) {
    violations.push('docs/benchmarks/registration-flow.md: archive notice must stay at the top');
  }
  for (const token of registrationFlowBenchmarkArchiveTokens) {
    if (source.includes(token)) continue;
    violations.push(`docs/benchmarks/registration-flow.md: missing ${token}`);
  }
  expect(violations, violations.join('\n')).toEqual([]);
});
test('Refactor 88 signing integration suite stays off the fake relay server', () => {
  const testsPackage = readJsonRecord(testsPackageJsonPath);
  const integrationScript = readScript(testsPackage, 'test:integration:signing');
  expect(integrationScript).toContain(
    'playwright test -c playwright.integration.config.ts --reporter=line',
  );
  assertScriptAvoidsFakeRelayServer('test:integration:signing', integrationScript);
});
test('Refactor 88 generic e2e script stays off the fake relay server', () => {
  const testsPackage = readJsonRecord(testsPackageJsonPath);
  const e2eScript = readScript(testsPackage, 'test:e2e');
  expect(e2eScript).toContain('playwright test ./e2e --reporter=line');
  assertScriptAvoidsFakeRelayServer('test:e2e', e2eScript);
});
test('Refactor 88 full generic suite stays off the fake relay server', () => {
  const testsPackage = readJsonRecord(testsPackageJsonPath);
  const testScript = readScript(testsPackage, 'test');
  expect(testScript).toContain('playwright test --reporter=line');
  assertScriptAvoidsFakeRelayServer('test', testScript);
});
test('Refactor 88 lite suite stays off the fake relay server', () => {
  const testsPackage = readJsonRecord(testsPackageJsonPath);
  const liteScript = readScript(testsPackage, 'test:lite');
  expect(liteScript).toContain('playwright test -c playwright.lite.config.ts --reporter=line');
  assertScriptAvoidsFakeRelayServer('test:lite', liteScript);
});
test('Refactor 88 inline suite stays off the fake relay server', () => {
  const testsPackage = readJsonRecord(testsPackageJsonPath);
  const inlineScript = readScript(testsPackage, 'test:inline');
  expect(inlineScript).toContain('playwright test --reporter=line');
  assertScriptAvoidsFakeRelayServer('test:inline', inlineScript);
});
test('Refactor 88 package scripts never launch the fake relay server', () => {
  const testsPackage = readJsonRecord(testsPackageJsonPath);
  const scripts = readScriptsRecord(testsPackage);
  for (const [scriptName, script] of Object.entries(scripts)) {
    assertScriptAvoidsFakeRelayServer(scriptName, script);
  }
});
test('Refactor 88 source-script suite name no longer refers to Router API server scripts', () => {
  const testsPackage = readJsonRecord(testsPackageJsonPath);
  const scripts = readScriptsRecord(testsPackage);
  expect(scripts['test:unit:scripts']).toBe(
    'playwright test -c playwright.scripts.config.ts --reporter=line',
  );
  expect(Object.hasOwn(scripts, 'test:unit:router-api-server-scripts')).toBe(false);
});
test('Refactor 88 wallet-service e2e header smoke stays off SDK plugin headers', () => {
  const source = fs.readFileSync(walletServiceHeadersTestPath, 'utf8');
  expect(source).toContain('app-origin wallet-service path does not emit SDK plugin headers');
  expect(source).toContain("headers['permissions-policy']");
  expect(source).toContain("headers['content-security-policy']");
  expect(source).toContain("headers['cross-origin-opener-policy']");
  expect(source).toContain("headers['cross-origin-embedder-policy']");
  expect(source).toContain("headers['cross-origin-resource-policy']");
  expect(source).not.toContain('buildPermissionsPolicy');
  expect(source).not.toContain('buildWalletCsp');
  expect(source).not.toContain('DEFAULT_LOCAL_WALLET_ORIGIN');
  expect(source).not.toContain("'https://wallet.example.localhost'");
});
test('Refactor 88 intended config is serial Chromium with zero retries and a suite budget', () => {
  const source = fs.readFileSync(intendedConfigPath, 'utf8');
  expect(source).toContain('fullyParallel: false');
  expect(source).toContain('workers: 1');
  expect(source).toContain('retries: 0');
  expect(source).toContain('globalTimeout: 600_000');
  expect(source).toContain("name: 'chromium'");
  expect(source).toContain("devices['Desktop Chrome']");
  expect(source).not.toContain('webServer');
  expect(source).not.toContain('USE_RELAY_SERVER');
  expect(source).not.toContain('start-servers.mjs');
  expect(source).not.toContain('test-router-api-server.mjs');
});
test('Refactor 88 intended CI config owns service startup', () => {
  const configSource = fs.readFileSync(intendedCiConfigPath, 'utf8');
  const startupSource = fs.readFileSync(intendedCiStartupPath, 'utf8');
  expect(configSource).toContain("command: 'node ./scripts/start-intended-services.mjs'");
  expect(configSource).toContain('WEB_SERVER_READY_URL');
  expect(configSource).toContain("'http://127.0.0.1:37888/readyz'");
  expect(configSource).toContain('reuseExistingServer: false');
  expect(configSource).toContain("gracefulShutdown: { signal: 'SIGTERM', timeout: 30_000 }");
  expect(configSource).toContain('timeout: 420_000');
  expect(startupSource).toContain("spawnSync('pnpm'");
  expect(startupSource).toContain(
    "runRequiredBuild('sdk and Router A/B Workers', ['run', 'build:sdk-full'], {",
  );
  expect(startupSource).toContain('function assertSdkDistArtifacts()');
  expect(startupSource).toContain('requiredSdkDistArtifacts');
  expect(startupSource).toContain('function clearTransientViteCaches()');
  expect(startupSource).toContain("'apps/seams-site/node_modules/.vite'");
  expect(startupSource).toContain('function waitForSiteModuleGraphArtifacts()');
  expect(startupSource).toContain('siteModuleGraphUrl(relativePath)');
  expect(startupSource).toContain('`/@fs${absolutePath}`');
  expect(startupSource).toContain("spawnManaged('site'");
  expect(startupSource).toContain("['-C', 'apps/seams-site', 'run', 'vite']");
  expect(startupSource).not.toContain("spawnManaged('site', ['run', 'site']");
  expect(startupSource).toContain('function startRouter()');
  expect(startupSource).toContain("    'router',");
  expect(startupSource).toContain(
    "['run', 'router', '--', '--root', routerAbLocalRoot, '--no-init']",
  );
  expect(startupSource).toContain('localEnvRoot: routerAbLocalRoot');
  expect(startupSource).toContain('SEAMS_INTENDED_ROUTER_AB_ROOT');
  expect(startupSource).toContain('function initializeRouterAbLocalEnv()');
  expect(startupSource).toContain("'--bin',");
  expect(startupSource).toContain("'router_ab_local_init',");
  expect(startupSource).toContain('removeAbsolutePath(routerAbLocalRoot)');
  expect(startupSource).toContain(
    "removePath('packages/console-server-ts/.wrangler/state/seams-d1')",
  );
  expect(startupSource).toContain('VITE_SEAMS_PROJECT_ENVIRONMENT_ID: projectEnvironmentId');
  expect(startupSource).toContain('VITE_SEAMS_PUBLISHABLE_KEY: publishableKey');
  expect(startupSource).toContain("waitForHttpOk(`${routerUrl}/readyz`, 'router readyz'");
  expect(startupSource).toContain('function startWebServerReadyServer()');
  expect(startupSource).toContain('function handleWebServerReadyRequest(request, response)');
  expect(startupSource).toContain("request.url === '/readyz'");
  expect(startupSource).toContain("terminateManagedProcessLeaks('SIGTERM')");
  expect(startupSource).toContain("terminateManagedProcessLeaks('SIGKILL')");
  expect(startupSource).toContain('function isLocalWorkerdCommand(command)');
  assertTokensAppearInOrder(
    startupSource,
    [
      'const router = startRouter();',
      "await waitForHttpOk(`${routerUrl}/healthz`, 'router healthz', 180_000);",
      "await waitForHttpOk(`${routerUrl}/readyz`, 'router readyz', 180_000);",
      'const site = startSite();',
      "await waitForHttpOk(appUrl, 'site', 120_000);",
      'await waitForSiteModuleGraphArtifacts();',
      "await waitForHttpOk(intendedPageSmokeUrl(), 'intended page', 60_000);",
      'await startWebServerReadyServer();',
    ],
    'intended CI service startup order',
  );
});
test('Refactor 88 intended route is gated to dev and explicit CI opt-in', () => {
  const configSource = fs.readFileSync(seamsSiteConfigPath, 'utf8');
  const appSource = fs.readFileSync(seamsSiteAppPath, 'utf8');
  const startupSource = fs.readFileSync(intendedCiStartupPath, 'utf8');
  expect(configSource).toContain('enableIntendedE2E');
  expect(configSource).toContain('env.VITE_ENABLE_INTENDED_E2E');
  expect(configSource).toContain('env.DEV === true');
  expect(appSource).toContain("case '/__intended-e2e':");
  expect(appSource).toContain('FRONTEND_CONFIG.enableIntendedE2E ? <IntendedBehaviourE2EPage />');
  expect(appSource).toContain(': <NotFoundPage />');
  expect(startupSource).toContain("VITE_ENABLE_INTENDED_E2E: '1'");
});
test('Refactor 88 intended harness fails fast when a public action click is inert', () => {
  const source = fs.readFileSync(intendedHarnessPath, 'utf8');
  const startMethod = source.match(
    /private async waitForIntendedPageActionStarted[\s\S]*?\n {2}private async closeExportViewerIfOpen/,
  );
  expect(startMethod, 'waitForIntendedPageActionStarted method').not.toBeNull();
  expect(source).toContain('intendedPageActionStartedOrCompleted');
  expect(source).toContain('did not start after click');
  expect(source).toContain('tryReadIntendedPageSnapshot');
  expect(source).toContain('Page snapshot:');
  expect(startMethod?.[0]).not.toContain('.catch(() => undefined)');
});
test('Refactor 88 NEAR signing contract verifies Ed25519 signatures cryptographically', () => {
  const source = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(source).toContain('verifyNearEd25519Signature');
  expect(source).toContain('ed25519.verifyAsync');
  expect(source).toContain('parseNearUnsignedTransactionSubject');
  expect(source).toContain('base58Decode');
  expect(source).toContain("createHash('sha256')");
});
test('Refactor 88 ECDSA contracts recover Tempo and Arc/EVM signer addresses', () => {
  const source = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(source).toContain('verifyTempoEcdsaSignature');
  expect(source).toContain('verifyArcEvmSignature');
  expect(source).toContain('recoverAddress');
  expect(source).toContain('recoverTransactionAddress');
  expect(source).toContain('decodeTempoSignedTransaction');
  expect(source).toContain('thresholdEcdsaEthereumAddress');
});
test('Refactor 88 signing contracts assert structured auth-path events', () => {
  const source = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(source).toContain('assertSigningAuthEvents');
  expect(source).toContain('signing.auth.warm_session.claimed');
  expect(source).toContain('signing.auth.passkey.prompt.started');
  expect(source).toContain('signing.auth.email_otp.challenge.sent');
  expect(source).toContain('did not claim a warm signing session');
});
test('Refactor 88 post-exhaustion contracts require per-operation step-up', () => {
  const source = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(source).toContain(
    "return flow.startsWith('passkey') ? 'passkey_step_up' : 'email_otp_step_up'",
  );
  expect(source).not.toContain('passkey_step_up_or_warm_session');
  expect(source).not.toContain('email_otp_step_up_or_warm_session');
  expect(source).not.toContain('postExhaustionStepUpSatisfied');
});
test('Refactor 88 intended harness only stubs external identity and chain RPC hosts', () => {
  const source = fs.readFileSync(intendedHarnessPath, 'utf8');
  const externalHosts = extractDelimitedSource(
    source,
    'const EXTERNAL_HOST_PATTERNS = [',
    '] as const;',
  );
  const routeHandler = extractDelimitedSource(
    source,
    'private async handleExternalRoute',
    'private handleConsoleMessage',
  );
  const fulfillStub = extractDelimitedSource(
    source,
    'async function fulfillExternalStub',
    'async function fulfillNearRpcStub',
  );
  expect(externalHosts).toContain('googleapis\\.com');
  expect(externalHosts).toContain('accounts\\.google\\.com');
  expect(externalHosts).toContain('near\\.org');
  expect(externalHosts).toContain('fastnear\\.com');
  expect(externalHosts).toContain('rpc\\.moderato\\.tempo\\.xyz');
  expect(externalHosts).toContain('rpc\\.testnet\\.arc\\.network');
  expect(externalHosts).not.toContain('localhost');
  expect(externalHosts).not.toContain('router');
  expect(externalHosts).not.toContain('wallet');
  assertTokensAppearInOrder(
    routeHandler,
    [
      'if (!isExternalStubHost(url.hostname))',
      'await route.continue();',
      'return;',
      'await fulfillExternalStub(route, this.config);',
    ],
    'intended harness external route boundary',
  );
  expect(fulfillStub).not.toContain('routerUrl');
  expect(fulfillStub).not.toContain('walletOrigin');
  expect(fulfillStub).not.toContain('/__intended-e2e');
});
test('Refactor 88 passkey unlock preserves storage while clearing page runtime', () => {
  const source = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(source).toContain('resetRuntimeOnlyState');
  expect(source).toContain("this.page.goto('about:blank')");
  expect(source).toContain('requirePasskeyUnlockResult');
  expect(source).toContain('passkey_unlock_success');
});
test('Refactor 88 passkey contracts use a PRF-capable virtual authenticator', () => {
  const source = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(source).toContain('WebAuthn.addVirtualAuthenticator');
  expect(source).toContain('hasPrf: true');
});
test('Refactor 88 Email OTP unlock uses public flow and dev outbox readback', () => {
  const pageSource = fs.readFileSync(
    path.join(repoRoot, 'apps/seams-site/src/pages/intended-e2e/page.tsx'),
    'utf8',
  );
  const harnessSource = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(pageSource).toContain('beginGoogleEmailOtpWalletAuth');
  expect(pageSource).toContain("mode: 'login'");
  expect(pageSource).toContain("mode: 'register'");
  expect(pageSource).toContain('googleEmailOtpLoginFlowChallengeId');
  expect(pageSource).toContain('/wallet/email-otp/dev/otp-outbox');
  expect(pageSource).toContain('__seamsIntendedE2EReadEmailOtpCode');
  expect(pageSource).toContain('email_otp_unlock_success');
  expect(harnessSource).toContain('fillWalletIframeEmailOtpIfAvailable');
  expect(harnessSource).toContain('readWalletIframeEmailOtpChallengeId');
  expect(harnessSource).toContain('otpFilled');
});
test('Refactor 88 remaining-spend exhaustion is driven by public signing', () => {
  const source = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(source).toContain('exhaustSigningBudget');
  expect(source).toContain('remaining_spend.exhaust');
  expect(source).toContain('MAX_BUDGET_EXHAUSTION_SIGNS');
  expect(source).toContain('minimumRemainingUse');
  expect(source).toContain('this.signNearTransaction(this.currentWarmSigningStage)');
  expect(source).toContain('NEAR remaining spend did not exhaust');
  expect(source).not.toContain('IntendedHarnessActionNotImplementedError');
});
test('Refactor 88 ECDSA key export uses public exact-lane export UI', () => {
  const pageSource = fs.readFileSync(
    path.join(repoRoot, 'apps/seams-site/src/pages/intended-e2e/page.tsx'),
    'utf8',
  );
  const harnessSource = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(pageSource).toContain('resolveExactKeyExportLane');
  expect(pageSource).toContain('exportKeypairWithUI');
  expect(pageSource).toContain('ecdsa_export_success');
  expect(harnessSource).toContain('requireEcdsaExportResult');
  expect(harnessSource).toContain('assertKeyExportAuthEvents');
  expect(harnessSource).toContain('key_export.auth.passkey.prompt.started');
  expect(harnessSource).toContain('did not fill a fresh Email OTP export authorization');
});
function hasRefactor88KeepClassification(relativePath) {
  const planSource = fs.readFileSync(refactor88PlanPath, 'utf8');
  return planSource.includes('| `' + relativePath + '` | keep |');
}
function assertTokensAppearInOrder(source, tokens, label) {
  let offset = 0;
  for (const token of tokens) {
    const nextOffset = source.indexOf(token, offset);
    if (nextOffset < 0) {
      throw new Error(`${label} missing or reordered lifecycle action: ${token}`);
    }
    offset = nextOffset + token.length;
  }
}
function missingSourceTokens(source, tokens) {
  const missing = [];
  for (const token of tokens) {
    if (!source.includes(token)) missing.push(token);
  }
  return missing;
}
function extractModuleSpecifiers(source) {
  const specifiers = [];
  const importFromPattern = /\bimport\s+(?:type\s+)?[\s\S]*?\s+from\s+['"]([^'"]+)['"]/g;
  const sideEffectImportPattern = /\bimport\s+['"]([^'"]+)['"]/g;
  const dynamicImportPattern = /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  collectModuleSpecifiers(source, importFromPattern, specifiers);
  collectModuleSpecifiers(source, sideEffectImportPattern, specifiers);
  collectModuleSpecifiers(source, dynamicImportPattern, specifiers);
  return [...new Set(specifiers)].sort();
}
function collectModuleSpecifiers(source, pattern, specifiers) {
  for (const match of source.matchAll(pattern)) {
    const specifier = match[1];
    if (specifier) specifiers.push(specifier);
  }
}
function extractUnionMembers(source, typeName) {
  const unionSource = extractDelimitedSource(source, `type ${typeName} =`, ';');
  return [...unionSource.matchAll(/\|\s+([A-Za-z][A-Za-z0-9_]*)/g)].map((match) => match[1]);
}
function extractUniqueSwitchCases(source) {
  const cases = [...source.matchAll(/case\s+'([^']+)'/g)].map((match) => match[1]);
  return [...new Set(cases)].sort();
}
function extractUniqueSwitchCasesBeforeDefault(source, switchToken) {
  const switchStart = source.indexOf(switchToken);
  if (switchStart < 0) {
    throw new Error(`source missing switch token: ${switchToken}`);
  }
  const defaultStart = source.indexOf('default:', switchStart + switchToken.length);
  if (defaultStart < 0) {
    throw new Error(`source missing default branch after switch token: ${switchToken}`);
  }
  return extractUniqueSwitchCases(source.slice(switchStart, defaultStart));
}
function extractDelimitedSource(source, startToken, endToken) {
  const start = source.indexOf(startToken);
  if (start < 0) {
    throw new Error(`source missing start token: ${startToken}`);
  }
  const end = source.indexOf(endToken, start + startToken.length);
  if (end < 0) {
    throw new Error(`source missing end token after ${startToken}: ${endToken}`);
  }
  return source.slice(start, end);
}
function listTypeScriptFiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const absolutePath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listTypeScriptFiles(absolutePath));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith('.ts')) {
      files.push(path.relative(repoRoot, absolutePath).replaceAll(path.sep, '/'));
    }
  }
  return files.sort();
}
function listSourceTextFiles(relativeRoots) {
  return relativeRoots.flatMap(listSourceTextFilesInRoot).sort();
}
function listSourceTextFilesInRoot(relativeRoot) {
  return listSourceTextFilesRecursive(path.join(repoRoot, relativeRoot));
}
function listSourceTextFilesRecursive(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const absolutePath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'out' || entry.name === 'dist') {
        continue;
      }
      files.push(...listSourceTextFilesRecursive(absolutePath));
      continue;
    }
    if (!entry.isFile() || !isSourceTextFile(entry.name)) continue;
    files.push(path.relative(repoRoot, absolutePath).replaceAll(path.sep, '/'));
  }
  return files;
}
function isSourceTextFile(fileName) {
  return ['.ts', '.tsx', '.js', '.mjs', '.cjs'].some((extension) => fileName.endsWith(extension));
}
function readJsonRecord(filePath) {
  const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (!isRecord(parsed)) {
    throw new Error(`${filePath} must contain a JSON object`);
  }
  return parsed;
}
function readScript(packageJson, scriptName) {
  const scripts = readScriptsRecord(packageJson);
  const script = scripts[scriptName];
  if (typeof script !== 'string') {
    throw new Error(`package.json script ${scriptName} must be a string`);
  }
  return script;
}
function readScriptsRecord(packageJson) {
  const scripts = packageJson.scripts;
  if (!isRecord(scripts)) {
    throw new Error('package.json scripts must be an object');
  }
  const result = {};
  for (const [scriptName, script] of Object.entries(scripts)) {
    if (typeof script !== 'string') {
      throw new Error(`package.json script ${scriptName} must be a string`);
    }
    result[scriptName] = script;
  }
  return result;
}
function assertScriptAvoidsFakeRelayServer(scriptName, script) {
  const violations = [];
  for (const token of fakeRelayServerScriptTokens) {
    if (!script.includes(token)) continue;
    violations.push(`${scriptName}: ${token}`);
  }
  expect(violations, violations.join('\n')).toEqual([]);
}
function collectRetiredScriptViolations(label, packageJson, violations) {
  const scripts = readScriptsRecord(packageJson);
  for (const [scriptName, scriptValue] of Object.entries(scripts)) {
    if (typeof scriptValue !== 'string') {
      violations.push(`${label}: script ${scriptName} must be a string`);
      continue;
    }
    for (const token of retiredRegistrationFlowBenchmarkTokens) {
      if (scriptName.includes(token) || scriptValue.includes(token)) {
        violations.push(`${label}: ${scriptName} references retired ${token}`);
      }
    }
  }
}
function isRecord(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

console.log('[intended-behaviour-contract-boundaries] ok');
