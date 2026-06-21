import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const sdkPreparedIssuerSurfaceFiles = [
  'packages/sdk-web/src/core/types/signer-worker.ts',
  'packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts',
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/near-signer.worker.ts',
  'packages/sdk-web/src/core/signingEngine/chains/near/nearSignerWasm.ts',
] as const;

const generatedNearSignerWorkerFiles = [
  'wasm/near_signer/pkg/wasm_signer_worker.d.ts',
  'wasm/near_signer/pkg/wasm_signer_worker.js',
] as const;

const setupRestoreUnlockSigningRoots = [
  'packages/sdk-web/src/SeamsWeb/operations/auth',
  'packages/sdk-web/src/SeamsWeb/operations/registration',
  'packages/sdk-web/src/SeamsWeb/operations/session',
  'packages/sdk-web/src/SeamsWeb/signingSurface',
  'packages/sdk-web/src/core/signingEngine/flows/signNear',
  'packages/sdk-web/src/core/signingEngine/session',
  'packages/sdk-web/src/core/signingEngine/threshold/ed25519',
] as const;

const verifierDerivationDefinitionFile =
  'packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts';

const emailOtpEd25519ReconstructionFiles = [
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/provisioning.ts',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Warmup.ts',
] as const;

const emailOtpEd25519RecoveryCodeHydrationAdapterFile =
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/recoveryCodeWarmSessionHydration.ts';

const emailOtpEd25519RecoveryCodeSurfaceFiles = [
  'packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/enrollment.ts',
  'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/clientSecretSource.ts',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Warmup.ts',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/walletEnrollment.ts',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/walletUnlock.ts',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/workerEnrollment.ts',
  'packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts',
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
] as const;

const rawClientBaseAllowedActiveFiles = new Set([
  'packages/sdk-web/src/core/types/signer-worker.ts',
  'packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts',
  'packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssClientBase.ts',
  'packages/sdk-web/src/core/signingEngine/threshold/ed25519/workerMaterialHandle.ts',
  'packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts',
  'packages/sdk-web/src/core/signingEngine/session/persistence/records.ts',
  'packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts',
  'packages/sdk-web/src/core/signingEngine/session/sealedRecovery/recoveryRecord.ts',
  'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ed25519Authorization.ts',
]);

const clientOutputMaskAllowedActiveFiles = new Set([
  'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
  'packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts',
  'packages/sdk-web/src/core/types/signer-worker.ts',
  'packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts',
  'packages/sdk-web/src/core/signingEngine/threshold/ed25519/clientOutputMask.ts',
  'packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts',
  'packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts',
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/hss-client.worker.ts',
]);

const secretBearingMaterialAuthorizationAllowedFiles = new Set([
  'packages/sdk-web/src/core/types/signer-worker.ts',
  'packages/sdk-web/src/core/signingEngine/chains/near/nearSignerWasm.ts',
  'packages/sdk-web/src/core/signingEngine/session/passkey/prfClaim.ts',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/clientSecretSource.ts',
  'packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts',
]);

const ed25519RestorePersistenceBoundaryFiles = [
  'packages/sdk-web/src/core/signingEngine/session/persistence/records.ts',
  'packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts',
  'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistence.ts',
  'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistencePorts.ts',
  'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/types.ts',
  'packages/sdk-web/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts',
  'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519SigningMaterialReadiness.ts',
  'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519MaterialRestoreAuthorization.ts',
] as const;

const materialAuthorizationIssuerCallSiteAllowedFiles = new Set([
  'packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts',
  'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519MaterialRestoreAuthorization.ts',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/clientSecretSource.ts',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/provisioning.ts',
  'packages/sdk-web/src/core/signingEngine/session/passkey/prfClaim.ts',
]);

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function sourceRangeBetween(source: string, startNeedle: string, endNeedle: string): string {
  const start = source.indexOf(startNeedle);
  expect(start, `missing source range start: ${startNeedle}`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf(endNeedle, start + startNeedle.length);
  expect(end, `missing source range end: ${endNeedle}`).toBeGreaterThan(start);
  return source.slice(start, end);
}

function listTypeScriptFiles(relativePath: string): string[] {
  const absolutePath = path.join(repoRoot, relativePath);
  const stat = fs.statSync(absolutePath);
  if (stat.isFile()) return /\.tsx?$/.test(relativePath) ? [relativePath] : [];

  const files: string[] = [];
  for (const entry of fs.readdirSync(absolutePath, { withFileTypes: true })) {
    if (entry.name === 'dist' || entry.name === 'node_modules') continue;
    const childPath = path.join(relativePath, entry.name);
    if (entry.isDirectory()) files.push(...listTypeScriptFiles(childPath));
    if (entry.isFile() && /\.tsx?$/.test(entry.name)) files.push(childPath);
  }
  return files;
}

function countMarker(source: string, marker: string): number {
  return source.split(marker).length - 1;
}

function collectForbiddenMarkerOffenders(
  relativePaths: readonly string[],
  forbiddenMarkers: readonly string[],
): string[] {
  const offenders: string[] = [];
  for (const relativePath of relativePaths) {
    const source = readRepoSource(relativePath);
    for (const marker of forbiddenMarkers) {
      if (source.includes(marker)) offenders.push(`${relativePath} contains ${marker}`);
    }
  }
  return offenders;
}

function expectMarkersPresent(relativePath: string, requiredMarkers: readonly string[]): void {
  const source = readRepoSource(relativePath);
  const missingMarkers: string[] = [];
  for (const marker of requiredMarkers) {
    if (!source.includes(marker)) missingMarkers.push(marker);
  }
  expect(missingMarkers, missingMarkers.join('\n')).toEqual([]);
}

function setupRestoreUnlockSigningFiles(): string[] {
  const allFiles: string[] = [];
  for (const root of setupRestoreUnlockSigningRoots) {
    allFiles.push(...listTypeScriptFiles(root));
  }
  return [...new Set(allFiles)].sort();
}

function preparedIssuerWorkerSurfaceUsesPreparedCommandsOnly(): void {
  const forbiddenDirectInstallMarkers = [
    'ThresholdEd25519InstallPasskeyPrfMaterialAuthorization',
    'ThresholdEd25519InstallRecoveryCodeMaterialAuthorization',
    'installThresholdEd25519PasskeyPrfMaterialAuthorization',
    'installThresholdEd25519RecoveryCodeMaterialAuthorization',
    'threshold_ed25519_install_passkey_prf_material_authorization',
    'threshold_ed25519_install_recovery_code_material_authorization',
  ] as const;
  const offenders = collectForbiddenMarkerOffenders(
    sdkPreparedIssuerSurfaceFiles,
    forbiddenDirectInstallMarkers,
  );

  expect(offenders, offenders.join('\n')).toEqual([]);
  expectMarkersPresent('packages/sdk-web/src/core/types/signer-worker.ts', [
    'ThresholdEd25519PreparePasskeyPrfWorkerMaterialSealAuthorization',
    'ThresholdEd25519PrepareRecoveryCodeWorkerMaterialSealAuthorization',
    'ThresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorization',
    'ThresholdEd25519PrepareRecoveryCodeWorkerMaterialUnsealAuthorization',
  ]);
}

function generatedNearSignerPackageExportsPreparedIssuerCommandsOnly(): void {
  const forbiddenGeneratedMarkers = [
    'threshold_ed25519_install_passkey_prf_material_authorization',
    'threshold_ed25519_install_recovery_code_material_authorization',
  ] as const;
  const offenders = collectForbiddenMarkerOffenders(
    generatedNearSignerWorkerFiles,
    forbiddenGeneratedMarkers,
  );

  expect(offenders, offenders.join('\n')).toEqual([]);
  expectMarkersPresent('wasm/near_signer/pkg/wasm_signer_worker.d.ts', [
    'threshold_ed25519_prepare_passkey_prf_worker_material_seal_authorization',
    'threshold_ed25519_prepare_recovery_code_worker_material_seal_authorization',
    'threshold_ed25519_prepare_passkey_prf_worker_material_unseal_authorization',
    'threshold_ed25519_prepare_recovery_code_worker_material_unseal_authorization',
    'threshold_ed25519_prepare_hss_client_output_mask_handle',
  ]);
}

function preparedIssuerResultValidatorsExposeOnlyPublicFactsAndHandles(): void {
  const source = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/chains/near/nearSignerWasm.ts',
  );
  const unsealValidator = sourceRangeBetween(
    source,
    'function requireThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult',
    'function requireThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult',
  );
  const sealValidator = sourceRangeBetween(
    source,
    'function requireThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult',
    'function requireThresholdEd25519PutSealedWorkerMaterialResult',
  );
  const forbiddenResultMarkers = [
    'prfFirstBytes',
    'recoveryCodeSecret32',
    'clientOutputMaskB64u',
    'clientVerifyingShareB64u',
    'xClientBaseB64u',
    'sealedWorkerMaterialB64u',
  ] as const;

  for (const marker of forbiddenResultMarkers) {
    expect(unsealValidator, `unseal result validator exposes ${marker}`).not.toContain(marker);
    expect(sealValidator, `seal result validator exposes ${marker}`).not.toContain(marker);
  }
  expect(unsealValidator).toContain('unsealAuthorization');
  expect(unsealValidator).toContain('remainingUses');
  expect(sealValidator).toContain('materialKeyId');
  expect(sealValidator).toContain('sealAuthorization');
  expect(sealValidator).toContain('remainingUses');
}

function storeFromHssRequestKeepsVerifierDerivedInsideWorker(): void {
  const source = readRepoSource('packages/sdk-web/src/core/types/signer-worker.ts');
  const requestType = sourceRangeBetween(
    source,
    'export type ThresholdEd25519StoreWorkerMaterialFromHssOutputRequest = {',
    'export type ThresholdEd25519StoreWorkerMaterialFromHssOutputResult',
  );

  expect(requestType).toContain('sealAuthorization');
  expect(requestType).toContain('nearAccountId');
  expect(requestType).toContain('signerSlot');
  expect(requestType).toContain('signingRootId');
  expect(requestType).toContain('relayerKeyId');
  expect(requestType).toContain('clientOutputMask: ThresholdEd25519HssClientOutputMaskTransport');
  expect(requestType).not.toContain('clientOutputMaskB64u');
  expect(requestType).not.toContain('clientVerifyingShareB64u');
  expect(requestType).not.toContain('materialBindingDigest');
}

function setupRestoreUnlockAndSigningDoNotCallDeletedMaterialHelpers(): void {
  const helperName = 'deriveThresholdEd25519ClientVerifyingShareFromPrfFirst';
  const helperCallPattern = /\bderiveThresholdEd25519ClientVerifyingShareFromPrfFirst\s*\(/;
  const deletedPrewarmHelper = 'prewarmThresholdEd25519ClientBaseFromCredential';
  const offenders: string[] = [];

  for (const relativePath of setupRestoreUnlockSigningFiles()) {
    const source = readRepoSource(relativePath);
    if (source.includes(deletedPrewarmHelper)) {
      offenders.push(`${relativePath} references ${deletedPrewarmHelper}`);
    }
    if (relativePath === verifierDerivationDefinitionFile) {
      if (countMarker(source, helperName) !== 1) {
        offenders.push(`${relativePath} has helper references beyond the definition`);
      }
      continue;
    }
    if (helperCallPattern.test(source)) {
      offenders.push(`${relativePath} calls ${helperName}`);
    }
  }

  expect(offenders, offenders.join('\n')).toEqual([]);
}

function emailOtpEd25519ReconstructionUsesRecoveryCodeSecretName(): void {
  const provisioningSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/provisioning.ts',
  );
  const reconstructionArgs = sourceRangeBetween(
    provisioningSource,
    'export type ReconstructEmailOtpEd25519SessionArgs =',
    'function normalizeOptionalString',
  );
  const oldReconstructionInputPattern =
    /kind:\s*'session_ed25519_reconstruction'[\s\S]{0,600}\bprfFirstB64u\s*:/;
  const offenders: string[] = [];

  expect(reconstructionArgs).toContain('recoveryCodeSecret32B64u: string;');
  expect(reconstructionArgs).not.toContain('prfFirstB64u: string;');

  for (const relativePath of emailOtpEd25519ReconstructionFiles) {
    const source = readRepoSource(relativePath);
    if (oldReconstructionInputPattern.test(source)) {
      offenders.push(`${relativePath} constructs Ed25519 reconstruction with prfFirstB64u`);
    }
    if (source.includes('prfFirstB64u')) {
      offenders.push(`${relativePath} uses PRF.first naming in Email OTP Ed25519 reconstruction`);
    }
  }
  const hydrationAdapterSource = readRepoSource(emailOtpEd25519RecoveryCodeHydrationAdapterFile);
  expect(hydrationAdapterSource).toContain('recoveryCodeSecret32B64u');
  expect(hydrationAdapterSource).toContain('prfFirstB64u');
  for (const relativePath of emailOtpEd25519RecoveryCodeSurfaceFiles) {
    const source = readRepoSource(relativePath);
    if (source.includes('thresholdEd25519PrfFirstB64u')) {
      offenders.push(`${relativePath} exposes Email OTP Ed25519 material as PRF.first`);
    }
    if (source.includes('deriveEmailOtpEd25519PrfFirstB64u')) {
      offenders.push(`${relativePath} derives Email OTP Ed25519 material with PRF naming`);
    }
  }

  expect(offenders, offenders.join('\n')).toEqual([]);
}

function ed25519MaterialSecretErrorsUseRecoveryCodeDomain(): void {
  const hssLifecycleSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts',
  );
  const provisioningSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/provisioning.ts',
  );
  const recoveryCodeIssuerSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/clientSecretSource.ts',
  );
  const storeCeremonyArgs = sourceRangeBetween(
    hssLifecycleSource,
    'export async function runThresholdEd25519HssCeremonyWithMaterialHandle(args: {',
    '}): Promise<CompleteThresholdEd25519HssMaterialHandleCeremonyResult> {',
  );

  expect(storeCeremonyArgs).toContain('preparedSealAuthorization');
  expect(storeCeremonyArgs).not.toContain('materialSealAuthorizationSource');
  expect(hssLifecycleSource).not.toContain('ThresholdEd25519MaterialSealAuthorizationSource');
  expect(hssLifecycleSource).not.toContain('prfFirstBytes');
  expect(hssLifecycleSource).not.toContain('recoveryCodeSecret32');

  expect(recoveryCodeIssuerSource).toContain(
    'prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorizationNearSignerWasm',
  );
  expect(recoveryCodeIssuerSource).toContain('alphabetizeStringify');
  expect(recoveryCodeIssuerSource).toContain('sha256BytesUtf8');
  expect(recoveryCodeIssuerSource).toContain(
    'EMAIL_OTP_ED25519_RECOVERY_CODE_BINDING_DIGEST_KIND',
  );
  expect(recoveryCodeIssuerSource).not.toContain('recovery-code:');
  expect(recoveryCodeIssuerSource).toContain('recoveryCodeSecret32B64u');
  expect(recoveryCodeIssuerSource).not.toContain("kind: 'email_otp'");
  expect(provisioningSource).not.toContain(
    'prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorizationNearSignerWasm',
  );
  expect(provisioningSource).not.toContain('recoveryCodeSecret32 = decode');
}

function nearSigningMaterialResolverDoesNotReadPrfFirst(): void {
  const source = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingMaterials.ts',
  );
  const forbiddenMarkers = [
    'getPrfResultsFromCredential',
    'prfFirstB64u',
    'prfFirstBytes',
    'requirePrfFirstFromCredential',
  ] as const;
  const offenders = forbiddenMarkers.filter((marker) => source.includes(marker));

  expect(offenders, offenders.join('\n')).toEqual([]);
}

function finalNearSigningDoesNotOwnWorkerMaterialRestore(): void {
  const removedHelperPath = path.join(
    repoRoot,
    'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519SigningMaterialHandle.ts',
  );
  const readinessSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519SigningMaterialReadiness.ts',
  );
  const passkeyAuthorizationSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/passkey/prfClaim.ts',
  );

  expect(fs.existsSync(removedHelperPath)).toBe(false);
  expect(readinessSource).toContain('requireOrRestoreRouterAbEd25519WalletSessionState');
  expect(readinessSource).toContain('restoreThresholdEd25519WorkerMaterialNearSignerWasm');
  expect(readinessSource).toContain('ed25519MaterialUnsealAuthorizationRequiredError');
  expect(passkeyAuthorizationSource).not.toContain(
    'createWarmSessionClaimPasskeyUnsealAuthorizationIssuer',
  );
  expect(passkeyAuthorizationSource).not.toContain(
    'prepareThresholdEd25519PasskeyPrfWorkerMaterialUnsealAuthorizationNearSignerWasm',
  );
}

function ed25519SealAuthorizationSecretsLiveInCredentialBoundaries(): void {
  const passkeyAuthorizationSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/passkey/prfClaim.ts',
  );
  const emailAuthorizationSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/clientSecretSource.ts',
  );
  const warmBootstrapSource = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts',
  );
  const emailProvisioningSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/provisioning.ts',
  );
  const passkeySealHelperSource = sourceRangeBetween(
    passkeyAuthorizationSource,
    'export async function prepareThresholdEd25519PasskeyMaterialSealAuthorizationFromCredential',
    'export async function prepareThresholdEd25519PasskeyMaterialUnsealAuthorizationFromCredential',
  );
  const emailSealHelperSource = sourceRangeBetween(
    emailAuthorizationSource,
    'export async function prepareRecoveryCodeSealAuthorizationForEmailOtp',
    'export async function prepareRecoveryCodeUnsealAuthorizationForEmailOtp',
  );

  expect(passkeyAuthorizationSource).toContain('prfFirstBytes');
  expect(passkeyAuthorizationSource).toContain(
    'prepareThresholdEd25519PasskeyMaterialSealAuthorizationFromCredential',
  );
  expect(passkeyAuthorizationSource).toContain(
    'prepareThresholdEd25519PasskeyMaterialUnsealAuthorizationFromCredential',
  );
  expect(emailAuthorizationSource).toContain('recoveryCodeSecret32');
  expect(emailAuthorizationSource).toContain('prepareRecoveryCodeSealAuthorizationForEmailOtp');
  expect(emailAuthorizationSource).toContain('prepareRecoveryCodeUnsealAuthorizationForEmailOtp');
  expect(warmBootstrapSource).not.toContain('prfFirstBytes');
  expect(warmBootstrapSource).not.toContain('base64UrlDecode');
  expect(emailProvisioningSource).not.toContain('recoveryCodeSecret32 = decode');
  expect(emailProvisioningSource).not.toContain('base64UrlDecode');
  expect(passkeySealHelperSource).toContain(
    'requirePasskeyCredentialPrfFirstB64u(args.credential)',
  );
  expect(passkeySealHelperSource).toContain('finally');
  expect(passkeySealHelperSource).toContain('zeroizeSecretBytes(prfFirstBytes)');
  expect(passkeySealHelperSource).not.toContain('prfFirstB64u: string');
  expect(passkeySealHelperSource).not.toContain('args.prfFirstB64u');
  for (const sealHelperSource of [passkeySealHelperSource, emailSealHelperSource] as const) {
    expect(sealHelperSource).toContain(
      'expiresAtMs: WORKER_DEFAULT_MATERIAL_AUTHORIZATION_EXPIRES_AT_MS',
    );
    expect(sealHelperSource).not.toContain('expiresAtMs: args.expiresAtMs');
    expect(sealHelperSource).not.toContain('expiresAtMs: number;');
  }
}

function nearSigningFlowsUseSharedEd25519MaterialRestoreReadiness(): void {
  const restoreAuthorizationSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519MaterialRestoreAuthorization.ts',
  );
  const nearInterfacesSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/interfaces/near.ts',
  );
  const signingFlowFiles = [
    'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts',
  ] as const;
  const deletedDirectPrfClaimMarker = [
    'claim',
    'PrfFirst',
    'ByThreshold',
    'SessionId',
  ].join('');
  const offenders: string[] = [];

  for (const relativePath of signingFlowFiles) {
    const source = readRepoSource(relativePath);
    if (!source.includes('requireOrRestoreRouterAbEd25519WalletSessionState')) {
      offenders.push(`${relativePath} does not call the shared Ed25519 restore readiness helper`);
    }
    if (!source.includes('resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForStepUp')) {
      offenders.push(
        `${relativePath} does not use the shared Ed25519 restore authorization resolver`,
      );
    }
    if (!source.includes('refreshPasskeyEd25519SealedRecordAfterSigningMaterial')) {
      offenders.push(`${relativePath} does not refresh sealed Ed25519 restore metadata`);
    }
    if (source.includes('requireThresholdEd25519WorkerMaterialHandle')) {
      offenders.push(`${relativePath} still owns direct material-handle validation`);
    }
    if (source.includes(deletedDirectPrfClaimMarker)) {
      offenders.push(`${relativePath} claims raw PRF material`);
    }
    if (source.includes('loadRouterAbEd25519SigningMaterialForNearOperation')) {
      offenders.push(`${relativePath} calls the deleted restore loader`);
    }
    if (source.includes("kind: 'unseal_authorization_unavailable'")) {
      offenders.push(`${relativePath} hard-codes unavailable material unseal authorization`);
    }
  }
  if (
    !restoreAuthorizationSource.includes(
      'prepareThresholdEd25519PasskeyMaterialUnsealAuthorizationFromCredential',
    )
  ) {
    offenders.push(
      'shared restore authorization resolver does not use the passkey boundary issuer',
    );
  }
  if (restoreAuthorizationSource.includes(deletedDirectPrfClaimMarker)) {
    offenders.push('shared restore authorization resolver claims raw PRF material');
  }
  if (restoreAuthorizationSource.includes('prfFirstBytes')) {
    offenders.push('shared restore authorization resolver handles raw PRF bytes');
  }
  if (restoreAuthorizationSource.includes('recoveryCodeSecret32')) {
    offenders.push('shared restore authorization resolver handles raw recovery-code bytes');
  }
  if (
    !restoreAuthorizationSource.includes(
      'ed25519_email_otp_material_unseal_authorization_available',
    )
  ) {
    offenders.push(
      'shared restore authorization resolver does not accept Email OTP unseal handles',
    );
  }
  if (!restoreAuthorizationSource.includes('authorization.unsealAuthorization')) {
    offenders.push(
      'shared restore authorization resolver does not pass through opaque unseal handles',
    );
  }
  if (
    !nearInterfacesSource.includes('NearEd25519EmailOtpRecoveryCodeUnsealAuthorization') ||
    !nearInterfacesSource.includes("kind: 'recovery_code_material_authorization_handle_v1'") ||
    !nearInterfacesSource.includes("purpose: 'unseal'")
  ) {
    offenders.push('Email OTP restore type does not require a recovery-code unseal authorization');
  }
  if (
    !restoreAuthorizationSource.includes('requireEmailOtpRecoveryCodeUnsealAuthorization') ||
    !restoreAuthorizationSource.includes(
      "authorization.kind !== 'recovery_code_material_authorization_handle_v1'",
    ) ||
    !restoreAuthorizationSource.includes("authorization.purpose !== 'unseal'")
  ) {
    offenders.push(
      'shared restore authorization resolver does not parse Email OTP recovery-code unseal handles',
    );
  }

  expect(offenders, offenders.join('\n')).toEqual([]);
}

function activeEd25519SessionRecordsDoNotCarryRawClientBase(): void {
  const recordsSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/persistence/records.ts',
  );
  const routerAbSessionSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts',
  );
  const recordType = sourceRangeBetween(
    recordsSource,
    'export type ThresholdEd25519SessionRecord = {',
    'export type ThresholdSessionRecordByCurve = {',
  );
  const upsertArgs = sourceRangeBetween(
    recordsSource,
    'export function upsertStoredThresholdEd25519SessionRecord(args: {',
    '}): ThresholdEd25519SessionRecord | null {',
  );
  const parser = sourceRangeBetween(
    routerAbSessionSource,
    'export function parseRouterAbEd25519SigningWalletSessionFromRecord',
    'export function parseRouterAbEcdsaHssSigningWalletSessionFromRecord',
  );

  expect(recordType).not.toContain('xClientBaseB64u');
  expect(upsertArgs).not.toContain('xClientBaseB64u');
  expect(recordsSource).not.toContain('persistStoredThresholdEd25519SessionClientBase');
  expect(recordsSource).toContain('isRawOnlyEd25519ClientBaseInput');
  expect(recordsSource).toContain('if (isRawOnlyEd25519ClientBaseInput(args)) return null;');
  expect(countMarker(recordsSource, 'xClientBaseB64u')).toBe(1);
  expect(parser).not.toContain('raw_material_without_handle');
  expect(parser).not.toContain('xClientBaseB64u');
}

function rawClientBaseUsesStayInExplicitBoundaries(): void {
  const roots = ['packages/sdk-web/src', 'packages/shared-ts/src'] as const;
  const offenders: string[] = [];

  for (const root of roots) {
    for (const relativePath of listTypeScriptFiles(root)) {
      if (relativePath.endsWith('.typecheck.ts')) continue;
      const source = readRepoSource(relativePath);
      if (!source.includes('xClientBaseB64u')) continue;
      if (rawClientBaseAllowedActiveFiles.has(relativePath)) continue;
      offenders.push(`${relativePath} contains raw Ed25519 client-base material`);
    }
  }

  expect(offenders, offenders.join('\n')).toEqual([]);

  const sharedSealedSessionTypes = readRepoSource(
    'packages/shared-ts/src/utils/signingSessionSeal.ts',
  );
  const sealedSessionStore = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts',
  );
  const signerWorkerTypes = readRepoSource('packages/sdk-web/src/core/types/signer-worker.ts');
  const thresholdSignerConfig = sourceRangeBetween(
    signerWorkerTypes,
    'export interface ThresholdSignerConfig {',
    'export type RouterAbEd25519PresignPoolPolicyConfig',
  );
  const hssClientSignerWasm = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts',
  );
  const hssClientWorker = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/workerManager/workers/hss-client.worker.ts',
  );
  const hssWorkerTypes = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts',
  );

  expect(sharedSealedSessionTypes).not.toContain('xClientBaseB64u');
  expect(sealedSessionStore).not.toContain('...(xClientBaseB64u ? { xClientBaseB64u } : {})');
  expect(countMarker(sealedSessionStore, 'xClientBaseB64u')).toBe(2);
  expect(thresholdSignerConfig).not.toContain('xClientBaseB64u');
  expect(signerWorkerTypes).not.toContain(
    'WasmCreateThresholdEd25519RoleSeparatedNormalSigningClientShareRequest',
  );
  expect(hssClientSignerWasm).not.toContain(
    'createThresholdEd25519RoleSeparatedNormalSigningClientShareWasm',
  );
  expect(hssClientWorker).not.toContain(
    'case WorkerRequestType.CreateThresholdEd25519RoleSeparatedNormalSigningClientShare',
  );
  expect(hssWorkerTypes).not.toContain(
    'WorkerRequestType.CreateThresholdEd25519RoleSeparatedNormalSigningClientShare',
  );
  const workerMaterialHandle = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/threshold/ed25519/workerMaterialHandle.ts',
  );
  expect(countMarker(workerMaterialHandle, 'xClientBaseB64u')).toBe(1);
  expect(workerMaterialHandle).toContain('xClientBaseB64u?: never');
}

function clientOutputMaskUsesStayInHssSetupBoundaries(): void {
  const roots = ['packages/sdk-web/src', 'packages/shared-ts/src'] as const;
  const offenders: string[] = [];

  for (const root of roots) {
    for (const relativePath of listTypeScriptFiles(root)) {
      if (relativePath.endsWith('.typecheck.ts')) continue;
      const source = readRepoSource(relativePath);
      if (!source.includes('clientOutputMaskB64u')) continue;
      if (clientOutputMaskAllowedActiveFiles.has(relativePath)) continue;
      offenders.push(`${relativePath} contains transitional HSS output-mask transport`);
    }
  }

  expect(offenders, offenders.join('\n')).toEqual([]);

  const forbiddenNormalOperationRoots = [
    'packages/sdk-web/src/SeamsWeb/operations/auth',
    'packages/sdk-web/src/SeamsWeb/signingSurface',
    'packages/sdk-web/src/core/signingEngine/flows/signNear',
  ] as const;
  const normalOperationOffenders: string[] = [];
  for (const root of forbiddenNormalOperationRoots) {
    for (const relativePath of listTypeScriptFiles(root)) {
      const source = readRepoSource(relativePath);
      if (source.includes('clientOutputMaskB64u')) {
        normalOperationOffenders.push(`${relativePath} contains clientOutputMaskB64u`);
      }
    }
  }

  expect(normalOperationOffenders, normalOperationOffenders.join('\n')).toEqual([]);
}

function finalWorkerMaterialStoreCommandUsesMaskHandle(): void {
  const generatedCommands = readRepoSource(
    'packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts',
  );
  const generatedStoreRequest = sourceRangeBetween(
    generatedCommands,
    'export type Ed25519StoreWorkerMaterialFromHssOutputRequest =',
    'export type Ed25519RestoreWorkerMaterialRequestKind',
  );
  const sdkWorkerTypes = readRepoSource('packages/sdk-web/src/core/types/signer-worker.ts');
  const sdkStoreRequest = sourceRangeBetween(
    sdkWorkerTypes,
    'export type ThresholdEd25519StoreWorkerMaterialFromHssOutputRequest = {',
    'export type ThresholdEd25519StoreWorkerMaterialFromHssOutputResult',
  );
  const nearSignerWasm = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/chains/near/nearSignerWasm.ts',
  );
  const nearStoreWrapper = sourceRangeBetween(
    nearSignerWasm,
    'export async function storeThresholdEd25519WorkerMaterialFromHssOutputNearSignerWasm',
    'export async function prepareThresholdEd25519HssClientOutputMaskHandleNearSignerWasm',
  );

  expect(generatedCommands).not.toContain('clientOutputMaskB64u');
  expect(generatedCommands).toContain('clientOutputMaskHandle: string');
  expect(generatedCommands).toContain('"kind": "rust_owned_mask_handle_v1"');
  expect(generatedStoreRequest).toContain('clientOutputMask: Ed25519HssClientOutputMaskTransport');
  expect(generatedStoreRequest).not.toContain('clientOutputMaskB64u');

  expect(sdkStoreRequest).toContain(
    'clientOutputMask: ThresholdEd25519HssClientOutputMaskTransport',
  );
  expect(sdkStoreRequest).not.toContain('clientOutputMaskB64u');

  expect(nearStoreWrapper).toContain('clientOutputMaskHandle: string');
  expect(nearStoreWrapper).toContain("kind: 'rust_owned_mask_handle_v1'");
  expect(nearStoreWrapper).not.toContain('clientOutputMaskB64u');
}

function secretBearingMaterialAuthorizationRequestsStayInCredentialBoundaries(): void {
  const roots = ['packages/sdk-web/src/core', 'packages/sdk-web/src/SeamsWeb'] as const;
  const forbiddenFieldPatterns = [
    /\bprfFirstBytes\s*[:,]/,
    /\brecoveryCodeSecret32\s*[:,]/,
  ] as const;
  const offenders: string[] = [];

  for (const root of roots) {
    for (const relativePath of listTypeScriptFiles(root)) {
      if (relativePath.endsWith('.typecheck.ts')) continue;
      if (secretBearingMaterialAuthorizationAllowedFiles.has(relativePath)) continue;
      const source = readRepoSource(relativePath);
      for (const pattern of forbiddenFieldPatterns) {
        if (pattern.test(source)) {
          offenders.push(`${relativePath} contains a secret-bearing material authorization field`);
        }
      }
    }
  }

  expect(offenders, offenders.join('\n')).toEqual([]);
}

function activeEd25519RestorePersistenceDoesNotStoreCredentialSecrets(): void {
  const forbiddenMarkers = [
    'sealedPrf',
    'sealedPRF',
    'sealedPrfClaim',
    'sealedPrfFirst',
    'sealedUnsealAuthorization',
    'unsealAuthorizationRef',
    'unsealAuthorizationHandle',
    'materialUnsealAuthorizationHandle',
    'recoveryCodeSecret32',
    'recoveryCodeSecret32B64u',
    'recoveryCodeSealBytes',
    'recoveryCodeUnsealBytes',
    'derivedSealKey',
    'derivedUnsealKey',
    'sealKeyBytes',
    'unsealKeyBytes',
  ] as const;
  const offenders = collectForbiddenMarkerOffenders(
    ed25519RestorePersistenceBoundaryFiles,
    forbiddenMarkers,
  );

  expect(offenders, offenders.join('\n')).toEqual([]);
}

function preparedIssuerCallSitesStayBehindServerAuthorizedContexts(): void {
  const roots = ['packages/sdk-web/src/core/signingEngine', 'packages/sdk-web/src/SeamsWeb'] as const;
  const issuerMarkers = [
    'prepareThresholdEd25519PasskeyMaterialSealAuthorizationFromCredential',
    'prepareThresholdEd25519PasskeyMaterialUnsealAuthorizationFromCredential',
    'prepareRecoveryCodeSealAuthorizationForEmailOtp',
    'prepareRecoveryCodeUnsealAuthorizationForEmailOtp',
  ] as const;
  const offenders: string[] = [];

  for (const root of roots) {
    for (const relativePath of listTypeScriptFiles(root)) {
      if (relativePath.endsWith('.typecheck.ts')) continue;
      const source = readRepoSource(relativePath);
      const usesIssuer = issuerMarkers.some((marker) => source.includes(marker));
      if (usesIssuer && !materialAuthorizationIssuerCallSiteAllowedFiles.has(relativePath)) {
        offenders.push(`${relativePath} prepares material authorization outside approved contexts`);
      }
    }
  }

  const passkeySealBootstrapSource = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts',
  );
  const passkeySealCallSite = sourceRangeBetween(
    passkeySealBootstrapSource,
    'const materialBinding = {',
    'const completed =',
  );
  const emailOtpSealSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/provisioning.ts',
  );
  const restoreAuthorizationSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519MaterialRestoreAuthorization.ts',
  );

  for (const marker of [
    'thresholdSessionId',
    'signingGrantId',
    'signingRootId',
    'signingRootVersion',
    'expiresAtMs',
    'signingWorkerId',
    'prepareThresholdEd25519PasskeyMaterialSealAuthorizationFromCredential',
  ] as const) {
    if (!passkeySealCallSite.includes(marker)) {
      offenders.push(`passkey seal issuer call site missing ${marker}`);
    }
  }
  for (const marker of [
    'routeAuth.jwt',
    'buildEd25519SessionPolicy',
    'ROUTER_AB_ED25519_WALLET_SESSION_PATH_V2',
    'parseRouterAbEd25519NormalSigningState',
    'signingGrantId',
    'signingWorkerId',
    'prepareRecoveryCodeSealAuthorizationForEmailOtp',
  ] as const) {
    if (!emailOtpSealSource.includes(marker)) {
      offenders.push(`Email OTP seal issuer context missing ${marker}`);
    }
  }
  for (const marker of [
    'NearEd25519StepUpAuthorization',
    'restoreAvailableRecordForThresholdSession',
    'classifyRouterAbEd25519PersistedSigningRecord',
    "case 'warm_session':",
    'return unavailableRestoreAuthorization();',
    'prepareThresholdEd25519PasskeyMaterialUnsealAuthorizationFromCredential',
    'requireEmailOtpRecoveryCodeUnsealAuthorization',
  ] as const) {
    if (!restoreAuthorizationSource.includes(marker)) {
      offenders.push(`restore unseal issuer context missing ${marker}`);
    }
  }

  expect(offenders, offenders.join('\n')).toEqual([]);
}

function addSignerAndDeviceSyncUseSharedSealedWorkerMaterialSetup(): void {
  const offenders: string[] = [];
  const bootstrapSource = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts',
  );
  const registrationSource = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
  );
  const reconstructHelper = sourceRangeBetween(
    bootstrapSource,
    'export async function reconstructThresholdEd25519SigningMaterialFromWarmSession',
    'export async function hydrateThresholdWarmSessionFromRelay',
  );
  for (const marker of [
    'prepareThresholdEd25519PasskeyMaterialSealAuthorizationFromCredential',
    'runThresholdEd25519HssCeremonyWithMaterialHandle',
    'persistStoredThresholdEd25519SessionMaterialHandle',
    'sealedWorkerMaterialRef: signingMaterial.sealedWorkerMaterialRef',
    'sealedWorkerMaterialB64u: signingMaterial.sealedWorkerMaterialB64u',
    'materialFormatVersion: signingMaterial.materialFormatVersion',
    'materialKeyId: signingMaterial.materialKeyId',
    'materialCreatedAtMs: materialBinding.createdAtMs',
    'signerSlot: signingMaterial.signerSlot',
    'keyVersion: signingMaterial.keyVersion',
  ] as const) {
    if (!reconstructHelper.includes(marker)) {
      offenders.push(`shared Ed25519 reconstruction helper missing ${marker}`);
    }
  }

  for (const relativePath of [
    'packages/sdk-web/src/SeamsWeb/operations/recovery/emailRecovery.ts',
    'packages/sdk-web/src/SeamsWeb/operations/devices/linkDevice.ts',
    'packages/sdk-web/src/SeamsWeb/operations/recovery/syncAccount.ts',
  ] as const) {
    const source = readRepoSource(relativePath);
    for (const marker of [
      'hydrateThresholdWarmSessionFromRelay',
      'reconstructThresholdEd25519SigningMaterialFromWarmSession',
      'storeThresholdEd25519KeyMaterial',
      'thresholdKeyMaterialCreatedAtMs',
    ] as const) {
      if (!source.includes(marker)) {
        offenders.push(`${relativePath} missing ${marker}`);
      }
    }
  }

  for (const marker of [
    'reconstructThresholdEd25519SigningMaterialFromWarmSession',
    'credential: passkeyAuthority!.credential',
    'keyVersion: finalizedEd25519.keyVersion',
    'participantIdsHint: finalizedEd25519.participantIds',
  ] as const) {
    if (!registrationSource.includes(marker)) {
      offenders.push(`add-signer registration path missing ${marker}`);
    }
  }

  expect(offenders, offenders.join('\n')).toEqual([]);
}

function ed25519DurableRefreshTransportDoesNotUseHssMaterialKeyVersion(): void {
  const source = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts',
  );
  const helperSource = sourceRangeBetween(
    source,
    'async function refreshDurableThresholdEd25519SealedSessionWithWorkerMaterial',
    'export async function reconstructThresholdEd25519SigningMaterialFromWarmSession',
  );
  const transportSource = sourceRangeBetween(
    helperSource,
    'transport: {',
    '},',
  );

  expect(helperSource).toContain('hydrateSigningSession');
  expect(transportSource).toContain("curve: 'ed25519'");
  expect(transportSource).toContain('walletSessionJwt: args.walletSessionJwt');
  expect(transportSource).not.toContain('keyVersion');
}

function rawHssMaterialMarkersStayDeletedFromActiveSourceAndFixtures(): void {
  const forbiddenMarkers = [
    ['claim', 'PrfFirst', 'ByThreshold', 'SessionId'].join(''),
    ['router_ab', 'ed25519', 'hss_material_ref_v1'].join('_'),
    ['ed25519', 'hss', 'material:'].join('-'),
    ['ed25519', 'Hss', 'MaterialHandle'].join(''),
    ['ed25519', 'Hss', 'MaterialBindingDigest'].join(''),
  ] as const;
  const roots = ['packages/sdk-web/src', 'tests/unit', 'tests/e2e'] as const;
  const offenders: string[] = [];

  for (const root of roots) {
    for (const relativePath of listTypeScriptFiles(root)) {
      if (relativePath === 'tests/unit/refactor74LoginNoHss.guard.unit.test.ts') continue;
      const source = readRepoSource(relativePath);
      for (const marker of forbiddenMarkers) {
        if (source.includes(marker)) {
          offenders.push(`${relativePath} contains deleted marker ${marker}`);
        }
      }
    }
  }

  expect(offenders, offenders.join('\n')).toEqual([]);
}

function hssClientWorkerDoesNotOwnEd25519SigningMaterialHandles(): void {
  const hssClientWorker = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/workerManager/workers/hss-client.worker.ts',
  );
  const hssClientWasm = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts',
  );
  const hssWorkerTypes = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts',
  );
  const materialBindingSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssMaterialBinding.ts',
  );
  const forbiddenMarkers = [
    'StoredEd25519HssMaterial',
    'ed25519HssMaterialStore',
    'storeEd25519HssMaterial',
    'validateEd25519HssMaterialHandle',
    'validateEd25519WorkerMaterialHandle',
    'storeRouterAbEd25519HssMaterialFromClientOutput',
    'StoreThresholdEd25519HssMaterial',
    'StoreRouterAbEd25519HssMaterialFromClientOutput',
    'ValidateThresholdEd25519HssMaterial',
    'ThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandleSuccess',
    'buildRouterAbEd25519SigningMaterialPersistedHandle',
    'ed25519-hss-material:',
  ] as const;
  const offenders: string[] = [];

  for (const [label, source] of [
    ['hss-client.worker.ts', hssClientWorker],
    ['hssClientSignerWasm.ts', hssClientWasm],
    ['workerTypes.ts', hssWorkerTypes],
    ['hssMaterialBinding.ts', materialBindingSource],
  ] as const) {
    for (const marker of forbiddenMarkers) {
      if (source.includes(marker)) offenders.push(`${label} contains ${marker}`);
    }
  }

  expect(offenders, offenders.join('\n')).toEqual([]);
  expect(hssClientWorker).not.toContain('xClientBaseB64u');
}

function oldEd25519HssMaterialFieldNamesAreDeletedFromActiveCode(): void {
  const roots = ['packages/sdk-web/src', 'packages/shared-ts/src', 'tests/unit'] as const;
  const oldHandleMarker = ['ed25519', 'Hss', 'MaterialHandle'].join('');
  const oldDigestMarker = ['ed25519', 'Hss', 'MaterialBindingDigest'].join('');
  const offenders: string[] = [];

  for (const root of roots) {
    for (const relativePath of listTypeScriptFiles(root)) {
      if (relativePath === 'tests/unit/refactor74LoginNoHss.guard.unit.test.ts') continue;
      const source = readRepoSource(relativePath);
      if (source.includes(oldHandleMarker)) {
        offenders.push(`${relativePath} contains ${oldHandleMarker}`);
      }
      if (source.includes(oldDigestMarker)) {
        offenders.push(`${relativePath} contains ${oldDigestMarker}`);
      }
    }
  }

  expect(offenders, offenders.join('\n')).toEqual([]);
}

function refactor74TestGlobalsStayOutOfProductionSdk(): void {
  const forbiddenMarkers = [
    '__w3aWorkerOperationTrace',
    '__w3aClearRouterAbEd25519WorkerMaterialRuntimeValidationForTests',
    'clearRouterAbEd25519WorkerMaterialRuntimeValidationForTests',
  ] as const;
  const offenders: string[] = [];

  for (const relativePath of listTypeScriptFiles('packages/sdk-web/src')) {
    const source = readRepoSource(relativePath);
    for (const marker of forbiddenMarkers) {
      if (source.includes(marker)) {
        offenders.push(`${relativePath} contains production-reachable test global ${marker}`);
      }
    }
  }

  expect(offenders, offenders.join('\n')).toEqual([]);
}

test(
  'Refactor 74 exposes prepared issuer worker commands without direct material install commands',
  preparedIssuerWorkerSurfaceUsesPreparedCommandsOnly,
);

test(
  'Refactor 74 generated near-signer package exposes prepared issuer commands only',
  generatedNearSignerPackageExportsPreparedIssuerCommandsOnly,
);

test(
  'Refactor 74 prepared issuer result validators expose only public facts and opaque handles',
  preparedIssuerResultValidatorsExposeOnlyPublicFactsAndHandles,
);

test(
  'Refactor 74 store-from-HSS request keeps client verifier derivation inside the worker',
  storeFromHssRequestKeepsVerifierDerivedInsideWorker,
);

test(
  'Refactor 74 setup, restore, unlock, and signing flows do not call deleted material helpers',
  setupRestoreUnlockAndSigningDoNotCallDeletedMaterialHelpers,
);

test(
  'Refactor 74 Email OTP Ed25519 reconstruction names recovery-code secret material directly',
  emailOtpEd25519ReconstructionUsesRecoveryCodeSecretName,
);

test(
  'Refactor 74 Ed25519 material secret handling uses recovery-code domain naming',
  ed25519MaterialSecretErrorsUseRecoveryCodeDomain,
);

test(
  'Refactor 74 NEAR signing material resolver does not read PRF.first material',
  nearSigningMaterialResolverDoesNotReadPrfFirst,
);

test(
  'Refactor 74 final NEAR signing does not own worker material restore',
  finalNearSigningDoesNotOwnWorkerMaterialRestore,
);

test(
  'Refactor 74 seal authorization secrets live in credential boundaries',
  ed25519SealAuthorizationSecretsLiveInCredentialBoundaries,
);

test(
  'Refactor 74 NEAR signing flows use shared Ed25519 material restore readiness',
  nearSigningFlowsUseSharedEd25519MaterialRestoreReadiness,
);

test(
  'Refactor 74 active Ed25519 session records do not carry raw client-base material',
  activeEd25519SessionRecordsDoNotCarryRawClientBase,
);

test(
  'Refactor 74 raw client-base uses stay in explicit boundaries',
  rawClientBaseUsesStayInExplicitBoundaries,
);

test(
  'Refactor 74 client output masks stay in HSS setup boundaries',
  clientOutputMaskUsesStayInHssSetupBoundaries,
);

test(
  'Refactor 74 final worker-material store command uses a Rust-owned mask handle',
  finalWorkerMaterialStoreCommandUsesMaskHandle,
);

test(
  'Refactor 74 secret-bearing material authorization requests stay in credential boundaries',
  secretBearingMaterialAuthorizationRequestsStayInCredentialBoundaries,
);

test(
  'Refactor 74 active Ed25519 restore persistence does not store credential secrets',
  activeEd25519RestorePersistenceDoesNotStoreCredentialSecrets,
);

test(
  'Refactor 74 prepared issuer call sites stay behind server-authorized contexts',
  preparedIssuerCallSitesStayBehindServerAuthorizedContexts,
);

test(
  'Refactor 74 add-signer and device-sync setup use shared sealed worker-material persistence',
  addSignerAndDeviceSyncUseSharedSealedWorkerMaterialSetup,
);

test(
  'Refactor 74 Ed25519 durable refresh transport does not use HSS material keyVersion',
  ed25519DurableRefreshTransportDoesNotUseHssMaterialKeyVersion,
);

test(
  'Refactor 74 deleted raw HSS material markers stay out of active source and fixtures',
  rawHssMaterialMarkersStayDeletedFromActiveSourceAndFixtures,
);

test(
  'Refactor 74 HSS client worker does not own Ed25519 signing material handles',
  hssClientWorkerDoesNotOwnEd25519SigningMaterialHandles,
);

test(
  'Refactor 74 old Ed25519 HSS material field names are deleted from active code',
  oldEd25519HssMaterialFieldNamesAreDeletedFromActiveCode,
);

test(
  'Refactor 74 test-only globals stay out of production SDK modules',
  refactor74TestGlobalsStayOutOfProductionSdk,
);
