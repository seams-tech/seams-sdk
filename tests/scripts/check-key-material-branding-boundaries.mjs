#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function check(_label, callback) {
  callback();
}

function expect(received, message = '') {
  return {
    not: {
      toContain(expected) {
        assert.ok(
          !received.includes(expected),
          message || `Expected value not to contain \`${expected}\``,
        );
      },
    },
    toContain(expected) {
      assert.ok(
        received.includes(expected),
        message || `Expected value to contain \`${expected}\``,
      );
    },
    toEqual(expected) {
      assert.deepEqual(received, expected, message);
    },
    toBeGreaterThan(expected) {
      assert.ok(received > expected, message || `Expected ${received} > ${expected}`);
    },
    toBeGreaterThanOrEqual(expected) {
      assert.ok(received >= expected, message || `Expected ${received} >= ${expected}`);
    },
    not: {
      toContain(expected) {
        assert.ok(
          !received.includes(expected),
          message || `Expected value not to contain \`${expected}\``,
        );
      },
    },
  };
}

function readRepoSource(relativePath) {
  return fs.readFileSync(path.join(REPO_ROOT, relativePath), 'utf8');
}

function sourceBetween(source, start, end) {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  expect(startIndex, `missing source marker ${start}`).toBeGreaterThanOrEqual(0);
  expect(endIndex, `missing source marker ${end}`).toBeGreaterThan(startIndex);
  return source.slice(startIndex, endIndex);
}

function findBalancedCallBlocks(source, callee) {
  const blocks = [];
  let searchIndex = 0;
  const marker = `${callee}(`;
  while (searchIndex < source.length) {
    const start = source.indexOf(marker, searchIndex);
    if (start < 0) break;
    let depth = 0;
    let quote = null;
    for (let index = start + callee.length; index < source.length; index += 1) {
      const char = source[index];
      const previous = source[index - 1];
      if (quote) {
        if (char === quote && previous !== '\\') quote = null;
        continue;
      }
      if (char === '"' || char === "'" || char === '`') {
        quote = char;
        continue;
      }
      if (char === '(') {
        depth += 1;
        continue;
      }
      if (char !== ')') continue;
      depth -= 1;
      if (depth === 0) {
        blocks.push(source.slice(start, index + 1));
        searchIndex = index + 1;
        break;
      }
    }
    if (source.indexOf(marker, searchIndex) === start) break;
  }
  return blocks;
}

check('warm-session policy input requires explicit generated or shared grant lifecycle', () => {
    const source = readRepoSource(
      'packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts',
    );
    const inputType = sourceBetween(
      source,
      'export type ThresholdWarmSessionPolicyDraftInput =',
      'export type ThresholdWarmSessionRequestEnvelope =',
    );
    const draftType = sourceBetween(
      source,
      'export type ThresholdWarmSessionPolicyDraft =',
      'export type ThresholdWarmSessionPolicyDraftInput =',
    );
    const envelopeType = sourceBetween(
      source,
      'export type ThresholdWarmSessionRequestEnvelope =',
      'export type ThresholdWarmSessionContext =',
    );
    const builder = sourceBetween(
      source,
      'export function createThresholdWarmSessionPolicyDraft',
      'export function buildThresholdWarmSessionRequestEnvelope',
    );
    const envelopeBuilderStart = source.indexOf(
      'export function buildThresholdWarmSessionRequestEnvelope',
    );
    expect(envelopeBuilderStart).toBeGreaterThanOrEqual(0);
    const envelopeBuilder = source.slice(envelopeBuilderStart);

    expect(draftType).toContain('signingGrantId: string');
    expect(draftType).not.toContain('signingGrantId?: string');
    expect(inputType).toContain("kind: 'generated_signing_grant'");
    expect(inputType).not.toContain("kind?: 'generated_signing_grant'");
    expect(envelopeType).toContain('signingGrantId: string');
    expect(envelopeType).not.toContain('signingGrantId?: string');
    expect(builder).toContain('input: ThresholdWarmSessionPolicyDraftInput');
    expect(builder).not.toContain('input?: ThresholdWarmSessionPolicyDraftInput');
    expect(builder).toContain('const budget = policyBudget({');
    expect(source).toContain("case 'generated_signing_grant':");
    expect(source).toContain("case 'shared_signing_grant':");
    expect(envelopeBuilder).toContain('const signingGrantId =');
    expect(envelopeBuilder).toContain('!thresholdSessionId || !signingGrantId');
    expect(envelopeBuilder).toContain('authority: args.authority');
    expect(envelopeBuilder).toContain('signingGrantId,');
  });

check('all warm-session policy call sites choose a grant lifecycle branch', () => {
    const callSiteFiles = [
      'packages/sdk-web/src/SeamsWeb/operations/devices/linkDevice.ts',
      'packages/sdk-web/src/SeamsWeb/operations/recovery/syncAccount.ts',
      'packages/sdk-web/src/SeamsWeb/operations/recovery/emailRecovery.ts',
      'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
      'tests/unit/thresholdWarmSessionPolicyDraft.unit.test.ts',
    ];
    const offenders = callSiteFiles.flatMap((relativePath) =>
      findBalancedCallBlocks(
        readRepoSource(relativePath),
        'createThresholdWarmSessionPolicyDraft',
      )
        .filter((block) => !block.includes('kind:'))
        .map((block) => `${relativePath}: ${block.slice(0, 120)}`),
    );

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

check('key-version domains use branded parsers at high-risk boundaries', () => {
    const sdkBrands = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/keyMaterialBrands.ts',
    );
    const serverBrands = readRepoSource('packages/sdk-server-ts/src/core/keyMaterialBrands.ts');
    const serverSealOptions = readRepoSource(
      'packages/sdk-server-ts/src/threshold/session/signingSessionSeal/options.ts',
    );
    const serverThresholdSigning = readRepoSource(
      'packages/sdk-server-ts/src/core/routerAbSigning/RouterAbEcdsaBootstrapExportRuntime.ts',
    );
    const serverEcdsaPoolFill = readRepoSource(
      'packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaDerivationPoolFillHandlers.ts',
    );
    const serverEmailOtpSeal = readRepoSource(
      'packages/sdk-server-ts/src/core/authService/emailOtpSeal.ts',
    );
    const sdkSealTransportTypes = readRepoSource(
      'packages/sdk-web/src/core/types/secure-confirm-worker.ts',
    );
    const sdkConfigBuilder = readRepoSource(
      'packages/sdk-web/src/core/config/configBuilder.ts',
    );
    const sdkCapabilityReader = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/capabilityReader.ts',
    );
    const sdkCapabilityReaderCore = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/capabilityReaderCore.ts',
    );

    for (const source of [sdkBrands, serverBrands]) {
      expect(source).toContain("EcdsaDerivationKeyVersion");
      expect(source).toContain("SigningSessionSealKeyVersion");
      expect(source).toContain("parseEcdsaDerivationKeyVersion");
      expect(source).toContain("parseSigningSessionSealKeyVersion");
    }
    expect(serverSealOptions).toContain('parseSigningSessionSealKeyVersion(input.keyVersion)');
    expect(serverSealOptions).toContain('signingSessionSealKeyVersion: SigningSessionSealKeyVersion');
    expect(serverEmailOtpSeal).toContain(
      'parseSigningSessionSealKeyVersion(input.keyVersionRaw)',
    );
    expect(serverEmailOtpSeal).toContain('formatSigningSessionSealKeyVersionForWire');
    expect(serverThresholdSigning).toContain(
      "const THRESHOLD_ECDSA_DERIVATION_KEY_VERSION_V1 = parseEcdsaDerivationKeyVersion('v1')",
    );
    expect(serverThresholdSigning).toContain('parseEcdsaDerivationKeyVersionOrDefault');
    expect(serverThresholdSigning).toContain('ecdsaDerivationKeyVersionWire');
    expect(serverEcdsaPoolFill).toContain('parseEcdsaDerivationKeyVersion');
    expect(serverEcdsaPoolFill).toContain('formatEcdsaDerivationKeyVersionForWire');

    const sealTransportCommon = sourceBetween(
      sdkSealTransportTypes,
      'type WarmSessionSealTransportCommon =',
      'export interface UiConfirmManagerConfig',
    );
    expect(sealTransportCommon).toContain(
      'signingSessionSealKeyVersion?: SigningSessionSealKeyVersion',
    );
    expect(sealTransportCommon).not.toContain('keyVersion?: string');
    expect(sdkConfigBuilder).toContain('parseSigningSessionSealKeyVersion(keyVersion)');
    expect(sdkConfigBuilder).toContain('signingSessionSealKeyVersion:');
    expect(sdkCapabilityReader).toContain(
      'signingSessionSealKeyVersion: SigningSessionSealKeyVersion',
    );
    expect(sdkCapabilityReaderCore).toContain(
      'signingSessionSealKeyVersion: SigningSessionSealKeyVersion',
    );
  });

check('ECDSA lifecycle identity helpers stay branch-specific', () => {
    const planSource = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts',
    );
    const readinessSource = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/useCases/provisionEcdsaSession.ts',
    );
    const evmReadinessSource = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaReadiness.ts',
    );

    expect(planSource).not.toContain('getEcdsaSessionProvisionIdentity');
    expect(planSource).toContain('getEcdsaReconnectSessionIdentity');
    expect(planSource).toContain('getEcdsaFreshProvisionSessionIdentity');
    expect(planSource).toContain('getEcdsaProvisionPlanLaneIdentity');
    expect(readinessSource).not.toContain('recordMatchesPlannedIdentity');
    expect(readinessSource).not.toContain('provisionPlanRequiresExistingRecordIdentity');
    expect(readinessSource).not.toContain('getEcdsaSessionProvisionIdentity');
    expect(readinessSource).toContain('function recordMatchesReconnectIdentity');
    expect(readinessSource).toContain('plan: EcdsaReconnectProvisionPlan');
    expect(evmReadinessSource).not.toContain('getEcdsaSessionProvisionIdentity');
    expect(evmReadinessSource).toContain('getEcdsaProvisionPlanLaneIdentity');
  });

check('second-tier material brands protect ECDSA restore and signing boundaries', () => {
    const sdkBrands = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/keyMaterialBrands.ts',
    );
    const serverBrands = readRepoSource('packages/sdk-server-ts/src/core/keyMaterialBrands.ts');
    const ecdsaPoolFill = readRepoSource(
      'packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaDerivationPoolFillHandlers.ts',
    );
    const ecdsaClientPresignPool = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/routerAb/ecdsaDerivation/presignaturePool.ts',
    );
    const serverSealOptions = readRepoSource(
      'packages/sdk-server-ts/src/threshold/session/signingSessionSeal/options.ts',
    );
    const serverEmailOtpSeal = readRepoSource(
      'packages/sdk-server-ts/src/core/authService/emailOtpSeal.ts',
    );

    for (const source of [sdkBrands, serverBrands]) {
      expect(source).toContain('EcdsaClientVerifyingShareB64u');
      expect(source).toContain('EcdsaRelayerKeyId');
      expect(source).toContain('EcdsaThresholdKeyId');
      expect(source).toContain('EcdsaKeyHandle');
      expect(source).toContain('SigningSessionSealShamirPrimeB64u');
      expect(source).toContain('parseSigningSessionSealShamirPrimeB64u');
    }
    expect(sdkBrands).toContain('EcdsaClientAdditiveShareHandle');

    expect(ecdsaPoolFill).toContain('ecdsaThresholdKeyId: EcdsaThresholdKeyId');
    expect(ecdsaPoolFill).toContain('keyHandle: EcdsaKeyHandle');
    expect(ecdsaPoolFill).toContain('relayerKeyId: EcdsaRelayerKeyId');
    expect(ecdsaPoolFill).toContain(
      'clientVerifyingShareB64u: EcdsaClientVerifyingShareB64u',
    );
    expect(ecdsaClientPresignPool).toContain('keyHandle?: EcdsaKeyHandle');
    expect(ecdsaClientPresignPool).toContain('ecdsaThresholdKeyId: EcdsaThresholdKeyId');
    expect(ecdsaClientPresignPool).toContain(
      'clientVerifyingShareB64u: EcdsaClientVerifyingShareB64u',
    );
    expect(serverSealOptions).toContain('parseSigningSessionSealShamirPrimeB64u');
    expect(serverSealOptions).toContain(
      'shamirPrimeB64u: SigningSessionSealShamirPrimeB64u',
    );
    expect(serverEmailOtpSeal).toContain('parseSigningSessionSealShamirPrimeB64u');
    expect(serverEmailOtpSeal).toContain('formatSigningSessionSealShamirPrimeB64uForWire');
  });

check('WebAuthn RP ids cannot be confused with NEAR Ed25519 signing-key ids', () => {
    const domainIds = readRepoSource('packages/shared-ts/src/utils/domainIds.ts');
    const walletCapabilityBindings = readRepoSource(
      'packages/shared-ts/src/utils/walletCapabilityBindings.ts',
    );
    const registrationIntent = readRepoSource('packages/shared-ts/src/utils/registrationIntent.ts');
    const serverTypes = readRepoSource('packages/sdk-server-ts/src/core/types.ts');
    const serverAuthService = readRepoSource(
      'packages/sdk-server-ts/src/core/authService/AuthService.ts',
    );
    const serverWebAuthnAuthority = readRepoSource(
      'packages/sdk-server-ts/src/core/authService/webauthnAuthority.ts',
    );
    const serverWebAuthnOidcHelpers = readRepoSource(
      'packages/sdk-server-ts/src/core/authService/webauthnOidcHelpers.ts',
    );
    const walletRegistrationRoutes = readRepoSource(
      'packages/sdk-server-ts/src/router/walletRegistrationRoutes.ts',
    );
    const thresholdSigning = readRepoSource(
      'packages/sdk-server-ts/src/core/routerAbSigning/RouterAbEcdsaBootstrapExportRuntime.ts',
    );
    const serverTypecheck = readRepoSource(
      'packages/sdk-server-ts/src/core/keyMaterialBrands.typecheck.ts',
    );
    const sdkTypecheck = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/keyMaterialBrands.typecheck.ts',
    );

    expect(domainIds).toContain("WebAuthnRpId = DomainId<'WebAuthnRpId'>");
    expect(domainIds).toContain('parseWebAuthnRpId');
    expect(walletCapabilityBindings).toContain('export type RpId = WebAuthnRpId');
    expect(registrationIntent).toContain('export type NearEd25519SigningKeyId');
    expect(registrationIntent).toContain('parseNearEd25519SigningKeyId');
    expect(registrationIntent).toContain('formatNearEd25519SigningKeyIdForWire');
    expect(registrationIntent).toContain('rpId: WebAuthnRpId;');
    expect(registrationIntent).toContain('rpId?: never;');
    const nearEd25519Parser = sourceBetween(
      registrationIntent,
      'export function parseNearEd25519SigningKeyId(value: unknown): NearEd25519SigningKeyId',
      'export function formatNearEd25519SigningKeyIdForWire',
    );
    expect(nearEd25519Parser).toContain("typeof value !== 'string'");
    expect(nearEd25519Parser).not.toContain('String(value ??');
    const generatedKeyDigestInput = sourceBetween(
      registrationIntent,
      'export type GeneratedImplicitNearEd25519SigningKeyDigestInput =',
      'export async function computeGeneratedImplicitNearEd25519SigningKeyId',
    );
    expect(generatedKeyDigestInput).toContain('authorityScope: RegistrationEd25519AuthorityScope;');
    const registrationKeyDigestInput = sourceBetween(
      registrationIntent,
      'export async function computeRegistrationNearEd25519SigningKeyId(input:',
      'export function implicitNearAccountProvisioning',
    );
    expect(registrationKeyDigestInput).toContain(
      'authorityScope: RegistrationEd25519AuthorityScope;',
    );

    expect(serverTypes).toContain('rpId: WebAuthnRpId');

    expect(serverWebAuthnAuthority).toContain('requireWebAuthnRpId');
    expect(serverWebAuthnOidcHelpers).toContain(
      'function isHostWithinRpId(host: string, rpId: WebAuthnRpId)',
    );
    expect(serverWebAuthnOidcHelpers).not.toContain(
      'function isHostWithinRpId(host: string, rpId: string)',
    );
    const registrationVerificationHelper = sourceBetween(
      serverAuthService,
      'private async verifyRegistrationCredentialForIntent(input:',
      'async verifyWebAuthnAuthenticationLite(input:',
    );
    expect(registrationVerificationHelper).toContain('rpId: WebAuthnRpId;');
    expect(registrationVerificationHelper).not.toContain('rpId: string;');
    expect(serverAuthService).not.toContain('private async verifyRegistrationAuthorityForIntent');
    const liteVerificationHelper = sourceBetween(
      serverAuthService,
      'async verifyWebAuthnAuthenticationLite(input:',
      'async listWebAuthnAuthenticatorsForUser',
    );
    expect(liteVerificationHelper).toContain('rpId: WebAuthnRpId;');
    expect(liteVerificationHelper).not.toContain('rpId: string;');
    expect(walletRegistrationRoutes).toContain('requireWebAuthnRpId(');
    expect(walletRegistrationRoutes).toContain('rpId: parsedRpId.rpId,');
    expect(serverAuthService).not.toContain('input.intent.rpId');
    expect(serverAuthService).not.toContain('rpId: registrationAccountScope.value.walletKeyId');
    expect(serverAuthService).not.toContain('wallet_key_id: registrationAccountScope.walletKeyId');
    expect(thresholdSigning).not.toContain('registrationAccountScope.value.walletKeyId');
    expect(thresholdSigning).not.toContain('rpId: registrationAccountScope.value.walletKeyId');
    for (const source of [serverTypecheck, sdkTypecheck]) {
      expect(source).toContain('acceptsWebAuthnRpId(nearEd25519SigningKeyId)');
      expect(source).toContain('acceptsNearEd25519SigningKeyId(webAuthnRpId)');
    }
  });

check('valid signing-session seal key ids use explicit domain names in active defaults', () => {
    const localD1Worker = readRepoSource(
      'packages/console-server-ts/src/router/cloudflare/d1LocalDevWorker.ts',
    );
    const stagingD1Worker = readRepoSource(
      'packages/console-server-ts/src/router/cloudflare/d1RouterApiStagingWorker.ts',
    );
    const d1AuthConfig = readRepoSource(
      'packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthConfig.ts',
    );
    const serverSealOptions = readRepoSource(
      'packages/sdk-server-ts/src/threshold/session/signingSessionSeal/options.ts',
    );
    const generateKeys = readRepoSource(
      'apps/web-server/scripts/generate-signing-session-seal-keys.mjs',
    );
    const currentSealFixtureFiles = [
      'tests/unit/walletIframe.signerModeConfigPropagation.unit.test.ts',
      'tests/unit/warmSessionStore.lifecycle.unit.test.ts',
      'tests/unit/sealedRefresh.parity.unit.test.ts',
      'tests/unit/signingSessionSeal.idempotencyRecords.unit.test.ts',
      'tests/unit/sealedSessionStore.unit.test.ts',
      'tests/unit/warmSessionReadModel.unit.test.ts',
      'tests/unit/emailOtpWalletSessionCoordinator.unit.test.ts',
      'tests/unit/sealedRecovery.methodAdapters.unit.test.ts',
      'tests/unit/signingSessionSeal.shared.unit.test.ts',
      'tests/unit/signingSessionRestoreCoordinator.unit.test.ts',
    ];

    expect(generateKeys).toContain('signing-session-seal-kek-${today}-r1');
    expect(localD1Worker).toContain(
      'normalizeLocalString(env.SIGNING_SESSION_SEAL_KEY_VERSION)',
    );
    expect(stagingD1Worker).toContain("readEnvString(env, 'SIGNING_SESSION_SEAL_KEY_VERSION')");
    expect(localD1Worker).toContain('keyVersion: seal.keyVersion');
    expect(stagingD1Worker).toContain('keyVersion: seal.keyVersion');
    expect(serverSealOptions).toContain('parseSigningSessionSealKeyVersion(input.keyVersion)');
    expect(d1AuthConfig).toContain('parseSigningSessionSealKeyVersion(keyVersionRaw)');
    expect(d1AuthConfig).toContain('formatSigningSessionSealKeyVersionForWire');
    expect(localD1Worker).not.toContain('kek-s-2026-02');
    expect(stagingD1Worker).not.toContain('kek-s-2026-02');
    expect(generateKeys).not.toContain('kek-s-${today}');
    for (const relativePath of currentSealFixtureFiles) {
      const source = readRepoSource(relativePath);
      expect(source, relativePath).not.toContain('kek-s-2026-02');
      expect(source, relativePath).not.toContain("keyVersion: 'seal-v1'");
      expect(source, relativePath).not.toContain('keyVersion: "seal-v1"');
    }
  });

check('EVM-family signing key slot identity cannot fall back to generic wallet key strings', () => {
    const sharedEvmFamilyKey = readRepoSource(
      'packages/shared-ts/src/signing-lanes/evmFamilySigningKeySlotId.ts',
    );
    const ecdsaIdentity = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts',
    );
    const sessionRecords = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/persistence/records.ts',
    );
    const provisionUseCase = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/useCases/provisionEcdsa.ts',
    );
    const sessionPolicy = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.ts',
    );
    const platformPorts = readRepoSource('packages/sdk-web/src/core/platform/ports.ts');
    const emailOtpWorker = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
    );
    const thresholdValidation = readRepoSource(
      'packages/sdk-server-ts/src/core/ThresholdService/validation.ts',
    );
    const ecdsaPoolFillHandlers = readRepoSource(
      'packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaDerivationPoolFillHandlers.ts',
    );
    const authService = readRepoSource(
      'packages/sdk-server-ts/src/core/authService/emailRecoveryAuthOperations.ts',
    );
    const d1RegistrationRecords = readRepoSource(
      'packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords.ts',
    );

    expect(sharedEvmFamilyKey).toContain('export type EvmFamilySigningKeySlotId =');
    expect(sharedEvmFamilyKey).toContain(
      'EVM-family signing key slot id must be wallet-key:evm-family:<walletId>:<signingRootId>:<signingRootVersion>',
    );
    expect(sharedEvmFamilyKey).toContain("typeof value !== 'string'");
    expect(sharedEvmFamilyKey).toContain('deriveEvmFamilySigningKeySlotId');

    expect(ecdsaIdentity).toContain('type EvmFamilySigningKeySlotId');
    expect(ecdsaIdentity).toContain('requireEvmFamilySigningKeySlotId');
    expect(ecdsaIdentity).not.toContain('FromSigningRootFacts');
    expect(ecdsaIdentity).not.toContain('walletKeyPart(');

    expect(sessionRecords).toContain('parseEvmFamilySigningKeySlotId(');
    expect(sessionRecords).toContain('obj.evmFamilySigningKeySlotId');
    expect(sessionRecords).not.toContain('parseWalletKeyIdOrNull(obj.walletKeyId)');
    expect(provisionUseCase).toContain('evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId');
    expect(sessionPolicy).toContain('evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId');
    expect(sessionPolicy).toContain(
      'evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(',
    );
    expect(platformPorts).toContain('evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId');
    expect(platformPorts).not.toContain('evmFamilySigningKeySlotId: WalletKeyId');

    expect(emailOtpWorker).toContain('function readEvmFamilySigningKeySlotId');
    expect(emailOtpWorker).not.toContain('function readWalletKeyId(');
    expect(emailOtpWorker).not.toContain('readString(payload.walletKeyId');
    expect(emailOtpWorker).not.toContain('readString(args.walletKeyId');
    expect(emailOtpWorker).not.toContain('readString(obj.walletKeyId');
    expect(thresholdValidation).toContain('parseEvmFamilySigningKeySlotIdOrNull');
    expect(thresholdValidation).not.toContain('parseWalletKeyIdOrNull');
    expect(ecdsaPoolFillHandlers).toContain('parseEvmFamilySigningKeySlotString');
    expect(ecdsaPoolFillHandlers).not.toContain(
      'toOptionalTrimmedString(claims?.walletKeyId)',
    );

    expect(authService).toContain('deriveEvmFamilySigningKeySlotId');
    expect(authService).not.toContain('function encodeEcdsaWalletKeyIdPart');
    expect(d1RegistrationRecords).toContain('export { deriveEvmFamilySigningKeySlotId }');
    expect(d1RegistrationRecords).not.toContain('encodeURIComponent(walletId)');
  });
console.log('[check-key-material-branding-boundaries] passed');
