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

check('key-version domains use branded parsers at high-risk boundaries', () => {
  const sdkBrands = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/keyMaterialBrands.ts',
  );
  const serverBrands = readRepoSource('packages/sdk-server-ts/src/core/keyMaterialBrands.ts');
  const serverSealOptions = readRepoSource(
    'packages/sdk-server-ts/src/threshold/session/signingSessionSeal/options.ts',
  );
  const serverEmailOtpSeal = readRepoSource(
    'packages/sdk-server-ts/src/core/authService/emailOtpSeal.ts',
  );
  const sdkSealTransportTypes = readRepoSource(
    'packages/sdk-web/src/core/types/secure-confirm-worker.ts',
  );

  for (const source of [sdkBrands, serverBrands]) {
    expect(source).toContain('EcdsaDerivationKeyVersion');
    expect(source).toContain('SigningSessionSealKeyVersion');
    expect(source).toContain('parseEcdsaDerivationKeyVersion');
    expect(source).toContain('parseSigningSessionSealKeyVersion');
  }
  expect(serverSealOptions).toContain('parseSigningSessionSealKeyVersion(parsed)');
  expect(serverSealOptions).toContain(
    'function parseKeyVersion(value: unknown, label: string): SigningSessionSealKeyVersion',
  );
  expect(serverEmailOtpSeal).toContain('parseSigningSessionSealRootConfig');
  expect(serverEmailOtpSeal).toContain('currentKeyVersion: string');
  const sealTransportCommon = sourceBetween(
    sdkSealTransportTypes,
    'type WarmSessionSealTransportCommon =',
    'export interface UiConfirmManagerConfig',
  );
  expect(sealTransportCommon).toContain(
    'signingSessionSealKeyVersion?: SigningSessionSealKeyVersion',
  );
  expect(sealTransportCommon).not.toContain('keyVersion?: string');
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
    'packages/sdk-server-ts/src/router/domains/walletRegistration/walletRegistrationRoutes.ts',
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
  for (const source of [serverTypecheck, sdkTypecheck]) {
    expect(source).toContain('acceptsWebAuthnRpId(nearEd25519SigningKeyId)');
    expect(source).toContain('acceptsNearEd25519SigningKeyId(webAuthnRpId)');
  }
});

check('EVM-family signing key slot identity cannot fall back to generic wallet key strings', () => {
  const sharedEvmFamilyKey = readRepoSource(
    'packages/shared-ts/src/signing-lanes/evmFamilySigningKeySlotId.ts',
  );
  const ecdsaProvisioner = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts',
  );
  const emailOtpWorker = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
  );
  const thresholdValidation = readRepoSource(
    'packages/sdk-server-ts/src/core/ThresholdService/validation.ts',
  );
  const d1RegistrationRecords = readRepoSource(
    'packages/sdk-server-ts/src/router/cloudflare/d1/registration/d1RegistrationCeremonyRecords.ts',
  );

  expect(sharedEvmFamilyKey).toContain('export type EvmFamilySigningKeySlotId =');
  expect(sharedEvmFamilyKey).toContain(
    'EVM-family signing key slot id must be wallet-key:evm-family:<walletId>:<signingRootId>:<signingRootVersion>',
  );
  expect(sharedEvmFamilyKey).toContain("typeof value !== 'string'");
  expect(sharedEvmFamilyKey).toContain('deriveEvmFamilySigningKeySlotId');

  expect(ecdsaProvisioner).toContain('walletKey: EvmFamilyEcdsaWalletKey');
  expect(ecdsaProvisioner).not.toContain('walletKeyId');

  expect(emailOtpWorker).toContain('function readEvmFamilySigningKeySlotId');
  expect(emailOtpWorker).not.toContain('function readWalletKeyId(');
  expect(emailOtpWorker).not.toContain('readString(payload.walletKeyId');
  expect(emailOtpWorker).not.toContain('readString(args.walletKeyId');
  expect(emailOtpWorker).not.toContain('readString(obj.walletKeyId');
  expect(thresholdValidation).toContain('parseEvmFamilySigningKeySlotIdOrNull');
  expect(thresholdValidation).not.toContain('parseWalletKeyIdOrNull');

  expect(d1RegistrationRecords).toContain('export { deriveEvmFamilySigningKeySlotId }');
  expect(d1RegistrationRecords).not.toContain('encodeURIComponent(walletId)');
});
console.log('[check-key-material-branding-boundaries] passed');
