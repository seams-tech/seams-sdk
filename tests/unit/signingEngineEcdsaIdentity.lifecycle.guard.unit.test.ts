import { expect, test } from '@playwright/test';
import {
  repoRoot,
  readRepoFile,
  listTsFiles,
  listSourceFiles,
  findCallObjects,
  findLoggerCalls,
  lineNumberForIndex,
  findBalancedBlock,
  findTypeDeclaration,
  findObjectBlockAfter,
  findChainedMethodCallObjects,
  findMethodDeclarationAndBody,
  expectRequiredFields,
  expectDeclaredFields,
  expectAnyDeclaredField,
  expectNoField,
  expectNoNearAccountId
} from './helpers/signingEngineEcdsaIdentityGuard';

test.describe('signing engine ECDSA lifecycle identity guards', () => {
  test('new optional lifecycle fields stay behind narrow current boundaries', () => {
    const searchRoots = [
      'client/src/core/signingEngine/session/warmCapabilities',
      'client/src/core/signingEngine/session/passkey',
      'client/src/core/signingEngine/session/emailOtp',
      'client/src/core/signingEngine/session/budget',
      'client/src/core/signingEngine/flows/signEvmFamily',
    ];
    const optionalLifecycleFieldAllowlist = new Set([
      'client/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts',
    ]);
    const offenders: string[] = [];
    const pattern =
      /sessionId\?: string|walletSigningSessionId\?: string|thresholdSessionId\?: string|thresholdSessionAuth\?:(?!\s*never\b)|webauthnAuthentication\?:(?!\s*never\b)|clientRootShare32B64u\?:(?!\s*never\b)|warmRecord\?:|warmKeyRef\?:|reauthRecord\?:|emailOtpAuthContext\?:(?!\s*never\b)/;
    for (const root of searchRoots) {
      for (const relativePath of listTsFiles(root)) {
        const source = readRepoFile(relativePath);
        if (!pattern.test(source)) continue;
        if (optionalLifecycleFieldAllowlist.has(relativePath)) continue;
        offenders.push(relativePath);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('old warm ECDSA lifecycle symbols stay deleted', () => {
    const offenders: string[] = [];
    const pattern =
      /\bEnsureWarmEcdsaCapabilityReadyArgs\b|\bResolveWarmEcdsaBootstrapRequestArgs\b|\bWarmEcdsaBootstrapRequest\b|\bProvisionWarmEcdsaCapabilityArgs\b|\bbuildProvisionWarmEcdsaCapabilityArgs\b/;
    for (const relativePath of listTsFiles('client/src/core/signingEngine')) {
      const source = readRepoFile(relativePath);
      if (!pattern.test(source)) continue;
      offenders.push(relativePath);
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('ECDSA provision plans only come from builder modules', () => {
    const provisionPlanConstructionPatterns = [
      /return\s*{\s*kind:\s*'passkey_ecdsa_session_provision'/,
      /return\s*{\s*kind:\s*'threshold_session_auth_ecdsa_reconnect'/,
      /return\s*{\s*kind:\s*'cookie_ecdsa_reconnect'/,
      /return\s*{\s*kind:\s*'email_otp_ecdsa_session_provision'/,
    ];
    const builderCalls = [
      'buildPasskeyEcdsaSessionProvision',
      'buildThresholdSessionAuthEcdsaReconnect',
      'buildEmailOtpEcdsaSessionProvision',
      'buildEcdsaSessionProvisionPlan',
    ];
    const offenders: string[] = [];
    for (const relativePath of listTsFiles('client/src/core/signingEngine')) {
      if (
        relativePath ===
          'client/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts' ||
        relativePath.endsWith('.typecheck.ts')
      ) {
        continue;
      }
      const source = readRepoFile(relativePath);
      for (const pattern of provisionPlanConstructionPatterns) {
        const match = source.match(pattern);
        if (match?.[0]) {
          offenders.push(`${relativePath} directly constructs ${match[0]}`);
        }
      }
      if (source.includes('as EcdsaSessionProvisionPlan')) {
        offenders.push(`${relativePath} casts to EcdsaSessionProvisionPlan`);
      }
      for (const callName of builderCalls) {
        for (const callObject of findCallObjects(source, callName)) {
          if (callObject.includes('...')) {
            offenders.push(`${relativePath} uses object spread in ${callName}()`);
          }
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('server budget-status routes stay parser-owned', () => {
    const routeFiles = [
      'server/src/router/express/routes/sessions.ts',
      'server/src/router/cloudflare/routes/sessions.ts',
    ];
    const offenders: string[] = [];
    for (const relativePath of routeFiles) {
      const source = readRepoFile(relativePath);
      for (const forbidden of [
        'parseThresholdEcdsaSessionClaims',
        'parseThresholdEd25519SessionClaims',
        'body.walletSigningSessionId',
        'body.thresholdSessionId',
      ]) {
        if (source.includes(forbidden)) {
          offenders.push(
            `${relativePath} contains forbidden route-local parsing token ${forbidden}`,
          );
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('raw ECDSA identity parsing stays out of guarded internals', () => {
    const searchRoots = [
      'client/src/core/signingEngine/flows/signEvmFamily',
      'client/src/core/signingEngine/session/passkey',
      'client/src/core/signingEngine/session/warmCapabilities',
    ];
    const rawIdentityParsingAllowlist = new Set([
      'client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    ]);
    const offenders: string[] = [];
    const patterns = [
      {
        name: 'object field identity parsing',
        pattern:
          /(thresholdSessionId|walletSigningSessionId)\s*:\s*String\((?:[^)\n]*)(?:thresholdSessionId|walletSigningSessionId)(?:[^)\n]*)\)\.trim\(/g,
      },
      {
        name: 'raw identity comparison',
        pattern:
          /String\([^;\n]*(?:thresholdSessionId|walletSigningSessionId)[^;\n]*\)\.trim\(\)\s*(?:={2,3}|!={1,2})\s*String\([^;\n]*(?:thresholdSessionId|walletSigningSessionId)[^;\n]*\)\.trim\(\)/g,
      },
      {
        name: 'paired local identity parsing',
        pattern:
          /\b(?:const|let)\s+\w*(?:ThresholdSessionId|SessionId)\s*=\s*String\([^;\n]*thresholdSessionId[^;\n]*\)\.trim\(\)[\s\S]{0,240}\b(?:const|let)\s+\w*WalletSigningSessionId\s*=\s*String\([^;\n]*walletSigningSessionId[^;\n]*\)\.trim\(\)/g,
      },
      {
        name: 'paired local identity parsing',
        pattern:
          /\b(?:const|let)\s+\w*WalletSigningSessionId\s*=\s*String\([^;\n]*walletSigningSessionId[^;\n]*\)\.trim\(\)[\s\S]{0,240}\b(?:const|let)\s+\w*(?:ThresholdSessionId|SessionId)\s*=\s*String\([^;\n]*thresholdSessionId[^;\n]*\)\.trim\(\)/g,
      },
    ];
    for (const root of searchRoots) {
      for (const relativePath of listTsFiles(root)) {
        const source = readRepoFile(relativePath);
        for (const { name, pattern } of patterns) {
          if (!pattern.test(source)) continue;
          pattern.lastIndex = 0;
          if (rawIdentityParsingAllowlist.has(relativePath)) continue;
          offenders.push(`${relativePath} (${name})`);
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('wallet unlock keeps raw ECDSA profile and inventory parsing at boundaries', () => {
    const loginSource = readRepoFile('client/src/core/SeamsPasskey/login.ts');
    const offenders: string[] = [];
    for (const forbidden of [
      'metadata.sharedEvmFamilyKey',
      'metadata.keyHandle',
      'metadata.ecdsaThresholdKeyId',
      'metadata.signingRootId',
      'metadata.signingRootVersion',
      'metadata.participantIds',
      'metadata.thresholdOwnerAddress',
      'metadata.ownerAddress',
      'const records = inventory.records',
      '/threshold-ecdsa/key-identities',
    ]) {
      if (loginSource.includes(forbidden)) {
        offenders.push(`login unlock path contains raw boundary token ${forbidden}`);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('near account to ECDSA subject derivations stay out of ECDSA signing paths', () => {
    const guardedRoots = [
      'client/src/core/signingEngine/flows/signEvmFamily',
      'client/src/core/signingEngine/session/passkey',
      'client/src/core/signingEngine/session/warmCapabilities',
      'client/src/core/signingEngine/threshold/ecdsa',
      'client/src/core/rpcClients/evm',
    ];
    const accountToSubjectPattern =
      /toWalletId\(\s*(?:(?:args|input|request)\.)?(?:nearAccountId|accountId)\s*\)/;
    const offenders: string[] = [];
    for (const relativePath of guardedRoots.flatMap((root) => listTsFiles(root))) {
      if (relativePath.endsWith('.typecheck.ts')) continue;
      const source = readRepoFile(relativePath);
      const lines = source.split(/\r?\n/);
      lines.forEach((line, index) => {
        if (accountToSubjectPattern.test(line)) {
          offenders.push(`${relativePath}:${index + 1}`);
        }
      });
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('nearAccountId residue stays out of ECDSA-only paths', () => {
    const forbiddenPaths = [
      'client/src/core/SeamsPasskey/evm',
      'client/src/core/SeamsPasskey/tempo',
      'client/src/core/signingEngine/flows/signEvmFamily',
      'client/src/core/signingEngine/nonce',
      'client/src/core/signingEngine/session/budget',
      'client/src/core/signingEngine/chains/evm',
      'client/src/core/signingEngine/threshold/ecdsa',
      'client/src/core/rpcClients/evm',
      'server/src/core/ThresholdService/ethSignerWasm.ts',
    ];
    const offenders: string[] = [];
    for (const relativePath of forbiddenPaths.flatMap((entry) => listSourceFiles(entry))) {
      const source = readRepoFile(relativePath);
      if (/\bnearAccountId\b/.test(source)) {
        offenders.push(relativePath);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('threshold/server logs do not emit raw secret material', () => {
    const roots = [
      'server/src/core/ThresholdService',
      'server/src/threshold/session/signingSessionSeal',
    ];
    const forbiddenFields = [
      'ciphertext',
      'wrappedCiphertext',
      'clientSignatureShareB64u',
      'cosignerShareB64u',
      'clientVerifyingShareB64u',
      'relayerSigningShareB64u',
      'secretBytes',
      'privateKey',
      'privateKeyHex',
      'token',
      'authorizationHeader',
      'cookieHeader',
      'claims',
    ];
    const offenders: string[] = [];
    for (const root of roots) {
      for (const relativePath of listTsFiles(root)) {
        const source = readRepoFile(relativePath);
        for (const call of findLoggerCalls(source)) {
          for (const field of forbiddenFields) {
            const fieldPattern = new RegExp(`\\b${field}\\b\\s*:`);
            if (fieldPattern.test(call)) {
              offenders.push(`${relativePath} logs forbidden field ${field}`);
            }
          }
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('strict ECDSA activation branches only come from activation builder modules', () => {
    const allowedFiles = new Set<string>([
      'client/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts',
      'client/src/core/signingEngine/useCases/provisionEcdsaSession.ts',
    ]);
    const offenders: string[] = [];
    const pattern =
      /kind:\s*'(passkey_ecdsa_activation|email_otp_ecdsa_activation|threshold_session_auth_reconnect|cookie_reconnect)'/;
    for (const relativePath of listTsFiles('client/src/core/signingEngine')) {
      if (relativePath.endsWith('.typecheck.ts')) continue;
      const source = readRepoFile(relativePath);
      if (!pattern.test(source)) continue;
      if (!allowedFiles.has(relativePath)) {
        offenders.push(relativePath);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('strict activation/session state avoids cast escape hatches', () => {
    const offenders: string[] = [];
    const pattern =
      /\bas (?:ThresholdEcdsaActivationRequest|ThresholdEcdsaPasskeyActivationRequest|ThresholdEcdsaEmailOtpActivationRequest|ThresholdEcdsaThresholdSessionAuthReconnectRequest|ThresholdEcdsaCookieReconnectRequest|PasskeyEcdsaActivation|EmailOtpEcdsaActivation|ThresholdSessionAuthEcdsaActivation|CookieEcdsaActivation|PreparedEvmFamilyEcdsaSigningSession|EcdsaSessionProvisionPlan)\b/;
    for (const relativePath of [
      ...listTsFiles('client/src/core/signingEngine/session/passkey'),
      ...listTsFiles('client/src/core/signingEngine/flows/signEvmFamily'),
    ]) {
      const source = readRepoFile(relativePath);
      if (pattern.test(source)) {
        offenders.push(relativePath);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('strict activation/session builders avoid broad spread shortcuts', () => {
    const offenders: string[] = [];
    const pattern = /\.\.\.(?:baseArgs|args\.signingAuthPlan|activation|effectivePlan)\b/;
    for (const relativePath of [
      'client/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts',
      'client/src/core/signingEngine/useCases/provisionEcdsaSession.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/requireEvmFamilyStepUpAuth.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    ]) {
      const source = readRepoFile(relativePath);
      if (pattern.test(source)) {
        offenders.push(relativePath);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });
});
