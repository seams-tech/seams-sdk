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
  expectNoNearAccountId,
} from './helpers/signingEngineEcdsaIdentityGuard';

test.describe('signing engine ECDSA export and fixture identity guards', () => {
  test('Email OTP ECDSA export authorization uses wallet-session identity', () => {
    const confirmationSource = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/recovery/keyExportConfirmation.ts',
    );
    const emailOtpExportPromptSource = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/stepUpConfirmation/otpPrompt/exportAuthorization.ts',
    );
    const ecdsaExportSource = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportFlow.ts',
    );
    const nearAccountBranchIndex = confirmationSource.indexOf("kind: 'near_account_export_auth'");
    const nearAccountBranch =
      nearAccountBranchIndex < 0
        ? ''
        : confirmationSource.slice(nearAccountBranchIndex, nearAccountBranchIndex + 350);
    const offenders: string[] = [];

    if (/ThresholdEcdsaChainTarget|WalletAuthCurve/.test(nearAccountBranch)) {
      offenders.push('near_account_export_auth still accepts broad ECDSA-capable fields');
    }
    if (ecdsaExportSource.includes("kind: 'near_account_export_auth'")) {
      offenders.push('ECDSA export flow still requests near_account_export_auth');
    }
    if (/toAccountId\([^)]*(?:walletId|walletSessionUserId)[^)]*\)/.test(confirmationSource)) {
      offenders.push('ECDSA export confirmation coerces wallet identity through toAccountId');
    }
    if (/toAccountId\([^)]*(?:walletId|walletSessionUserId)[^)]*\)/.test(ecdsaExportSource)) {
      offenders.push('ECDSA export flow coerces wallet identity through toAccountId');
    }
    if (/\bnearAccountId:\s*toAccountId\([^)]*walletId[^)]*\)/.test(ecdsaExportSource)) {
      offenders.push('ECDSA export viewer receives wallet id through nearAccountId conversion');
    }
    if (/requestEmailOtpExportAuthorization\(args:\s*\{\s*nearAccountId:/m.test(emailOtpExportPromptSource)) {
      offenders.push('Email OTP export prompt helper still accepts only nearAccountId identity');
    }
    if (/requestEmailOtpExportAuthorizationValue\(\{\s*nearAccountId:/m.test(confirmationSource)) {
      offenders.push('Email OTP ECDSA export still passes wallet identity as nearAccountId');
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('budget status lookup avoids subject-wide ECDSA scan fallback', () => {
    const source = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts',
    );
    const offenders: string[] = [];
    for (const forbidden of ['listThresholdEcdsaRuntimeLanesForSubject', 'toWalletId(walletId)']) {
      if (source.includes(forbidden)) {
        offenders.push(`budgetStatusReader contains forbidden ECDSA fallback ${forbidden}`);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('browser signing surface ECDSA methods do not derive subject identity from accounts', () => {
    const source = readRepoFile('packages/sdk-web/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts');
    const methodNames = [
      'signEvmFamily',
      'bootstrapEcdsaSession',
      'requestEmailOtpSigningSessionChallenge',
      'refreshEmailOtpSigningSession',
      'loginWithEmailOtpEcdsaCapabilityInternal',
      'enrollAndLoginWithEmailOtpEcdsaCapabilityInternal',
    ];
    const offenders: string[] = [];

    for (const methodName of methodNames) {
      const methodSource = findMethodDeclarationAndBody(source, methodName);
      if (!methodSource) continue;
      if (/\btoWalletId\(/.test(methodSource)) {
        offenders.push(`BrowserSigningSurface.${methodName} derives subject identity`);
      }
      if (/\bnearAccountId\b/.test(methodSource)) {
        offenders.push(`BrowserSigningSurface.${methodName} exposes nearAccountId`);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('public SDK signer fixtures use domain-shaped NEAR and ECDSA calls', () => {
    const ecdsaSigningMethods = ['signTempo', 'executeEvmFamilyTransaction'];
    const ecdsaLifecycleMethods = [
      'reportBroadcastAccepted',
      'reportBroadcastRejected',
      'reportFinalized',
      'reportDroppedOrReplaced',
      'reconcileNonceLane',
    ];
    const nearMethods = [
      'executeAction',
      'signAndSendTransaction',
      'signTransactionWithActions',
      'signDelegateAction',
      'signAndSendDelegateAction',
      'signNEP413Message',
    ];
    const offenders: string[] = [];

    for (const root of ['tests/helpers', 'tests/e2e', 'tests/unit']) {
      for (const relativePath of listTsFiles(root)) {
        const source = readRepoFile(relativePath);
        for (const call of findChainedMethodCallObjects(
          source,
          ecdsaSigningMethods,
          '\\b(?:pm|seams)\\.tempo|\\bsigner',
        )) {
          offenders.push(
            ...expectRequiredFields(
              call.block,
              ['walletSession', 'chainTarget'],
              `${relativePath}:${call.line} ${call.methodName}`,
            ),
            ...expectNoField(
              call.block,
              'subjectId',
              `${relativePath}:${call.line} ${call.methodName}`,
            ),
            ...expectNoNearAccountId(call.block, `${relativePath}:${call.line} ${call.methodName}`),
          );
        }
        for (const call of findChainedMethodCallObjects(
          source,
          ecdsaLifecycleMethods,
          '\\b(?:pm|seams)\\.tempo|\\bsigner',
        )) {
          offenders.push(
            ...expectRequiredFields(
              call.block,
              ['walletSession'],
              `${relativePath}:${call.line} ${call.methodName}`,
            ),
            ...expectNoNearAccountId(call.block, `${relativePath}:${call.line} ${call.methodName}`),
          );
        }
        for (const call of findChainedMethodCallObjects(
          source,
          nearMethods,
          '\\b(?:pm|seams)\\.near|\\bsigner',
        )) {
          offenders.push(
            ...expectRequiredFields(
              call.block,
              ['nearAccount'],
              `${relativePath}:${call.line} ${call.methodName}`,
            ),
          );
          if (/\bnearAccountId\s*:/.test(call.block)) {
            offenders.push(`${relativePath}:${call.line} ${call.methodName} uses nearAccountId`);
          }
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });
});
