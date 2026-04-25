import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

test.describe('Email OTP route auth refactor guard', () => {
  test('Email OTP public and worker message surfaces use routeAuth, not thresholdRouteAuth', () => {
    const guardedFiles = [
      'client/src/core/TatchiPasskey/index.ts',
      'client/src/core/TatchiPasskey/interfaces.ts',
      'client/src/core/WalletIframe/shared/messages.ts',
      'client/src/core/signingEngine/workerManager/workerTypes.ts',
      'client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
    ];

    const violations = guardedFiles.filter((relativePath) =>
      readRepoFile(relativePath).includes('thresholdRouteAuth'),
    );

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('transaction signing adapters do not derive Email OTP route auth from raw records', () => {
    const dependencyFactory = readRepoFile(
      'client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts',
    );
    const nearSigning = readRepoFile('client/src/core/signingEngine/api/nearSigning.ts');
    const evmSigning = readRepoFile('client/src/core/signingEngine/api/evmSigning.ts');

    expect(dependencyFactory).toContain('resolveEmailOtpSigningSessionAuthLane');
    expect(dependencyFactory).toContain('createWarmSessionCapabilityReader');
    expect(nearSigning).not.toContain('thresholdSessionRouteAuthFromEd25519Record');
    expect(evmSigning).not.toContain('thresholdSessionRouteAuthFromEcdsaRecord');
    expect(nearSigning).not.toContain('authLaneToRouteAuth');
    expect(evmSigning).not.toContain('authLaneToRouteAuth');
  });

  test('Email OTP worker operations require routePlan instead of raw auth fields', () => {
    const workerTypes = readRepoFile(
      'client/src/core/signingEngine/workerManager/workerTypes.ts',
    );
    const emailOtpWorker = readRepoFile(
      'client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
    );

    expect(workerTypes).toContain('routePlan: EmailOtpRoutePlan');
    expect(emailOtpWorker).toContain('readRoutePlan(msg.payload.routePlan');
    expect(emailOtpWorker).not.toContain('msg.payload.appSessionJwt');
    expect(emailOtpWorker).not.toContain('msg.payload.routeAuth');
  });

  test('Email OTP ECDSA export uses auth subject for OTP recovery and wallet id for HSS export', () => {
    const emailOtpWorker = readRepoFile(
      'client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
    );
    const exportSlice = emailOtpWorker.slice(
      emailOtpWorker.indexOf("case 'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization'"),
      emailOtpWorker.indexOf(
        'default:',
        emailOtpWorker.indexOf("case 'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization'"),
      ),
    );

    expect(exportSlice).toContain('userId: msg.payload.userId');
    expect(exportSlice).toContain("const walletId = readString(msg.payload.walletId, 'walletId');");
    expect(exportSlice).toContain('userId: walletId');
  });
});
