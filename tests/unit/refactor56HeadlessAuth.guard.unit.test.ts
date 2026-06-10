import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
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

function extractFunctionBlock(source: string, functionName: string): string {
  const start = source.indexOf(`const ${functionName} = async`);
  if (start < 0) throw new Error(`Missing ${functionName}`);
  const nextConst = source.indexOf('\n  const ', start + 1);
  if (nextConst < 0) return source.slice(start);
  return source.slice(start, nextConst);
}

test.describe('refactor 56 headless auth guards', () => {
  test('demo Google Email OTP path uses the headless flow', () => {
    const source = readRepoSource('examples/seams-site/src/flows/demo/PasskeyLoginMenu.tsx');
    const googleFlow = extractFunctionBlock(source, 'onGoogleSsoEmailOtp');

    expect(googleFlow).toContain('beginGoogleEmailOtpWalletAuth');
    expect(googleFlow).not.toMatch(/\bexchangeGoogleEmailOtpSession\b/);
    expect(googleFlow).not.toMatch(/\brequestEmailOtpChallenge\b/);
    expect(googleFlow).not.toMatch(/\brequestEmailOtpEnrollmentChallenge\b/);
    expect(googleFlow).not.toMatch(/\bloginWithEmailOtpEcdsaCapability\b/);
    expect(googleFlow).not.toMatch(/\bregisterNearWallet\b/);
    expect(googleFlow).not.toMatch(/\bgetWalletSession\b/);
    expect(googleFlow).not.toMatch(/\bwalletSessionRefFromSession\b/);
  });

  test('React UI code does not branch on relay Google Email OTP resolution', () => {
    const offenders = listTypeScriptFiles('packages/sdk-web/src/react').filter((relativePath) =>
      /\bgoogleEmailOtpResolution\b/.test(readRepoSource(relativePath)),
    );

    expect(offenders).toEqual([]);
  });

  test('headless flow operation depends on narrow ports', () => {
    const source = readRepoSource(
      'packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow.ts',
    );

    expect(source).not.toMatch(/\bSeamsWebContext\b/);
    expect(source).not.toMatch(/\bSeamsWebSigningSurface\b/);
    expect(source).not.toMatch(/\bBrowserSigningSurface\b/);
    expect(source).not.toMatch(/from\s+['"]@\/SeamsWeb\/SeamsWeb['"]/);
  });

  test('standard Google Email OTP registration branch cannot issue OTP challenges', () => {
    const source = readRepoSource(
      'packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow.ts',
    );
    const start = source.indexOf('function createGoogleEmailOtpWalletRegistrationFlow');
    const end = source.indexOf('function createGoogleEmailOtpWalletLoginFlow');
    if (start < 0 || end < start) {
      throw new Error('Missing Google Email OTP registration flow block');
    }
    const registrationFlow = source.slice(start, end);

    expect(registrationFlow).not.toMatch(/\brequestLoginChallenge\b/);
    expect(registrationFlow).not.toMatch(/\brequestEmailOtpChallenge\b/);
    expect(registrationFlow).not.toMatch(/\bcreateGoogleEmailOtpWalletLoginFlow\b/);
    expect(registrationFlow).not.toMatch(/\bchallenge_sent\b/);
  });

  test('public API layer does not own wallet iframe flow handles', () => {
    const offenders = listTypeScriptFiles('packages/sdk-web/src/SeamsWeb/publicApi').filter((relativePath) =>
      /\bflowHandleId\b|googleEmailOtpWalletAuthFlows\b/.test(readRepoSource(relativePath)),
    );

    expect(offenders).toEqual([]);
  });

  test('wallet iframe Email OTP flow handles are bound before consume', () => {
    const hostSource = readRepoSource(
      'packages/sdk-web/src/SeamsWeb/walletIframe/host/handlers/emailOtp.ts',
    );
    const messagesSource = readRepoSource('packages/sdk-web/src/SeamsWeb/walletIframe/shared/messages.ts');
    const clientSource = readRepoSource('packages/sdk-web/src/SeamsWeb/walletIframe/client/router.ts');

    expect(messagesSource).toMatch(/flowId: string/);
    expect(messagesSource).toMatch(/walletId: string/);
    expect(messagesSource).toMatch(/mode: GoogleEmailOtpWalletAuthResolvedMode/);
    expect(hostSource).toContain('assertFlowHandleMatchesPayload(record.flow, payload)');
    expect(clientSource).toMatch(/flowId: wire\.flowId/);
    expect(clientSource).toMatch(/walletId: wire\.walletId/);
    expect(clientSource).toMatch(/mode: wire\.mode/);
  });
});
