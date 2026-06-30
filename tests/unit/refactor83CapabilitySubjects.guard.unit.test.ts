import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SDK_WEB_SRC = 'packages/sdk-web/src';
const ECDSA_HANDLE_MODULE =
  'packages/sdk-web/src/core/signingEngine/session/identity/ecdsaHssSigningMaterialHandle.ts';

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function extractSourceBlock(source: string, startMarker: string, endMarker: string): string {
  const start = source.indexOf(startMarker);
  expect(start).toBeGreaterThanOrEqual(0);
  const end = source.indexOf(endMarker, start + startMarker.length);
  expect(end).toBeGreaterThan(start);
  return source.slice(start, end + endMarker.length);
}

function listTypeScriptFiles(relativePath: string): string[] {
  const absolutePath = path.join(repoRoot, relativePath);
  const stat = fs.statSync(absolutePath);
  if (stat.isFile()) return /\.(ts|tsx)$/.test(relativePath) ? [relativePath] : [];
  return fs.readdirSync(absolutePath, { withFileTypes: true }).flatMap((entry) => {
    if (entry.name === 'dist' || entry.name === 'node_modules') return [];
    const childPath = path.join(relativePath, entry.name);
    if (entry.isDirectory()) return listTypeScriptFiles(childPath);
    return /\.(ts|tsx)$/.test(entry.name) ? [childPath] : [];
  });
}

test.describe('Refactor 83 capability subject source guards', () => {
  test('role-local ECDSA material handles are constructed only in the identity module', () => {
    const offenders = listTypeScriptFiles(SDK_WEB_SRC).filter((relativePath) => {
      if (relativePath === ECDSA_HANDLE_MODULE) return false;
      return readRepoSource(relativePath).includes('router-ab-ecdsa-role-local:');
    });

    expect(offenders).toEqual([]);
    expect(readRepoSource(ECDSA_HANDLE_MODULE)).toContain('EcdsaRoleLocalMaterialBinding');
  });

  test('wallet-scoped unlock code no longer uses the collapsed NEAR binding error', () => {
    const walletAuth = readRepoSource('packages/sdk-web/src/SeamsWeb/operations/auth/walletAuth.ts');
    expect(walletAuth).not.toContain(
      'wallet-scoped auth requires a resolved NEAR account binding',
    );
    expect(walletAuth).toContain('WalletUnlockSubject');
  });

  test('visible iframe passkey registration is bound to a provided wallet ID', () => {
    const publicTypes = readRepoSource('packages/sdk-web/src/SeamsWeb/publicApi/types.ts');
    const messages = readRepoSource(
      'packages/sdk-web/src/SeamsWeb/walletIframe/shared/messages.ts',
    );
    const controller = readRepoSource(
      'packages/sdk-web/src/react/components/PasskeyAuthMenu/controller/usePasskeyAuthMenuController.ts',
    );
    const passkeyAuthMenuTypes = readRepoSource(
      'packages/sdk-web/src/react/components/PasskeyAuthMenu/types.ts',
    );
    const hostNear = readRepoSource(
      'packages/sdk-web/src/SeamsWeb/walletIframe/host/handlers/near.ts',
    );
    const touchIdPrompt = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt.ts',
    );
    const registrationFlow = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/registration.ts',
    );
    const activationSurfaceArgs = extractSourceBlock(
      publicTypes,
      'export type CreatePasskeyRegistrationActivationSurfaceArgs = {',
      '};',
    );
    const activationPreparePayload = extractSourceBlock(
      messages,
      'export interface PMRegistrationActivationPreparePayload {',
      '\n}',
    );

    expect(activationSurfaceArgs).toContain(
      "wallet: Extract<RegisterWalletInput, { kind: 'provided' }>",
    );
    expect(activationPreparePayload).toContain(
      "wallet: Extract<RegisterWalletInput, { kind: 'provided' }>",
    );
    expect(activationSurfaceArgs).not.toContain(
      "wallet?: Extract<RegisterWalletInput, { kind: 'provided' }>",
    );
    expect(activationPreparePayload).not.toContain(
      "wallet?: Extract<RegisterWalletInput, { kind: 'provided' }>",
    );
    expect(controller).toContain('type PasskeyRegistrationDraft');
    expect(controller).toContain('createReadableWalletId()');
    expect(controller).toContain('createPasskeyAuthMenuRegistrationRequest');
    expect(controller).toContain('props.onRegister?.(registrationRequest)');
    expect(passkeyAuthMenuTypes).toContain('export type PasskeyAuthMenuRegistrationRequest =');
    expect(passkeyAuthMenuTypes).toContain("kind: 'implicit_wallet'");
    expect(passkeyAuthMenuTypes).toContain("kind: 'sponsored_named_near_account'");
    expect(passkeyAuthMenuTypes).not.toContain('onRegister?: (options?:');
    expect(controller).not.toContain('props.onRegister?.(registrationOptions)');
    expect(controller).not.toContain('createServerAllocatedWalletId');
    expect(controller).not.toContain('createReadableRegistrationWalletId');
    expect(hostNear).toContain('parseRegistrationActivationProvidedWallet');
    expect(hostNear).not.toContain('...(payload.wallet');
    expect(touchIdPrompt).toContain('requireExpectedPasskeyRegistrationUser');
    expect(touchIdPrompt).not.toContain('generateSignerSlotDisplayName');
    expect(registrationFlow).not.toContain('derivePasskeyRegistrationIntendedUserName');
  });
});
