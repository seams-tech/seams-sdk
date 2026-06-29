import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';

const REGISTRATION_URL = new URL(
  '../../packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
  import.meta.url,
);
const SEAMS_WEB_URL = new URL('../../packages/sdk-web/src/SeamsWeb/SeamsWeb.ts', import.meta.url);
const PRODUCTION_CONTINUATION_SCAN_URLS = [
  '../../packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
  '../../packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts',
  '../../packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts',
  '../../packages/sdk-server-ts/src/core/types.ts',
  '../../packages/sdk-server-ts/src/router/commonRouterUtils.ts',
] as const;

test.describe('Passkey registration rollback guard', () => {
  test('preserves local passkey state after on-chain account creation', () => {
    const source = readFileSync(REGISTRATION_URL, 'utf8');
    const functionStart = source.indexOf('async function performRegistrationRollback');
    expect(functionStart).toBeGreaterThan(-1);
    const rollbackBlock = source.slice(functionStart);

    expect(rollbackBlock).toContain('registrationState.databaseStored');
    expect(rollbackBlock).toContain(
      'registrationState.accountCreated || registrationState.contractRegistered',
    );
    expect(rollbackBlock).toContain('databaseRollbackSkippedReason');
    expect(rollbackBlock).toContain('on_chain_account_created');
    expect(rollbackBlock).toContain('rollbackUserRegistration');
    expect(rollbackBlock.indexOf('on_chain_account_created')).toBeLessThan(
      rollbackBlock.indexOf('await registrationAccounts.rollbackUserRegistration'),
    );
  });

  test('passkey registration helper routes through wallet registration signer-set builder', () => {
    const source = readFileSync(SEAMS_WEB_URL, 'utf8');
    const functionStart = source.indexOf('private async registerPasskeyDomain');
    expect(functionStart).toBeGreaterThan(-1);
    const functionEnd = source.indexOf(
      'private createPasskeyRegistrationActivationSurfaceDomain',
      functionStart,
    );
    expect(functionEnd).toBeGreaterThan(functionStart);
    const functionBlock = source.slice(functionStart, functionEnd);

    expect(functionBlock).toContain('return await this.registerWalletDomain({');
    expect(functionBlock).toContain('buildNearWalletRegistrationSignerSetSelection');
    expect(functionBlock).not.toContain("mode: 'ed25519_only'");
    expect(source).not.toContain('async function provisionThresholdEcdsaAfterRegistration');
    expect(source).not.toContain("kind: 'registration_continuation'");
  });

  test('production registration paths do not expose continuation ECDSA auth', () => {
    for (const relativeUrl of PRODUCTION_CONTINUATION_SCAN_URLS) {
      const source = readFileSync(new URL(relativeUrl, import.meta.url), 'utf8');
      expect(source, relativeUrl).not.toContain('registrationContinuation');
      expect(source, relativeUrl).not.toContain('registration_continuation');
    }
  });
});
