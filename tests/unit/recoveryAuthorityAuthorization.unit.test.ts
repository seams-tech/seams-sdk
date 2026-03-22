import { expect, test } from '@playwright/test';
import { injectImportMap } from '../setup/bootstrap';

const IMPORT_PATHS = {
  server: '/sdk/esm/server/index.js',
} as const;

test.describe('recovery authority authorization', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await injectImportMap(page);
  });

  test('builds distinct contract-facing recovery authorization payloads and calldata', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const {
        buildRecoveryAuthorityAuthorizationDigest,
        encodeRecoveryAuthorityCalldata,
        getRecoveryAuthorityFunctionSelector,
        signRecoveryAuthorityAuthorization,
      } = await import(paths.server);

      const baseInput = {
        chainId: 11155111,
        verifyingContract: `0x${'22'.repeat(20)}`,
        nearAccountId: 'alice.testnet',
        newNearPublicKey: 'ed25519:recovery-key',
        newOwnerAddress: `0x${'11'.repeat(20)}`,
        recoverySessionId: 'ABC123',
        deadlineEpochSeconds: 1_893_456_000,
      };

      const verifyAndRecover = buildRecoveryAuthorityAuthorizationDigest(baseInput);
      const recoverAddOwner = buildRecoveryAuthorityAuthorizationDigest({
        ...baseInput,
        contractMethod: 'recoverAddOwner',
      });
      const signedVerifyAndRecover = await signRecoveryAuthorityAuthorization({
        authorityPrivateKeyHex: `0x${'88'.repeat(32)}`,
        authorityAddress: `0x${'99'.repeat(20)}`,
        authorization: verifyAndRecover,
      });

      return {
        verifyAndRecover,
        recoverAddOwner,
        signedVerifyAndRecover,
        verifySelector: getRecoveryAuthorityFunctionSelector('verifyAndRecover'),
        recoverSelector: getRecoveryAuthorityFunctionSelector('recoverAddOwner'),
        verifyCalldata: encodeRecoveryAuthorityCalldata(signedVerifyAndRecover),
      };
    }, { paths: IMPORT_PATHS });

    expect(result.verifyAndRecover.contractMethod).toBe('verifyAndRecover');
    expect(result.recoverAddOwner.contractMethod).toBe('recoverAddOwner');
    expect(result.verifyAndRecover.payload.nearAccountIdHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result.verifyAndRecover.payload.newNearKeyHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result.verifyAndRecover.payload.recoverySessionHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result.verifyAndRecover.payload.deadline).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result.verifyAndRecover.payload.nonce).not.toBe(result.recoverAddOwner.payload.nonce);
    expect(result.verifyAndRecover.digest).not.toBe(result.recoverAddOwner.digest);
    expect(result.verifySelector).toMatch(/^0x[0-9a-f]{8}$/);
    expect(result.recoverSelector).toMatch(/^0x[0-9a-f]{8}$/);
    expect(result.verifySelector).not.toBe(result.recoverSelector);
    expect(result.verifyCalldata.startsWith(result.verifySelector)).toBe(true);
    expect(result.signedVerifyAndRecover.signature).toMatch(/^0x[0-9a-f]{130}$/);
    expect(result.signedVerifyAndRecover.authorityAddress).toBe(`0x${'99'.repeat(20)}`);
  });

  test('rejects invalid recovery authorization inputs early', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { buildRecoveryAuthorityAuthorizationDigest } = await import(paths.server);
      const errors: Record<string, string> = {};

      const capture = (label: string, run: () => unknown) => {
        try {
          run();
        } catch (error: unknown) {
          errors[label] = error instanceof Error ? error.message : String(error);
        }
      };

      capture('invalid_chain', () =>
        buildRecoveryAuthorityAuthorizationDigest({
          chainId: 0,
          verifyingContract: `0x${'22'.repeat(20)}`,
          nearAccountId: 'alice.testnet',
          newNearPublicKey: 'ed25519:recovery-key',
          newOwnerAddress: `0x${'11'.repeat(20)}`,
          recoverySessionId: 'ABC123',
          deadlineEpochSeconds: 1_893_456_000,
        }),
      );
      capture('expired_deadline', () =>
        buildRecoveryAuthorityAuthorizationDigest({
          chainId: 11155111,
          verifyingContract: `0x${'22'.repeat(20)}`,
          nearAccountId: 'alice.testnet',
          newNearPublicKey: 'ed25519:recovery-key',
          newOwnerAddress: `0x${'11'.repeat(20)}`,
          recoverySessionId: 'ABC123',
          deadlineEpochSeconds: 0,
        }),
      );
      capture('invalid_wallet', () =>
        buildRecoveryAuthorityAuthorizationDigest({
          chainId: 11155111,
          verifyingContract: 'not-an-address',
          nearAccountId: 'alice.testnet',
          newNearPublicKey: 'ed25519:recovery-key',
          newOwnerAddress: `0x${'11'.repeat(20)}`,
          recoverySessionId: 'ABC123',
          deadlineEpochSeconds: 1_893_456_000,
        }),
      );

      return errors;
    }, { paths: IMPORT_PATHS });

    expect(result.invalid_chain).toContain('Invalid chainId');
    expect(result.expired_deadline).toContain('Invalid recovery authorization payload');
    expect(result.invalid_wallet).toContain('Invalid verifyingContract');
  });
});
