import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';

const REGISTRATION_URL = new URL('../../client/src/core/SeamsPasskey/registration.ts', import.meta.url);

test.describe('Passkey registration rollback guard', () => {
  test('preserves local passkey state after on-chain account creation', () => {
    const source = readFileSync(REGISTRATION_URL, 'utf8');
    const functionStart = source.indexOf('async function performRegistrationRollback');
    expect(functionStart).toBeGreaterThan(-1);
    const functionEnd = source.indexOf('async function provisionThresholdEcdsaAfterRegistration', functionStart);
    expect(functionEnd).toBeGreaterThan(functionStart);
    const rollbackBlock = source.slice(functionStart, functionEnd);

    expect(rollbackBlock).toContain('registrationState.databaseStored');
    expect(rollbackBlock).toContain('registrationState.accountCreated || registrationState.contractRegistered');
    expect(rollbackBlock).toContain('databaseRollbackSkippedReason');
    expect(rollbackBlock).toContain('on_chain_account_created');
    expect(rollbackBlock).toContain('rollbackUserRegistration');
    expect(rollbackBlock.indexOf('on_chain_account_created')).toBeLessThan(
      rollbackBlock.indexOf('rollbackUserRegistration'),
    );
  });

  test('passes registration continuation runtime scope into threshold ECDSA bootstrap', () => {
    const source = readFileSync(REGISTRATION_URL, 'utf8');
    const functionStart = source.indexOf('async function provisionThresholdEcdsaAfterRegistration');
    expect(functionStart).toBeGreaterThan(-1);
    const functionBlock = source.slice(functionStart);

    expect(functionBlock).toContain(
      'resolveRegistrationContinuationRuntimePolicyScope(\n      registrationContinuationToken',
    );
    expect(source).toContain('parseThresholdRuntimePolicyScopeFromJwt(registrationContinuationToken)');
    expect(functionBlock).toContain('runtimePolicyScope,');
  });
});
