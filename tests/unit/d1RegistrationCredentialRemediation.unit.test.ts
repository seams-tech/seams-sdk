import { expect, test } from '@playwright/test';
import {
  createRegistrationCredentialRemediationFixture,
  type RegistrationCredentialRemediationFixture,
} from './helpers/registrationCredentialRemediation.fixtures';
import { runRegistrationCredentialRemediation } from '../../packages/wallet-server/src/router/cloudflare/d1/registration/d1RegistrationCredentialRemediation';

let fixture: RegistrationCredentialRemediationFixture;

test.beforeEach(async () => {
  fixture = await createRegistrationCredentialRemediationFixture();
});

test.afterEach(() => {
  fixture.cleanup();
});

test.describe('registration credential remediation', () => {
  test('retires an activation bearer and its exact active parent before deleting the completion', async () => {
    await fixture.insertLegacySession();
    await fixture.insertOrdinaryBearer('ecdsa', fixture.ecdsaToken);
    await fixture.insertHistoricalCompletion('registration_activate', [
      { curve: 'ecdsa', token: fixture.ecdsaToken },
    ]);

    const report = await fixture.run();

    expect(report.before).toEqual({
      selectedRows: 1,
      credentialBearingRows: 1,
      bearerCount: 1,
    });
    expect(report.retired).toEqual({
      tokenRows: 1,
      sessionRows: 1,
      quotaRows: 1,
      deletedCompletionRows: 1,
    });
    expect(report.after).toEqual({ selectedRows: 0, credentialBearingRows: 0 });
    expect(report.repeat.credentialBearingRows).toBe(0);
    expect(await fixture.ordinaryBearerCount()).toBe(0);
    expect(await fixture.sessionLifecycle()).toBe('superseded');
    expect(await fixture.quotaLifecycle()).toEqual({
      lifecycle_kind: 'exhausted',
      remaining_uses: 0,
    });
  });

  test('handles the deferred NEAR prefix with the same exact retirement semantics', async () => {
    await fixture.insertLegacySession();
    await fixture.insertRegistrationReplayBearer('ed25519', fixture.ed25519Token);
    await fixture.insertHistoricalCompletion('near_provisioning', [
      { curve: 'ed25519', token: fixture.ed25519Token },
    ]);

    const report = await fixture.run();

    expect(report.retired.tokenRows).toBe(1);
    expect(report.retired.deletedCompletionRows).toBe(1);
    expect(await fixture.registrationReplayBearerCount()).toBe(0);
    expect(await fixture.sessionLifecycle()).toBe('superseded');
  });

  test('deletes both mixed-family bearers before retiring their one parent', async () => {
    await fixture.insertLegacySession();
    await fixture.insertOrdinaryBearer('ecdsa', fixture.ecdsaToken);
    await fixture.insertOrdinaryBearer('ed25519', fixture.ed25519Token);
    await fixture.insertHistoricalCompletion('registration_activate', [
      { curve: 'ecdsa', token: fixture.ecdsaToken },
      { curve: 'ed25519', token: fixture.ed25519Token },
    ]);

    const report = await fixture.run();

    expect(report.before.bearerCount).toBe(2);
    expect(report.retired).toEqual({
      tokenRows: 2,
      sessionRows: 1,
      quotaRows: 1,
      deletedCompletionRows: 1,
    });
    expect(await fixture.ordinaryBearerCount()).toBe(0);
  });

  test('aborts before mutation for an unknown row or a bearer without an exact usable mapping', async () => {
    await fixture.insertLegacySession();
    await fixture.insertOrdinaryBearer('ecdsa', fixture.ecdsaToken);
    await fixture.insertHistoricalCompletion('registration_activate', [
      { curve: 'ecdsa', token: fixture.ecdsaToken },
    ]);
    await fixture.insertUnknownPrefixedRow();

    await expect(fixture.run()).rejects.toThrow('unsupported row kind');
    expect(await fixture.ordinaryBearerCount()).toBe(1);
    expect(await fixture.sessionLifecycle()).toBe('active');
    expect(await fixture.quotaLifecycle()).toEqual({
      lifecycle_kind: 'active',
      remaining_uses: 7,
    });

    await fixture.removeUnknownPrefixedRow();
    await fixture.removeOrdinaryBearers();
    await expect(fixture.run()).rejects.toThrow('bearer mapping is not unique');
    expect(await fixture.sessionLifecycle()).toBe('active');
  });

  test('preserves current and unrelated rows, rejects premature execution, and repeats as a no-op', async () => {
    await fixture.insertCurrentCompletion();
    await fixture.insertHistoricalCredentialFreeError();
    await fixture.insertUnrelatedCredentialRow();
    await expect(
      runRegistrationCredentialRemediation(fixture.input({ nowMs: 1_050_000 })),
    ).rejects.toThrow('in-flight window has not elapsed');

    const first = await fixture.run();
    const second = await fixture.run();

    expect(first.before).toEqual({
      selectedRows: 2,
      credentialBearingRows: 0,
      bearerCount: 0,
    });
    expect(first.retired.deletedCompletionRows).toBe(0);
    expect(second.retired).toEqual({
      tokenRows: 0,
      sessionRows: 0,
      quotaRows: 0,
      deletedCompletionRows: 0,
    });
    expect(await fixture.journalRowExists('wallet-registration-activate:current')).toBe(true);
    expect(
      await fixture.journalRowExists('wallet-registration-near-provisioning:historical-error'),
    ).toBe(true);
    expect(await fixture.journalRowExists('unrelated:credential-bearing')).toBe(true);
  });
});
