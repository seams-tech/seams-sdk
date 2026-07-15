import { expect, test } from '@playwright/test';
import {
  EmailOtpEd25519YaoRootVault,
  type EmailOtpEd25519YaoOwnedFactorSecret,
  type EmailOtpEd25519YaoRootBinding,
  type EmailOtpEd25519YaoRootConsumer,
  type EmailOtpEd25519YaoRootConsumerResult,
  type EmailOtpEd25519YaoRootScope,
} from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519YaoRootVault';

const NOW_MS = 1_800_000_000_000;
const EXPIRES_AT_MS = NOW_MS + 60_000;

function registrationScope(): EmailOtpEd25519YaoRootScope {
  return {
    kind: 'email_otp_ed25519_yao_root_scope_v1',
    purpose: 'registration',
    walletId: 'email-otp-yao.testnet',
    providerSubject: 'google:email-otp-subject',
    nearEd25519SigningKeyId: 'ed25519ks_email_otp_yao_1',
    signingRootId: 'project_email_otp:dev',
    signerSlot: 1,
    participantIds: [1, 2],
  };
}

function registrationBinding(): EmailOtpEd25519YaoRootBinding {
  return {
    kind: 'email_otp_ed25519_yao_root_binding_v1',
    lifecycleId: 'registration-ceremony-1',
    scope: registrationScope(),
  };
}

class RecordingRootConsumer implements EmailOtpEd25519YaoRootConsumer<string> {
  readonly copiedSecrets: Uint8Array[] = [];
  readonly ownedSecretReferences: Uint8Array[] = [];

  async consumeOwnedFactorSecret(
    input: EmailOtpEd25519YaoOwnedFactorSecret,
  ): Promise<EmailOtpEd25519YaoRootConsumerResult<string>> {
    this.copiedSecrets.push(input.factorSecret32.slice());
    this.ownedSecretReferences.push(input.factorSecret32);
    return { ok: true, value: input.binding.lifecycleId };
  }
}

class FailingRootConsumer implements EmailOtpEd25519YaoRootConsumer<string> {
  readonly ownedSecretReferences: Uint8Array[] = [];

  async consumeOwnedFactorSecret(
    input: EmailOtpEd25519YaoOwnedFactorSecret,
  ): Promise<EmailOtpEd25519YaoRootConsumerResult<string>> {
    this.ownedSecretReferences.push(input.factorSecret32);
    return { ok: false, code: 'yao_execution_failed', message: 'Yao execution failed' };
  }
}

test('Email OTP Yao root vault exposes only an opaque one-use handle', async () => {
  const vault = new EmailOtpEd25519YaoRootVault();
  const ownedFactorSecret32 = new Uint8Array(32).fill(0x41);
  const handle = vault.issueOwned({
    scope: registrationScope(),
    ownedFactorSecret32,
    expiresAtMs: EXPIRES_AT_MS,
    nowMs: NOW_MS,
  });

  expect([...ownedFactorSecret32]).toEqual(new Array(32).fill(0));
  expect(Object.keys(handle).sort()).toEqual(['expiresAtMs', 'handleId', 'kind', 'purpose']);
  expect(JSON.stringify(handle)).not.toContain('41');

  const consumer = new RecordingRootConsumer();
  const consumed = await vault.consume({
    handle,
    binding: registrationBinding(),
    consumer,
    nowMs: NOW_MS,
  });
  expect(consumed).toEqual({ ok: true, value: 'registration-ceremony-1' });
  expect([...consumer.copiedSecrets[0]!]).toEqual(new Array(32).fill(0x41));
  expect([...consumer.ownedSecretReferences[0]!]).toEqual(new Array(32).fill(0));

  const replay = await vault.consume({
    handle,
    binding: registrationBinding(),
    consumer,
    nowMs: NOW_MS,
  });
  expect(replay).toMatchObject({ ok: false, code: 'root_handle_missing' });
});

test('Email OTP Yao root vault rejects substitution without consuming the valid handle', async () => {
  const vault = new EmailOtpEd25519YaoRootVault();
  const handle = vault.issueOwned({
    scope: registrationScope(),
    ownedFactorSecret32: new Uint8Array(32).fill(0x52),
    expiresAtMs: EXPIRES_AT_MS,
    nowMs: NOW_MS,
  });
  const consumer = new RecordingRootConsumer();
  const substitutedBinding = {
    ...registrationBinding(),
    scope: {
      ...registrationScope(),
      walletId: 'substituted.testnet',
    },
  };

  const substituted = await vault.consume({
    handle,
    binding: substitutedBinding,
    consumer,
    nowMs: NOW_MS,
  });
  expect(substituted).toMatchObject({ ok: false, code: 'root_handle_scope_mismatch' });
  expect(consumer.copiedSecrets).toHaveLength(0);

  const exact = await vault.consume({
    handle,
    binding: registrationBinding(),
    consumer,
    nowMs: NOW_MS,
  });
  expect(exact.ok).toBe(true);
});

test('Email OTP Yao root vault burns and zeroizes a failed consumer handoff', async () => {
  const vault = new EmailOtpEd25519YaoRootVault();
  const handle = vault.issueOwned({
    scope: registrationScope(),
    ownedFactorSecret32: new Uint8Array(32).fill(0x63),
    expiresAtMs: EXPIRES_AT_MS,
    nowMs: NOW_MS,
  });
  const consumer = new FailingRootConsumer();

  const failed = await vault.consume({
    handle,
    binding: registrationBinding(),
    consumer,
    nowMs: NOW_MS,
  });
  expect(failed).toEqual({
    ok: false,
    code: 'yao_execution_failed',
    message: 'Yao execution failed',
  });
  expect([...consumer.ownedSecretReferences[0]!]).toEqual(new Array(32).fill(0));

  const retry = await vault.consume({
    handle,
    binding: registrationBinding(),
    consumer,
    nowMs: NOW_MS,
  });
  expect(retry).toMatchObject({ ok: false, code: 'root_handle_missing' });
});

test('Email OTP Yao root vault expires and removes unused material', async () => {
  const vault = new EmailOtpEd25519YaoRootVault();
  const handle = vault.issueOwned({
    scope: registrationScope(),
    ownedFactorSecret32: new Uint8Array(32).fill(0x74),
    expiresAtMs: EXPIRES_AT_MS,
    nowMs: NOW_MS,
  });
  const consumer = new RecordingRootConsumer();

  const expired = await vault.consume({
    handle,
    binding: registrationBinding(),
    consumer,
    nowMs: EXPIRES_AT_MS,
  });
  expect(expired).toMatchObject({ ok: false, code: 'root_handle_expired' });
  expect(consumer.copiedSecrets).toHaveLength(0);
  expect(vault.remove(handle)).toBe(false);
});

test('Email OTP Yao root disposal rejects mutated handle metadata', () => {
  const vault = new EmailOtpEd25519YaoRootVault();
  const handle = vault.issueOwned({
    scope: registrationScope(),
    ownedFactorSecret32: new Uint8Array(32).fill(0x75),
    expiresAtMs: EXPIRES_AT_MS,
    nowMs: NOW_MS,
  });

  expect(() => vault.remove({ ...handle, purpose: 'recovery' })).toThrow(/metadata changed/);
  expect(vault.remove(handle)).toBe(true);
  expect(vault.remove(handle)).toBe(false);
});

test('Email OTP Yao pending factor binds once to the exact admitted scope', async () => {
  const vault = new EmailOtpEd25519YaoRootVault();
  const pendingSecret = new Uint8Array(32).fill(0x85);
  const pending = vault.issuePendingOwned({
    purpose: 'registration',
    walletId: registrationScope().walletId,
    providerSubject: registrationScope().providerSubject,
    ownedFactorSecret32: pendingSecret,
    expiresAtMs: EXPIRES_AT_MS,
    nowMs: NOW_MS,
  });
  expect(pendingSecret).toEqual(new Uint8Array(32));

  const substitutedScope = { ...registrationScope(), signerSlot: 2 };
  const exact = vault.bindPending({
    handle: pending,
    scope: substitutedScope,
    expiresAtMs: EXPIRES_AT_MS,
    nowMs: NOW_MS,
  });
  const consumer = new RecordingRootConsumer();
  const consumed = await vault.consume({
    handle: exact,
    binding: {
      kind: 'email_otp_ed25519_yao_root_binding_v1',
      lifecycleId: 'registration-ceremony-2',
      scope: substitutedScope,
    },
    consumer,
    nowMs: NOW_MS,
  });
  expect(consumed.ok).toBe(true);
  expect(consumer.copiedSecrets[0]).toEqual(new Uint8Array(32).fill(0x85));
  expect(() =>
    vault.bindPending({
      handle: pending,
      scope: substitutedScope,
      expiresAtMs: EXPIRES_AT_MS,
      nowMs: NOW_MS,
    }),
  ).toThrow(/unavailable/);
});

test('Email OTP Yao pending factor rejects wallet or provider substitution before burn', () => {
  const vault = new EmailOtpEd25519YaoRootVault();
  const pending = vault.issuePendingOwned({
    purpose: 'recovery',
    walletId: registrationScope().walletId,
    providerSubject: registrationScope().providerSubject,
    ownedFactorSecret32: new Uint8Array(32).fill(0x96),
    expiresAtMs: EXPIRES_AT_MS,
    nowMs: NOW_MS,
  });
  expect(() =>
    vault.bindPending({
      handle: pending,
      scope: {
        ...registrationScope(),
        purpose: 'recovery',
        providerSubject: 'google:substituted',
      },
      expiresAtMs: EXPIRES_AT_MS,
      nowMs: NOW_MS,
    }),
  ).toThrow(/scope changed/);

  const exact = vault.bindPending({
    handle: pending,
    scope: { ...registrationScope(), purpose: 'recovery' },
    expiresAtMs: EXPIRES_AT_MS,
    nowMs: NOW_MS,
  });
  expect(exact.purpose).toBe('recovery');
});

test('Email OTP Yao pending factor cannot extend its expiry during bind', () => {
  const vault = new EmailOtpEd25519YaoRootVault();
  const pending = vault.issuePendingOwned({
    purpose: 'registration',
    walletId: registrationScope().walletId,
    providerSubject: registrationScope().providerSubject,
    ownedFactorSecret32: new Uint8Array(32).fill(0xa7),
    expiresAtMs: EXPIRES_AT_MS,
    nowMs: NOW_MS,
  });

  expect(() =>
    vault.bindPending({
      handle: pending,
      scope: registrationScope(),
      expiresAtMs: EXPIRES_AT_MS + 1,
      nowMs: NOW_MS,
    }),
  ).toThrow(/expiry exceeds/);

  const exact = vault.bindPending({
    handle: pending,
    scope: registrationScope(),
    expiresAtMs: EXPIRES_AT_MS,
    nowMs: NOW_MS,
  });
  expect(exact.expiresAtMs).toBe(EXPIRES_AT_MS);
});

test('Email OTP Yao pending factor cancellation is one-use and zeroizing', () => {
  const vault = new EmailOtpEd25519YaoRootVault();
  const pending = vault.issuePendingOwned({
    purpose: 'recovery',
    walletId: registrationScope().walletId,
    providerSubject: registrationScope().providerSubject,
    ownedFactorSecret32: new Uint8Array(32).fill(0xb8),
    expiresAtMs: EXPIRES_AT_MS,
    nowMs: NOW_MS,
  });

  expect(vault.removePending(pending)).toBe(true);
  expect(vault.removePending(pending)).toBe(false);
  expect(() =>
    vault.bindPending({
      handle: pending,
      scope: { ...registrationScope(), purpose: 'recovery' },
      expiresAtMs: EXPIRES_AT_MS,
      nowMs: NOW_MS,
    }),
  ).toThrow(/unavailable/);
});
