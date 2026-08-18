import { expect, test } from '@playwright/test';
import {
  EMAIL_OTP_ED25519_YAO_REQUESTED_CAPABILITIES_KIND,
  EMAIL_OTP_NO_REQUESTED_CAPABILITIES_KIND,
  parseWalletUnlockRequestedCapabilitiesRequest,
} from '../../packages/wallet-server/src/router/domains/walletUnlock/walletUnlockRequestedCapabilitiesValidation';

const BASE_BODY = {
  unlockBackend: 'email_otp',
  walletId: 'requested-capabilities-wallet.testnet',
  orgId: 'requested-capabilities-org',
  challengeId: 'requested-capabilities-challenge',
  unlockProof: { kind: 'test-proof' },
} as const;

function parseRequest(body: Record<string, unknown>) {
  const parsed = parseWalletUnlockRequestedCapabilitiesRequest(body);
  if (!parsed.ok || !parsed.request) throw new Error('expected an Email OTP request');
  return parsed.request;
}

test.describe('wallet unlock requested capabilities boundary', () => {
  test('accepts none and ed25519_yao, rejects unknown fields and kinds', async () => {
    const none = parseRequest({
      ...BASE_BODY,
      requestedCapabilities: { kind: EMAIL_OTP_NO_REQUESTED_CAPABILITIES_KIND },
    });
    expect(none.requestedCapabilities).toEqual({ kind: 'none' });

    const ed25519 = parseRequest({
      ...BASE_BODY,
      requestedCapabilities: {
        kind: EMAIL_OTP_ED25519_YAO_REQUESTED_CAPABILITIES_KIND,
        signerSlot: 1,
        remainingUses: 3,
      },
    });
    expect(ed25519.requestedCapabilities).toEqual({
      kind: 'ed25519_yao',
      signerSlot: 1,
      remainingUses: 3,
    });

    const unknownField = parseWalletUnlockRequestedCapabilitiesRequest({
      ...BASE_BODY,
      requestedCapabilities: {
        kind: 'none',
        unsupported: true,
      },
    });
    expect(unknownField.ok).toBe(false);

    const unknownKind = parseWalletUnlockRequestedCapabilitiesRequest({
      ...BASE_BODY,
      requestedCapabilities: { kind: 'unknown' },
    });
    expect(unknownKind.ok).toBe(false);
  });
});
