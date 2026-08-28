import { expect, test } from '@playwright/test';
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
import { parseRecoveryCodeReservationId } from '@shared/wallet-recovery/recoveryCodeReservation';
import { prepareWalletRecoveryWithCode } from '../../packages/wallet/src/core/rpcClients/relayer/walletRecoveryPrepare';

const RP_ID = webAuthnRpIdFromString('wallet.example.localhost');
const RESERVATION_ID = parseRecoveryCodeReservationId('reservation-1');
const PASSKEY_TARGET = { kind: 'passkey', rpId: RP_ID } as const;

type CapturedRequest = {
  url: string;
  body: unknown;
};

function webAuthnRpIdFromString(value: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function captureRequest(
  capture: CapturedRequest,
  status: number,
  responseBody: unknown,
): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    capture.url = String(input);
    capture.body = JSON.parse(String(init?.body));
    return new Response(JSON.stringify(responseBody), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });
  }) as typeof fetch;
}

function respondWith(status: number, body: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })) as unknown as typeof fetch;
}

test('prepare posts the code-authorized R115 target request', async () => {
  const captured: CapturedRequest = { url: '', body: null };
  const result = await prepareWalletRecoveryWithCode({
    relayUrl: 'https://relay.localhost/',
    target: PASSKEY_TARGET,
    recoveryCodeB64u: 'QUJDREVG',
    reservationId: RESERVATION_ID,
    fetchImpl: captureRequest(captured, 400, { ok: false }),
  });

  expect(captured).toEqual({
    url: 'https://relay.localhost/wallets/recovery/prepare',
    body: {
      recoveryCodeB64u: 'QUJDREVG',
      reservationId: RESERVATION_ID,
      target: PASSKEY_TARGET,
    },
  });
  expect(result).toEqual({ kind: 'refused' });
});

test('prepare preserves the four exact failure classifications', async () => {
  const refused = await prepareWalletRecoveryWithCode({
    relayUrl: 'https://relay.localhost',
    target: PASSKEY_TARGET,
    recoveryCodeB64u: 'QUJDREVG',
    reservationId: RESERVATION_ID,
    fetchImpl: respondWith(401, { ok: false, code: 'recovery_code_rejected' }),
  });
  const conflict = await prepareWalletRecoveryWithCode({
    relayUrl: 'https://relay.localhost',
    target: PASSKEY_TARGET,
    recoveryCodeB64u: 'QUJDREVG',
    reservationId: RESERVATION_ID,
    fetchImpl: respondWith(409, { ok: false, code: 'recovery_conflict' }),
  });
  const consumed = await prepareWalletRecoveryWithCode({
    relayUrl: 'https://relay.localhost',
    target: PASSKEY_TARGET,
    recoveryCodeB64u: 'QUJDREVG',
    reservationId: RESERVATION_ID,
    fetchImpl: respondWith(401, { ok: false, code: 'recovery_code_used' }),
  });
  const uncertain = await prepareWalletRecoveryWithCode({
    relayUrl: 'https://relay.localhost',
    target: PASSKEY_TARGET,
    recoveryCodeB64u: 'QUJDREVG',
    reservationId: RESERVATION_ID,
    fetchImpl: respondWith(503, { ok: false }),
  });

  expect(refused).toEqual({ kind: 'refused' });
  expect(conflict).toEqual({ kind: 'retryable_conflict' });
  expect(consumed).toEqual({ kind: 'consumed' });
  expect(uncertain).toEqual({ kind: 'transport_uncertain' });
});

test('prepare classifies a network failure as transport uncertainty', async () => {
  const result = await prepareWalletRecoveryWithCode({
    relayUrl: 'https://relay.localhost',
    target: PASSKEY_TARGET,
    recoveryCodeB64u: 'QUJDREVG',
    reservationId: RESERVATION_ID,
    fetchImpl: (async () => {
      throw new Error('offline');
    }) as unknown as typeof fetch,
  });

  expect(result).toEqual({ kind: 'transport_uncertain' });
});
