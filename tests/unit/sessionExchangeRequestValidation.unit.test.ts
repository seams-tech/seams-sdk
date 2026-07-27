import { expect, test } from '@playwright/test';
import { parseSessionExchangeRouteCommand } from '../../packages/sdk-server-ts/src/router/sessionExchangeRequestValidation';

test.describe('hosted-wallet Seams session exchange request validation', () => {
  test('parses code issuance and redemption as exact JWT exchanges', () => {
    expect(
      parseSessionExchangeRouteCommand({
        sessionKind: 'jwt',
        exchange: {
          type: 'hosted_wallet_exchange_code',
          wallet_origin: 'https://wallet.example.test',
        },
      }),
    ).toEqual({
      ok: true,
      command: {
        kind: 'hosted_wallet_exchange_code',
        sessionKind: 'jwt',
        walletOrigin: 'https://wallet.example.test',
      },
    });

    expect(
      parseSessionExchangeRouteCommand({
        sessionKind: 'jwt',
        exchange: {
          type: 'hosted_wallet_exchange_code_redeem',
          exchange_code: 'exchange-code',
          nonce: 'exchange-nonce',
        },
      }),
    ).toEqual({
      ok: true,
      command: {
        kind: 'hosted_wallet_exchange_code_redeem',
        sessionKind: 'jwt',
        exchangeCode: 'exchange-code',
        nonce: 'exchange-nonce',
      },
    });
  });

  test('rejects cookie delivery and unexpected exchange fields', () => {
    expect(
      parseSessionExchangeRouteCommand({
        sessionKind: 'cookie',
        exchange: {
          type: 'hosted_wallet_exchange_code',
          wallet_origin: 'https://wallet.example.test',
        },
      }),
    ).toMatchObject({ ok: false });
    expect(
      parseSessionExchangeRouteCommand({
        sessionKind: 'jwt',
        exchange: {
          type: 'hosted_wallet_exchange_code_redeem',
          exchange_code: 'exchange-code',
          nonce: 'exchange-nonce',
          appSessionJwt: 'bearer-must-not-cross-this-boundary',
        },
      }),
    ).toMatchObject({ ok: false });
  });
});
