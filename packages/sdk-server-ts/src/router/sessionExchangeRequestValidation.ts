import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';
import type { WebAuthnAuthenticationCredential } from '../core/types';
import {
  findUnexpectedRouteKey,
  parseWebAuthnAuthenticationCredential,
} from './routeRequestValidation';
import { parseSessionKind } from './routerApi';
import { parseOidcAccountMode } from './emailOtpSessionRouteHelpers';
import {
  parseHostedWalletSeamsSessionExchangeCode,
  parseHostedWalletSeamsSessionExchangeNonce,
  parseSessionOrigin,
  type HostedWalletSeamsSessionExchangeCode,
  type HostedWalletSeamsSessionExchangeNonce,
  type SessionOrigin,
} from '../authorization/domain';

export type SessionExchangeRouteCommand =
  | {
      kind: 'oidc_jwt';
      sessionKind: 'jwt' | 'cookie';
      token: string;
      provider: string;
      accountMode?: 'register' | 'login';
      restartRegistrationOffer: boolean;
      projectEnvironmentId?: string;
    }
  | {
      kind: 'passkey_assertion';
      sessionKind: 'jwt' | 'cookie';
      challengeId: string;
      webauthnAuthentication: WebAuthnAuthenticationCredential;
      expectedOrigin?: string;
      projectEnvironmentId?: string;
    }
  | {
      kind: 'hosted_wallet_exchange_code';
      sessionKind: 'jwt';
      walletOrigin: SessionOrigin;
    }
  | {
      kind: 'hosted_wallet_exchange_code_redeem';
      sessionKind: 'jwt';
      exchangeCode: HostedWalletSeamsSessionExchangeCode;
      nonce: HostedWalletSeamsSessionExchangeNonce;
    };

export type SessionExchangeRouteParseResult =
  | { ok: true; command: SessionExchangeRouteCommand }
  | {
      ok: false;
      body: {
        ok: false;
        code: 'invalid_body';
        message: string;
      };
      exchangeType: string;
      sessionKind: 'jwt' | 'cookie';
    };

const SESSION_EXCHANGE_KEYS = [
  'sessionKind',
  'session_kind',
  'exchange',
  'projectEnvironmentId',
] as const;
const OIDC_EXCHANGE_KEYS = ['type', 'token', 'provider', 'account_mode', 'accountMode'] as const;
const PASSKEY_EXCHANGE_KEYS = [
  'type',
  'challengeId',
  'webauthn_authentication',
  'expected_origin',
] as const;
const HOSTED_WALLET_EXCHANGE_KEYS = ['type', 'wallet_origin'] as const;
const HOSTED_WALLET_REDEEM_KEYS = ['type', 'exchange_code', 'nonce'] as const;

function invalidSessionExchangeBody(
  message: string,
  exchangeType: string,
  sessionKind: 'jwt' | 'cookie',
): SessionExchangeRouteParseResult {
  return {
    ok: false,
    body: { ok: false, code: 'invalid_body', message },
    exchangeType,
    sessionKind,
  };
}

export function parseSessionExchangeRouteCommand(raw: unknown): SessionExchangeRouteParseResult {
  const body = isPlainObject(raw) ? raw : {};
  const sessionKind = parseSessionKind(body);
  const unsupportedBodyKey = findUnexpectedRouteKey(body, SESSION_EXCHANGE_KEYS);
  if (unsupportedBodyKey) {
    return invalidSessionExchangeBody(
      `Unsupported session exchange field: ${unsupportedBodyKey}`,
      '',
      sessionKind,
    );
  }
  const exchange = isPlainObject(body.exchange) ? body.exchange : null;
  const exchangeType = (toOptionalTrimmedString(exchange?.type) || '').toLowerCase();
  if (
    !exchange ||
    ![
      'oidc_jwt',
      'passkey_assertion',
      'hosted_wallet_exchange_code',
      'hosted_wallet_exchange_code_redeem',
    ].includes(exchangeType)
  ) {
    return invalidSessionExchangeBody(
      'exchange.type must be one of: oidc_jwt, passkey_assertion, hosted_wallet_exchange_code, hosted_wallet_exchange_code_redeem',
      exchangeType,
      sessionKind,
    );
  }
  const projectEnvironmentId = toOptionalTrimmedString(body.projectEnvironmentId) || undefined;
  if (exchangeType === 'oidc_jwt') {
    const unsupportedExchangeKey = findUnexpectedRouteKey(exchange, OIDC_EXCHANGE_KEYS);
    if (unsupportedExchangeKey) {
      return invalidSessionExchangeBody(
        `Unsupported oidc_jwt exchange field: ${unsupportedExchangeKey}`,
        exchangeType,
        sessionKind,
      );
    }
    const token = toOptionalTrimmedString(exchange.token) || '';
    if (!token) {
      return invalidSessionExchangeBody('exchange.token is required', exchangeType, sessionKind);
    }
    const provider = (toOptionalTrimmedString(exchange.provider) || '').toLowerCase();
    const accountModeRaw = exchange.account_mode ?? exchange.accountMode;
    const hasAccountMode =
      Object.prototype.hasOwnProperty.call(exchange, 'account_mode') ||
      Object.prototype.hasOwnProperty.call(exchange, 'accountMode');
    const accountMode = parseOidcAccountMode(accountModeRaw);
    if (hasAccountMode && !accountMode) {
      return invalidSessionExchangeBody(
        'exchange.account_mode must be register or login for Google Email OTP',
        exchangeType,
        sessionKind,
      );
    }
    return {
      ok: true,
      command: {
        kind: 'oidc_jwt',
        sessionKind,
        token,
        provider,
        ...(accountMode ? { accountMode } : {}),
        restartRegistrationOffer: accountMode === 'register',
        ...(projectEnvironmentId ? { projectEnvironmentId } : {}),
      },
    };
  }

  if (exchangeType === 'hosted_wallet_exchange_code') {
    if (projectEnvironmentId) {
      return invalidSessionExchangeBody(
        'hosted-wallet Seams session exchange does not accept projectEnvironmentId',
        exchangeType,
        sessionKind,
      );
    }
    const unsupportedExchangeKey = findUnexpectedRouteKey(exchange, HOSTED_WALLET_EXCHANGE_KEYS);
    if (unsupportedExchangeKey) {
      return invalidSessionExchangeBody(
        `Unsupported hosted_wallet_exchange_code field: ${unsupportedExchangeKey}`,
        exchangeType,
        sessionKind,
      );
    }
    if (sessionKind !== 'jwt') {
      return invalidSessionExchangeBody(
        'hosted-wallet Seams session exchange requires sessionKind jwt',
        exchangeType,
        sessionKind,
      );
    }
    let walletOrigin: SessionOrigin;
    try {
      walletOrigin = parseSessionOrigin(exchange.wallet_origin);
    } catch {
      return invalidSessionExchangeBody(
        'exchange.wallet_origin must be a canonical HTTP origin',
        exchangeType,
        sessionKind,
      );
    }
    return {
      ok: true,
      command: {
        kind: 'hosted_wallet_exchange_code',
        sessionKind,
        walletOrigin,
      },
    };
  }

  if (exchangeType === 'hosted_wallet_exchange_code_redeem') {
    if (projectEnvironmentId) {
      return invalidSessionExchangeBody(
        'hosted-wallet Seams session redemption does not accept projectEnvironmentId',
        exchangeType,
        sessionKind,
      );
    }
    const unsupportedExchangeKey = findUnexpectedRouteKey(exchange, HOSTED_WALLET_REDEEM_KEYS);
    if (unsupportedExchangeKey) {
      return invalidSessionExchangeBody(
        `Unsupported hosted_wallet_exchange_code_redeem field: ${unsupportedExchangeKey}`,
        exchangeType,
        sessionKind,
      );
    }
    if (sessionKind !== 'jwt') {
      return invalidSessionExchangeBody(
        'hosted-wallet Seams session redemption requires sessionKind jwt',
        exchangeType,
        sessionKind,
      );
    }
    let exchangeCode: HostedWalletSeamsSessionExchangeCode;
    let nonce: HostedWalletSeamsSessionExchangeNonce;
    try {
      exchangeCode = parseHostedWalletSeamsSessionExchangeCode(exchange.exchange_code);
      nonce = parseHostedWalletSeamsSessionExchangeNonce(exchange.nonce);
    } catch {
      return invalidSessionExchangeBody(
        'exchange.exchange_code and exchange.nonce must be compact opaque identifiers',
        exchangeType,
        sessionKind,
      );
    }
    return {
      ok: true,
      command: {
        kind: 'hosted_wallet_exchange_code_redeem',
        sessionKind,
        exchangeCode,
        nonce,
      },
    };
  }

  const unsupportedExchangeKey = findUnexpectedRouteKey(exchange, PASSKEY_EXCHANGE_KEYS);
  if (unsupportedExchangeKey) {
    return invalidSessionExchangeBody(
      `Unsupported passkey_assertion exchange field: ${unsupportedExchangeKey}`,
      exchangeType,
      sessionKind,
    );
  }
  const challengeId = toOptionalTrimmedString(exchange.challengeId) || '';
  if (!challengeId) {
    return invalidSessionExchangeBody(
      'exchange.challengeId is required',
      exchangeType,
      sessionKind,
    );
  }
  const webauthnAuthentication = parseWebAuthnAuthenticationCredential(
    exchange.webauthn_authentication,
  );
  if (!webauthnAuthentication) {
    return invalidSessionExchangeBody(
      'exchange.webauthn_authentication is required',
      exchangeType,
      sessionKind,
    );
  }
  const expectedOrigin = toOptionalTrimmedString(exchange.expected_origin) || undefined;
  return {
    ok: true,
    command: {
      kind: 'passkey_assertion',
      sessionKind,
      challengeId,
      webauthnAuthentication,
      ...(expectedOrigin ? { expectedOrigin } : {}),
      ...(projectEnvironmentId ? { projectEnvironmentId } : {}),
    },
  };
}
