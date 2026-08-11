import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';
import type { WebAuthnAuthenticationCredential } from '../../core/types';
import {
  findUnexpectedRouteKey,
  parseWebAuthnAuthenticationCredential,
} from '../framework/routeRequestValidation';
import { parseSessionKind } from '../framework/routerApi';
import { parseOidcAccountMode } from '../domains/emailOtp/emailOtpSessionRouteHelpers';
import {
  parseHostedWalletSeamsSessionExchangeCode,
  parseHostedWalletSeamsSessionExchangeNonce,
  parseSessionOrigin,
  type HostedWalletSeamsSessionExchangeCode,
  type HostedWalletSeamsSessionExchangeNonce,
  type SessionOrigin,
} from '../../authorization/domain';
import {
  parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1,
  type RouterAbEcdsaPostRegistrationSessionActivationPolicyV1,
} from '@shared/utils/routerAbEcdsaDerivation';

export type PasskeySessionExchangeEcdsaActivation =
  | { kind: 'no_ecdsa_activation' }
  | {
      kind: 'activate_first_ecdsa_wallet_session';
      policy: RouterAbEcdsaPostRegistrationSessionActivationPolicyV1;
    };

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
      walletId?: never;
      webauthnAuthentication: WebAuthnAuthenticationCredential;
      ecdsaActivation: { kind: 'no_ecdsa_activation' };
      expectedOrigin?: string;
      projectEnvironmentId?: string;
    }
  | {
      kind: 'passkey_assertion';
      sessionKind: 'jwt' | 'cookie';
      challengeId: string;
      walletId: string;
      webauthnAuthentication: WebAuthnAuthenticationCredential;
      ecdsaActivation: Extract<
        PasskeySessionExchangeEcdsaActivation,
        { kind: 'activate_first_ecdsa_wallet_session' }
      >;
      expectedOrigin?: string;
      projectEnvironmentId?: string;
    }
  | {
      kind: 'github_oauth_code';
      sessionKind: 'jwt' | 'cookie';
      code: string;
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
const GITHUB_OAUTH_CODE_EXCHANGE_KEYS = ['type', 'code'] as const;
const PASSKEY_EXCHANGE_KEYS = [
  'type',
  'challengeId',
  'webauthn_authentication',
  'expected_origin',
  'wallet_id',
  'ecdsa_session_policy',
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
      'github_oauth_code',
      'passkey_assertion',
      'hosted_wallet_exchange_code',
      'hosted_wallet_exchange_code_redeem',
    ].includes(exchangeType)
  ) {
    return invalidSessionExchangeBody(
      'exchange.type must be one of: oidc_jwt, github_oauth_code, passkey_assertion, hosted_wallet_exchange_code, hosted_wallet_exchange_code_redeem',
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

  if (exchangeType === 'github_oauth_code') {
    const unsupportedExchangeKey = findUnexpectedRouteKey(
      exchange,
      GITHUB_OAUTH_CODE_EXCHANGE_KEYS,
    );
    if (unsupportedExchangeKey) {
      return invalidSessionExchangeBody(
        `Unsupported github_oauth_code exchange field: ${unsupportedExchangeKey}`,
        exchangeType,
        sessionKind,
      );
    }
    const code = toOptionalTrimmedString(exchange.code) || '';
    if (!code) {
      return invalidSessionExchangeBody('exchange.code is required', exchangeType, sessionKind);
    }
    return {
      ok: true,
      command: {
        kind: 'github_oauth_code',
        sessionKind,
        code,
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
  const walletId = toOptionalTrimmedString(exchange.wallet_id) || undefined;
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
  let ecdsaActivation: PasskeySessionExchangeEcdsaActivation = {
    kind: 'no_ecdsa_activation',
  };
  if (exchange.ecdsa_session_policy !== undefined) {
    if (!walletId) {
      return invalidSessionExchangeBody(
        'exchange.wallet_id is required with ECDSA policy',
        exchangeType,
        sessionKind,
      );
    }
    try {
      ecdsaActivation = {
        kind: 'activate_first_ecdsa_wallet_session',
        policy: parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1(
          exchange.ecdsa_session_policy,
        ),
      };
    } catch (error: unknown) {
      return invalidSessionExchangeBody(
        error instanceof Error ? error.message : 'ECDSA Wallet Session activation is invalid',
        exchangeType,
        sessionKind,
      );
    }
  } else if (walletId) {
    return invalidSessionExchangeBody(
      'exchange.wallet_id requires an ECDSA policy',
      exchangeType,
      sessionKind,
    );
  }
  if (ecdsaActivation.kind === 'no_ecdsa_activation') {
    return {
      ok: true,
      command: {
        kind: 'passkey_assertion',
        sessionKind,
        challengeId,
        webauthnAuthentication,
        ecdsaActivation,
        ...(expectedOrigin ? { expectedOrigin } : {}),
        ...(projectEnvironmentId ? { projectEnvironmentId } : {}),
      },
    };
  }
  if (!walletId) {
    return invalidSessionExchangeBody(
      'exchange.wallet_id is required with ECDSA policy',
      exchangeType,
      sessionKind,
    );
  }
  return {
    ok: true,
    command: {
      kind: 'passkey_assertion',
      sessionKind,
      challengeId,
      walletId,
      webauthnAuthentication,
      ecdsaActivation,
      ...(expectedOrigin ? { expectedOrigin } : {}),
      ...(projectEnvironmentId ? { projectEnvironmentId } : {}),
    },
  };
}
