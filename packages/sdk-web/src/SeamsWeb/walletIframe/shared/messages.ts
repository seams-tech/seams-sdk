// Typed RPC messages for the wallet service iframe channel (SeamsWeb-first)
import type { WalletUIRegistry } from '../host/lit-ui/iframe-lit-element-registry';
import type { BootstrapThresholdEcdsaSessionArgs } from '@/SeamsWeb/signingSurface/types';
import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import { ActionArgs, TransactionInput } from '@/core/types';
import { type DeviceLinkingQRData } from '@/core/types/linkDevice';
import type { DelegateActionInput } from '@/core/types/delegate';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { TempoSigningRequest } from '@/core/signingEngine/chains/tempo/tempoSigning.types';
import type { EvmSigningRequest } from '@/core/signingEngine/chains/evm/evmSigning.types';
import type { TempoFeeTokenPreferenceSigningRequest } from '@/core/signingEngine/chains/tempo/feeToken';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import type {
  AddPasskeyAuthorization,
  EvmEip155ChainTarget,
  NearAccountRef,
  TempoChainTarget,
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EmailOtpAuthPolicy, SeamsConfigsInput } from '@/core/types/seams';
import type { WalletEmailOtpLoginOperation } from '@shared/utils/emailOtpDomain';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type {
  RegistrationTimingSpanV1,
  SdkLifecycleEvent,
  WalletFlowEvent,
} from '@/core/types/sdkSentEvents';
import type {
  GoogleEmailOtpWalletAuthDelivery,
  GoogleEmailOtpWalletAuthEcdsaTargets,
  GoogleEmailOtpWalletAuthFailure,
  GoogleEmailOtpWalletAuthPromptCopy,
  GoogleEmailOtpWalletAuthRegistrationCompleted,
  GoogleEmailOtpWalletAuthResolvedMode,
  GoogleEmailOtpWalletAuthRequestedMode,
  GoogleEmailOtpWalletAuthSubmitSuccess,
  ResolveExactKeyExportLaneInput,
  WalletRecoveryRotationAuthorization,
} from '@/SeamsWeb/publicApi/types';
import type {
  AddSignerSelection,
  EmailOtpRegistrationAuthMethodInput,
  PasskeyRegistrationAuthMethodInput,
  RegisterWalletInput,
  RegistrationSignerSetSelection,
  WalletId,
} from '@shared/utils/registrationIntent';
import { parseWalletId } from '@shared/utils/domainIds';
import type { PMUnlockPayload } from '@/core/types/login.types';
import {
  walletIframeRequestIdFromBoundary,
  type WalletIframeAuthMenuSessionId,
  type WalletIframeRequestId,
} from '@/core/types/walletIframeIdentity';
import { isPlainObject } from '@shared/utils/validation';
import type { WalletIframeExactSessionIdentity } from './exactSessionState';
export type {
  LoginUnlockRequest,
  PMUnlockOptions,
  PMUnlockPayload,
} from '@/core/types/login.types';

/**
 * Correlation identities for one wallet-origin auth-menu session. These are
 * intentionally distinct from request and surface ids: one menu can own
 * several internal requests while it remains the same foreground surface.
 */
export type HostedAuthMenuSessionId = WalletIframeAuthMenuSessionId;

export const WALLET_IFRAME_SURFACE_MEASUREMENT_MAX_CSS_PX = 4096;

export type WalletIframeSurfaceMeasurement =
  | {
      kind: 'measured_v1';
      requestId: WalletIframeRequestId;
      authMenuSessionId?: never;
      sequence: number;
      widthCssPx: number;
      heightCssPx: number;
    }
  | {
      kind: 'measured_auth_menu_v1';
      requestId: WalletIframeRequestId;
      authMenuSessionId: HostedAuthMenuSessionId;
      sequence: number;
      widthCssPx: number;
      heightCssPx: number;
    };

export type HostedAuthMenuExternalAuthRequestId = string & {
  readonly __hostedAuthMenuExternalAuthRequestId: unique symbol;
};

export type HostedAuthMenuMode = 'login' | 'register';

export type HostedAuthMenuRegistrationAccountInput =
  | 'implicit_wallet'
  | 'sponsored_named_near_account';

export type HostedAuthMenuExternalProvider = 'google';

export type HostedAuthMenuModeCopy = {
  title: string;
  subtitle: string;
  passkeyCta: string;
};

export type HostedAuthMenuCopy = {
  login: HostedAuthMenuModeCopy;
  register: HostedAuthMenuModeCopy & {
    passkeyNameLabel: string;
  };
  common: {
    closeLabel: string;
  };
};

export type HostedAuthMenuCopyInput = {
  login?: Partial<HostedAuthMenuModeCopy>;
  register?: Partial<HostedAuthMenuModeCopy> & {
    passkeyNameLabel?: string;
  };
  common?: Partial<HostedAuthMenuCopy['common']>;
};

export type HostedAuthMenuOpenRequest = {
  kind: 'hosted_auth_menu_open_v1';
  authMenuSessionId: HostedAuthMenuSessionId;
  initialMode: HostedAuthMenuMode;
  registrationAccountInput: HostedAuthMenuRegistrationAccountInput;
  showRegistrationInput: boolean;
  showProgress: boolean;
  copy: HostedAuthMenuCopy;
  enabledExternalProviders: readonly HostedAuthMenuExternalProvider[];
};

export type HostedAuthMenuExternalAuthRequest = {
  kind: 'hosted_auth_menu_external_auth_request_v1';
  authMenuSessionId: HostedAuthMenuSessionId;
  externalAuthRequestId: HostedAuthMenuExternalAuthRequestId;
  provider: HostedAuthMenuExternalProvider;
  mode: HostedAuthMenuMode;
};

export type HostedAuthMenuDemoEmailOtpDelivery = {
  kind: 'hosted_auth_menu_demo_email_otp_delivery_v1';
  authMenuSessionId: HostedAuthMenuSessionId;
  delivery: Extract<GoogleEmailOtpWalletAuthDelivery, { otpCode: string }>;
};

export type HostedAuthMenuExternalAuthFailureCode =
  | 'provider_unavailable'
  | 'provider_error'
  | 'invalid_evidence';

export type HostedAuthMenuExternalAuthEvidence =
  | {
      kind: 'google_id_token';
      idToken: string;
    }
  | {
      kind: 'cancelled';
      reason: 'user_cancelled';
    }
  | {
      kind: 'failed';
      code: HostedAuthMenuExternalAuthFailureCode;
      message: string;
    };

export type HostedAuthMenuExternalAuthResolution = {
  kind: 'hosted_auth_menu_external_auth_resolution_v1';
  authMenuSessionId: HostedAuthMenuSessionId;
  externalAuthRequestId: HostedAuthMenuExternalAuthRequestId;
  /** Original PM_OPEN_AUTH_MENU request identity, not the resolution RPC id. */
  requestId: WalletIframeRequestId;
  evidence: HostedAuthMenuExternalAuthEvidence;
};

export type HostedAuthMenuExternalAuthResolutionInput = Omit<
  HostedAuthMenuExternalAuthResolution,
  'requestId'
>;

export type HostedAuthMenuCancelReason =
  | 'close_button'
  | 'component_unmounted'
  | 'connection_closed';

export type HostedAuthMenuCancelPayload = {
  kind: 'hosted_auth_menu_cancel_v1';
  authMenuSessionId: HostedAuthMenuSessionId;
  /** Original PM_OPEN_AUTH_MENU request identity, not the cancellation RPC id. */
  requestId: WalletIframeRequestId;
  reason: HostedAuthMenuCancelReason;
};

export type HostedAuthMenuFailureCode =
  | 'invalid_request'
  | 'unsupported_provider'
  | 'provider_error'
  | 'invalid_evidence'
  | 'webauthn_failed'
  | 'wallet_error'
  | 'timeout'
  | 'connection_closed'
  | 'internal_error';

export type HostedAuthMenuOutcome =
  | {
      kind: 'authenticated';
      authMenuSessionId: HostedAuthMenuSessionId;
      walletId: WalletId;
      method: 'passkey' | 'google_email_otp';
    }
  | {
      kind: 'registered';
      authMenuSessionId: HostedAuthMenuSessionId;
      walletId: WalletId;
      method: 'passkey' | 'google_email_otp';
    }
  | {
      kind: 'account_synced';
      authMenuSessionId: HostedAuthMenuSessionId;
      walletId: WalletId;
    }
  | {
      kind: 'cancelled';
      authMenuSessionId: HostedAuthMenuSessionId;
      reason: HostedAuthMenuCancelReason;
    }
  | {
      kind: 'failed';
      authMenuSessionId: HostedAuthMenuSessionId;
      code: HostedAuthMenuFailureCode;
      message: string;
    };

export type PMOpenAuthMenuPayload = HostedAuthMenuOpenRequest;
export type PMCancelAuthMenuPayload = HostedAuthMenuCancelPayload;
export type PMResolveAuthMenuExternalAuthPayload = HostedAuthMenuExternalAuthResolution;

const DEFAULT_HOSTED_AUTH_MENU_COPY: HostedAuthMenuCopy = {
  login: {
    title: 'Sign in',
    subtitle: 'Continue with Passkey or Google SSO',
    passkeyCta: 'Sign in with Passkey',
  },
  register: {
    title: 'Create your account',
    subtitle: 'Continue with Passkey or Google SSO',
    passkeyNameLabel: 'Wallet name',
    passkeyCta: 'Sign up with Passkey',
  },
  common: { closeLabel: 'Close' },
};

function boundaryString(value: unknown, _field: string): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  return normalized ? normalized : null;
}

function brandedBoundaryString<T extends string>(value: unknown, field: string): T | null {
  const normalized = boundaryString(value, field);
  return normalized === null ? null : (normalized as T);
}

function requestIdFromBoundary(value: unknown): WalletIframeRequestId | null {
  try {
    return walletIframeRequestIdFromBoundary(value);
  } catch {
    return null;
  }
}

function hasOnlyKeys(record: Record<string, unknown>, allowedKeys: readonly string[]): boolean {
  const allowed = new Set(allowedKeys);
  return Object.keys(record).every((key) => allowed.has(key));
}

function positiveSafeSequence(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : null;
}

function boundedPositiveCssPx(value: unknown): number | null {
  return typeof value === 'number' &&
    Number.isFinite(value) &&
    value > 0 &&
    value <= WALLET_IFRAME_SURFACE_MEASUREMENT_MAX_CSS_PX
    ? value
    : null;
}

export function parseWalletIframeSurfaceMeasurement(
  value: unknown,
): WalletIframeSurfaceMeasurement | null {
  const record = recordFromBoundary(value);
  if (!record || !isWireSerializable(record)) return null;

  if (record.kind === 'measured_v1') {
    if (!hasOnlyKeys(record, ['kind', 'requestId', 'sequence', 'widthCssPx', 'heightCssPx'])) {
      return null;
    }
    const requestId = requestIdFromBoundary(record.requestId);
    const sequence = positiveSafeSequence(record.sequence);
    const widthCssPx = boundedPositiveCssPx(record.widthCssPx);
    const heightCssPx = boundedPositiveCssPx(record.heightCssPx);
    return requestId && sequence && widthCssPx && heightCssPx
      ? { kind: record.kind, requestId, sequence, widthCssPx, heightCssPx }
      : null;
  }

  if (record.kind === 'measured_auth_menu_v1') {
    if (
      !hasOnlyKeys(record, [
        'kind',
        'requestId',
        'authMenuSessionId',
        'sequence',
        'widthCssPx',
        'heightCssPx',
      ])
    ) {
      return null;
    }
    const requestId = requestIdFromBoundary(record.requestId);
    const authMenuSessionId = hostedAuthMenuSessionIdFromBoundary(record.authMenuSessionId);
    const sequence = positiveSafeSequence(record.sequence);
    const widthCssPx = boundedPositiveCssPx(record.widthCssPx);
    const heightCssPx = boundedPositiveCssPx(record.heightCssPx);
    return requestId && authMenuSessionId && sequence && widthCssPx && heightCssPx
      ? {
          kind: record.kind,
          requestId,
          authMenuSessionId,
          sequence,
          widthCssPx,
          heightCssPx,
        }
      : null;
  }

  return null;
}

export function hostedAuthMenuSessionIdFromBoundary(
  value: unknown,
): HostedAuthMenuSessionId | null {
  return brandedBoundaryString<HostedAuthMenuSessionId>(value, 'authMenuSessionId');
}

export function hostedAuthMenuExternalAuthRequestIdFromBoundary(
  value: unknown,
): HostedAuthMenuExternalAuthRequestId | null {
  return brandedBoundaryString<HostedAuthMenuExternalAuthRequestId>(value, 'externalAuthRequestId');
}

function recordFromBoundary(value: unknown): Record<string, unknown> | null {
  return isPlainObject(value) ? value : null;
}

function isWireSerializable(
  value: unknown,
  seen = new Set<unknown>(),
  allowUndefined = false,
): boolean {
  if (value === undefined) return allowUndefined;
  if (value === null) return true;
  if (typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value !== 'object') return false;
  if (seen.has(value)) return false;
  seen.add(value);
  if (Array.isArray(value)) {
    return value.every((entry) => isWireSerializable(entry, seen, allowUndefined));
  }
  const record = recordFromBoundary(value);
  return (
    record !== null &&
    Object.values(record).every((entry) => isWireSerializable(entry, seen, allowUndefined))
  );
}

function stringOrDefault(value: unknown, fallback: string): string {
  return boundaryString(value, 'copy') ?? fallback;
}

function normalizeModeCopy(raw: unknown, fallback: HostedAuthMenuModeCopy): HostedAuthMenuModeCopy {
  const record = recordFromBoundary(raw);
  return {
    title: stringOrDefault(record?.title, fallback.title),
    subtitle: stringOrDefault(record?.subtitle, fallback.subtitle),
    passkeyCta: stringOrDefault(record?.passkeyCta, fallback.passkeyCta),
  };
}

function normalizeHostedAuthMenuCopy(raw: unknown): HostedAuthMenuCopy {
  const record = recordFromBoundary(raw);
  const register = recordFromBoundary(record?.register);
  return {
    login: normalizeModeCopy(record?.login, DEFAULT_HOSTED_AUTH_MENU_COPY.login),
    register: {
      ...normalizeModeCopy(record?.register, DEFAULT_HOSTED_AUTH_MENU_COPY.register),
      passkeyNameLabel: stringOrDefault(
        register?.passkeyNameLabel,
        DEFAULT_HOSTED_AUTH_MENU_COPY.register.passkeyNameLabel,
      ),
    },
    common: {
      closeLabel: stringOrDefault(
        recordFromBoundary(record?.common)?.closeLabel,
        DEFAULT_HOSTED_AUTH_MENU_COPY.common.closeLabel,
      ),
    },
  };
}

function parseExternalProvider(value: unknown): HostedAuthMenuExternalProvider | null {
  return value === 'google' ? value : null;
}

function parseAuthMenuMode(value: unknown): HostedAuthMenuMode | null {
  return value === 'login' || value === 'register' ? value : null;
}

function parseRegistrationAccountInput(
  value: unknown,
): HostedAuthMenuRegistrationAccountInput | null {
  return value === 'implicit_wallet' || value === 'sponsored_named_near_account' ? value : null;
}

function parseHostedAuthMenuCancelReason(value: unknown): HostedAuthMenuCancelReason | null {
  return value === 'close_button' ||
    value === 'component_unmounted' ||
    value === 'connection_closed'
    ? value
    : null;
}

function parseHostedAuthMenuFailureCode(value: unknown): HostedAuthMenuFailureCode | null {
  switch (value) {
    case 'invalid_request':
    case 'unsupported_provider':
    case 'provider_error':
    case 'invalid_evidence':
    case 'webauthn_failed':
    case 'wallet_error':
    case 'timeout':
    case 'connection_closed':
    case 'internal_error':
      return value;
    default:
      return null;
  }
}

function hasOnlyOptionalRecordKeys(value: unknown, allowedKeys: readonly string[]): boolean {
  if (value === undefined) return true;
  const record = recordFromBoundary(value);
  return record !== null && hasOnlyKeys(record, allowedKeys);
}

function hasOnlyHostedAuthMenuCopyKeys(value: unknown): boolean {
  const copy = recordFromBoundary(value);
  if (!copy) return false;
  if (!hasOnlyKeys(copy, ['login', 'register', 'common'])) return false;
  return (
    hasOnlyOptionalRecordKeys(copy.login, ['title', 'subtitle', 'passkeyCta']) &&
    hasOnlyOptionalRecordKeys(copy.register, [
      'title',
      'subtitle',
      'passkeyCta',
      'passkeyNameLabel',
    ]) &&
    hasOnlyOptionalRecordKeys(copy.common, ['closeLabel'])
  );
}

function parseExternalProviders(value: unknown): HostedAuthMenuExternalProvider[] | null {
  if (!Array.isArray(value)) return null;
  const providers: HostedAuthMenuExternalProvider[] = [];
  for (const entry of value) {
    const provider = parseExternalProvider(entry);
    if (!provider) return null;
    providers.push(provider);
  }
  return providers;
}

export function parseHostedAuthMenuOpenRequest(value: unknown): HostedAuthMenuOpenRequest | null {
  const record = recordFromBoundary(value);
  if (
    !record ||
    !isWireSerializable(record, new Set<unknown>(), true) ||
    record.kind !== 'hosted_auth_menu_open_v1' ||
    !hasOnlyKeys(record, [
      'kind',
      'authMenuSessionId',
      'initialMode',
      'registrationAccountInput',
      'showRegistrationInput',
      'showProgress',
      'copy',
      'enabledExternalProviders',
    ]) ||
    !hasOnlyHostedAuthMenuCopyKeys(record.copy)
  ) {
    return null;
  }
  const authMenuSessionId = hostedAuthMenuSessionIdFromBoundary(record.authMenuSessionId);
  const initialMode = parseAuthMenuMode(record.initialMode);
  const registrationAccountInput = parseRegistrationAccountInput(record.registrationAccountInput);
  const providers = parseExternalProviders(record.enabledExternalProviders);
  if (
    !authMenuSessionId ||
    !initialMode ||
    !registrationAccountInput ||
    typeof record.showRegistrationInput !== 'boolean' ||
    typeof record.showProgress !== 'boolean' ||
    !providers ||
    !isWireSerializable(record.copy, new Set<unknown>(), true)
  ) {
    return null;
  }
  return {
    kind: 'hosted_auth_menu_open_v1',
    authMenuSessionId,
    initialMode,
    registrationAccountInput,
    showRegistrationInput: record.showRegistrationInput,
    showProgress: record.showProgress,
    copy: normalizeHostedAuthMenuCopy(record.copy),
    enabledExternalProviders: providers,
  };
}

export function buildHostedAuthMenuOpenRequest(args: {
  authMenuSessionId: HostedAuthMenuSessionId;
  initialMode?: HostedAuthMenuMode;
  registrationAccountInput?: HostedAuthMenuRegistrationAccountInput;
  showRegistrationInput?: boolean;
  showProgress?: boolean;
  copy?: HostedAuthMenuCopyInput;
  enabledExternalProviders?: readonly HostedAuthMenuExternalProvider[];
}): HostedAuthMenuOpenRequest {
  if (!isWireSerializable(args, new Set<unknown>(), true)) {
    throw new Error('Hosted auth-menu open configuration must be serializable');
  }
  const argsRecord = recordFromBoundary(args);
  if (
    !argsRecord ||
    !hasOnlyKeys(argsRecord, [
      'authMenuSessionId',
      'initialMode',
      'registrationAccountInput',
      'showRegistrationInput',
      'showProgress',
      'copy',
      'enabledExternalProviders',
    ]) ||
    (args.copy !== undefined && !hasOnlyHostedAuthMenuCopyKeys(args.copy))
  ) {
    throw new Error('Hosted auth-menu open configuration contains unsupported fields');
  }
  const parsedSessionId = hostedAuthMenuSessionIdFromBoundary(args.authMenuSessionId);
  if (!parsedSessionId) throw new Error('authMenuSessionId must be a non-empty string');
  const request: HostedAuthMenuOpenRequest = {
    kind: 'hosted_auth_menu_open_v1',
    authMenuSessionId: parsedSessionId,
    initialMode: args.initialMode ?? 'login',
    registrationAccountInput: args.registrationAccountInput ?? 'implicit_wallet',
    showRegistrationInput: args.showRegistrationInput ?? false,
    showProgress: args.showProgress ?? false,
    copy: normalizeHostedAuthMenuCopy(args.copy),
    enabledExternalProviders: [...(args.enabledExternalProviders ?? [])],
  };
  if (!parseHostedAuthMenuOpenRequest(request)) {
    throw new Error('Hosted auth-menu open request is invalid');
  }
  return Object.freeze(request);
}

export function parseHostedAuthMenuExternalAuthRequest(
  value: unknown,
): HostedAuthMenuExternalAuthRequest | null {
  const record = recordFromBoundary(value);
  if (
    !record ||
    !isWireSerializable(record) ||
    record.kind !== 'hosted_auth_menu_external_auth_request_v1' ||
    !hasOnlyKeys(record, ['kind', 'authMenuSessionId', 'externalAuthRequestId', 'provider', 'mode'])
  ) {
    return null;
  }
  const authMenuSessionId = hostedAuthMenuSessionIdFromBoundary(record.authMenuSessionId);
  const externalAuthRequestId = hostedAuthMenuExternalAuthRequestIdFromBoundary(
    record.externalAuthRequestId,
  );
  const provider = parseExternalProvider(record.provider);
  const mode = parseAuthMenuMode(record.mode);
  if (!authMenuSessionId || !externalAuthRequestId || !provider || !mode) return null;
  return { kind: record.kind, authMenuSessionId, externalAuthRequestId, provider, mode };
}

export function parseHostedAuthMenuDemoEmailOtpDelivery(
  value: unknown,
): HostedAuthMenuDemoEmailOtpDelivery | null {
  const record = recordFromBoundary(value);
  if (
    !record ||
    !isWireSerializable(record) ||
    record.kind !== 'hosted_auth_menu_demo_email_otp_delivery_v1' ||
    !hasOnlyKeys(record, ['kind', 'authMenuSessionId', 'delivery'])
  ) {
    return null;
  }
  const authMenuSessionId = hostedAuthMenuSessionIdFromBoundary(record.authMenuSessionId);
  const delivery = recordFromBoundary(record.delivery);
  if (
    !authMenuSessionId ||
    !delivery ||
    !hasOnlyKeys(delivery, ['kind', 'status', 'emailHint', 'otpCode']) ||
    (delivery.kind !== 'demo_code_response' && delivery.kind !== 'provider_and_demo_code') ||
    (delivery.status !== 'sent' && delivery.status !== 'reused')
  ) {
    return null;
  }
  const emailHint = boundaryString(delivery.emailHint, 'emailHint');
  const otpCode = boundaryString(delivery.otpCode, 'otpCode');
  if (!emailHint || !otpCode || !/^\d{6}$/.test(otpCode)) return null;
  return {
    kind: record.kind,
    authMenuSessionId,
    delivery: { kind: delivery.kind, status: delivery.status, emailHint, otpCode },
  };
}

function parseExternalAuthEvidence(value: unknown): HostedAuthMenuExternalAuthEvidence | null {
  const record = recordFromBoundary(value);
  if (!record || !isWireSerializable(record)) return null;
  switch (record.kind) {
    case 'google_id_token': {
      if (!hasOnlyKeys(record, ['kind', 'idToken'])) return null;
      const idToken = boundaryString(record.idToken, 'idToken');
      return idToken ? { kind: record.kind, idToken } : null;
    }
    case 'cancelled':
      if (!hasOnlyKeys(record, ['kind', 'reason'])) return null;
      return record.reason === 'user_cancelled'
        ? { kind: record.kind, reason: record.reason }
        : null;
    case 'failed': {
      if (!hasOnlyKeys(record, ['kind', 'code', 'message'])) return null;
      const code =
        record.code === 'provider_unavailable' ||
        record.code === 'provider_error' ||
        record.code === 'invalid_evidence'
          ? record.code
          : null;
      const message = boundaryString(record.message, 'message');
      return code && message ? { kind: record.kind, code, message } : null;
    }
    default:
      return null;
  }
}

export function parseHostedAuthMenuExternalAuthResolution(
  value: unknown,
): HostedAuthMenuExternalAuthResolution | null {
  const record = recordFromBoundary(value);
  if (
    !record ||
    !isWireSerializable(record) ||
    record.kind !== 'hosted_auth_menu_external_auth_resolution_v1' ||
    !hasOnlyKeys(record, [
      'kind',
      'authMenuSessionId',
      'externalAuthRequestId',
      'requestId',
      'evidence',
    ])
  ) {
    return null;
  }
  const authMenuSessionId = hostedAuthMenuSessionIdFromBoundary(record.authMenuSessionId);
  const externalAuthRequestId = hostedAuthMenuExternalAuthRequestIdFromBoundary(
    record.externalAuthRequestId,
  );
  const requestId = requestIdFromBoundary(record.requestId);
  const evidence = parseExternalAuthEvidence(record.evidence);
  if (!authMenuSessionId || !externalAuthRequestId || !requestId || !evidence) return null;
  return { kind: record.kind, authMenuSessionId, externalAuthRequestId, requestId, evidence };
}

export function buildHostedAuthMenuExternalAuthResolution(args: {
  authMenuSessionId: HostedAuthMenuSessionId;
  externalAuthRequestId: HostedAuthMenuExternalAuthRequestId;
  requestId: WalletIframeRequestId;
  evidence: HostedAuthMenuExternalAuthEvidence;
}): HostedAuthMenuExternalAuthResolution {
  const resolution: HostedAuthMenuExternalAuthResolution = {
    kind: 'hosted_auth_menu_external_auth_resolution_v1',
    authMenuSessionId: args.authMenuSessionId,
    externalAuthRequestId: args.externalAuthRequestId,
    requestId: args.requestId,
    evidence: args.evidence,
  };
  if (!parseHostedAuthMenuExternalAuthResolution(resolution)) {
    throw new Error('Hosted auth-menu external-auth resolution is invalid');
  }
  return Object.freeze(resolution);
}

export function parseHostedAuthMenuCancelPayload(
  value: unknown,
): HostedAuthMenuCancelPayload | null {
  const record = recordFromBoundary(value);
  if (
    !record ||
    !isWireSerializable(record) ||
    record.kind !== 'hosted_auth_menu_cancel_v1' ||
    !hasOnlyKeys(record, ['kind', 'authMenuSessionId', 'requestId', 'reason'])
  ) {
    return null;
  }
  const authMenuSessionId = hostedAuthMenuSessionIdFromBoundary(record.authMenuSessionId);
  const requestId = requestIdFromBoundary(record.requestId);
  const reason = parseHostedAuthMenuCancelReason(record.reason);
  return authMenuSessionId && requestId && reason
    ? { kind: record.kind, authMenuSessionId, requestId, reason }
    : null;
}

export function buildHostedAuthMenuCancelPayload(args: {
  authMenuSessionId: HostedAuthMenuSessionId;
  requestId: WalletIframeRequestId;
  reason: HostedAuthMenuCancelReason;
}): HostedAuthMenuCancelPayload {
  const payload: HostedAuthMenuCancelPayload = {
    kind: 'hosted_auth_menu_cancel_v1',
    authMenuSessionId: args.authMenuSessionId,
    requestId: args.requestId,
    reason: args.reason,
  };
  if (!parseHostedAuthMenuCancelPayload(payload)) {
    throw new Error('Hosted auth-menu cancellation is invalid');
  }
  return Object.freeze(payload);
}

export function parseHostedAuthMenuOutcome(value: unknown): HostedAuthMenuOutcome | null {
  const record = recordFromBoundary(value);
  if (!record || !isWireSerializable(record)) return null;
  const authMenuSessionId = hostedAuthMenuSessionIdFromBoundary(record.authMenuSessionId);
  if (!authMenuSessionId) return null;
  switch (record.kind) {
    case 'authenticated':
    case 'registered': {
      if (!hasOnlyKeys(record, ['kind', 'authMenuSessionId', 'walletId', 'method'])) return null;
      const walletId = parseWalletId(record.walletId);
      const method =
        record.method === 'passkey' || record.method === 'google_email_otp' ? record.method : null;
      return walletId.ok && method
        ? { kind: record.kind, authMenuSessionId, walletId: walletId.value, method }
        : null;
    }
    case 'account_synced': {
      if (!hasOnlyKeys(record, ['kind', 'authMenuSessionId', 'walletId'])) return null;
      const walletId = parseWalletId(record.walletId);
      return walletId.ok
        ? { kind: record.kind, authMenuSessionId, walletId: walletId.value }
        : null;
    }
    case 'cancelled': {
      if (!hasOnlyKeys(record, ['kind', 'authMenuSessionId', 'reason'])) return null;
      const reason = parseHostedAuthMenuCancelReason(record.reason);
      return reason ? { kind: record.kind, authMenuSessionId, reason } : null;
    }
    case 'failed': {
      if (!hasOnlyKeys(record, ['kind', 'authMenuSessionId', 'code', 'message'])) return null;
      const message = boundaryString(record.message, 'message');
      const code = parseHostedAuthMenuFailureCode(record.code);
      return code && message ? { kind: record.kind, authMenuSessionId, code, message } : null;
    }
    default:
      return null;
  }
}

export const WALLET_PROTOCOL_VERSION = '1.0.0' as const;

export type WalletProtocolVersion = typeof WALLET_PROTOCOL_VERSION;

export type ParentToChildType =
  | 'PING'
  | 'PM_SET_CONFIG'
  | 'PM_CANCEL'
  | 'PM_OPEN_AUTH_MENU'
  | 'PM_CANCEL_AUTH_MENU'
  | 'PM_RESOLVE_AUTH_MENU_EXTERNAL_AUTH'
  | 'PM_REDEEM_HOSTED_WALLET_SEAMS_SESSION'
  // SeamsWeb API surface
  | 'PM_REGISTER_WALLET'
  | 'PM_ADD_WALLET_SIGNER'
  | 'PM_ADD_PASSKEY'
  | 'PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION'
  | 'PM_UNLOCK'
  | 'PM_LOCK'
  | 'PM_LOCK_EXACT_WALLET_SESSION'
  | 'PM_GET_WALLET_SESSION'
  | 'PM_GET_EXACT_WALLET_SESSION_STATE'
  | 'PM_GET_NEAR_PROVISIONING_STATE'
  | 'PM_REQUEST_EMAIL_OTP_CHALLENGE'
  | 'PM_REQUEST_EMAIL_OTP_ENROLLMENT_CHALLENGE'
  | 'PM_REQUEST_EMAIL_OTP_SIGNING_SESSION_CHALLENGE'
  | 'PM_EXCHANGE_GOOGLE_EMAIL_OTP_SESSION'
  | 'PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_RESEND'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_REROLL_WALLET_ID'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_CANCEL'
  | 'PM_ENROLL_EMAIL_OTP'
  | 'PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY'
  | 'PM_REFRESH_EMAIL_OTP_SIGNING_SESSION'
  | 'PM_GET_WALLET_RECOVERY_CODE_STATUS'
  | 'PM_ACKNOWLEDGE_WALLET_RECOVERY_CODE_BACKUP'
  | 'PM_ROTATE_WALLET_RECOVERY_CODES'
  | 'PM_REQUEST_WALLET_RECOVERY_BOOTSTRAP_CHALLENGE'
  | 'PM_VERIFY_WALLET_RECOVERY_BOOTSTRAP'
  | 'PM_PREPARE_WALLET_RECOVERY_WITH_BOOTSTRAP'
  | 'PM_COMPLETE_WALLET_RECOVERY'
  | 'PM_GET_RECOVERY_EMAILS'
  | 'PM_SET_RECOVERY_EMAILS'
  | 'PM_SIGN_TX_WITH_ACTIONS'
  | 'PM_SIGN_AND_SEND_TX'
  | 'PM_FUND_IMPLICIT_NEAR_ACCOUNT_FOR_TESTING'
  | 'PM_SEND_TRANSACTION'
  | 'PM_EXECUTE_ACTION'
  | 'PM_SIGN_DELEGATE_ACTION'
  | 'PM_SIGN_NEP413'
  | 'PM_SIGN_TEMPO'
  | 'PM_REPORT_TEMPO_BROADCAST_ACCEPTED'
  | 'PM_REPORT_TEMPO_BROADCAST_REJECTED'
  | 'PM_REPORT_TEMPO_FINALIZED'
  | 'PM_REPORT_TEMPO_DROPPED_OR_REPLACED'
  | 'PM_RECONCILE_TEMPO_NONCE_LANE'
  | 'PM_RESOLVE_EXACT_KEY_EXPORT_LANE'
  | 'PM_EXPORT_KEYPAIR_UI'
  | 'PM_GET_RECENT_UNLOCKS'
  | 'PM_PREFETCH_BLOCKHEIGHT'
  | 'PM_PREFILL_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL'
  | 'PM_SET_CONFIRM_BEHAVIOR'
  | 'PM_SET_CONFIRMATION_CONFIG'
  | 'PM_GET_CONFIRMATION_CONFIG'
  | 'PM_HAS_PASSKEY'
  | 'PM_VIEW_ACCESS_KEYS'
  | 'PM_DELETE_DEVICE_KEY'
  | 'PM_LIST_WALLET_CREDENTIALS'
  | 'PM_RENAME_WALLET_CREDENTIAL'
  | 'PM_REVOKE_WALLET_CREDENTIAL'
  | 'PM_LINK_DEVICE_WITH_SCANNED_QR_DATA'
  | 'PM_START_DEVICE2_LINKING_FLOW'
  | 'PM_STOP_DEVICE2_LINKING_FLOW'
  | 'PM_SYNC_ACCOUNT_FLOW';

export type ChildToParentType =
  | 'READY'
  | 'PONG'
  | 'PROGRESS'
  | 'SDK_LIFECYCLE_EVENT'
  | 'PREFERENCES_CHANGED'
  | 'AUTH_MENU_EXTERNAL_AUTH_REQUEST'
  | 'SURFACE_MEASUREMENT'
  | 'PM_RESULT'
  | 'ERROR';

export interface RpcEnvelope<T extends string = string, P = unknown> {
  type: T;
  requestId?: string;
  payload?: P;
  options?: {
    onProgress?(payload: ProgressPayload): void;
    sticky?: boolean;
  };
}

// ===== Payloads =====

export interface ReadyPayload {
  protocolVersion: WalletProtocolVersion;
}

export interface PreferencesChangedPayload {
  walletId: string | null;
  confirmationConfig: ConfirmationConfig;
  updatedAt: number;
}

export interface PMSetConfigPayload extends Partial<SeamsConfigsInput> {
  // Absolute base URL for SDK Lit component assets (e.g., https://app.example.com/sdk/)
  assetsBaseUrl?: string;
  // Optional: register wallet-host UI components (Lit tags + bindings)
  uiRegistry?: WalletUIRegistry;
}

export interface PMCancelPayload {
  requestId?: string; // when omitted, host may attempt best-effort global cancel (close UIs)
}

export interface PMRedeemHostedWalletSeamsSessionPayload {
  exchangeCode: string;
  nonce: string;
  relayUrl: string;
}

type PMEmailOtpChallengeRegistrationAuthMethod = Omit<
  Extract<EmailOtpRegistrationAuthMethodInput, { proofKind: 'otp_challenge' }>,
  'appSessionJwt'
> & {
  appSessionJwt?: never;
};

type PMGoogleSsoRegistrationAuthMethod = Omit<
  Extract<EmailOtpRegistrationAuthMethodInput, { proofKind: 'google_sso_registration' }>,
  'appSessionJwt'
> & {
  appSessionJwt?: never;
};

export type PMRegistrationAuthMethodInput =
  | PasskeyRegistrationAuthMethodInput
  | PMEmailOtpChallengeRegistrationAuthMethod
  | PMGoogleSsoRegistrationAuthMethod;

export interface PMRegisterWalletPayload {
  authMethod: PMRegistrationAuthMethodInput;
  wallet: RegisterWalletInput;
  signerSelection: RegistrationSignerSetSelection;
  confirmationConfig?: Partial<ConfirmationConfig>;
  options?: Record<string, unknown>;
}

export interface PMAddWalletSignerPayload {
  walletId: WalletId | string;
  rpId: string;
  signerSelection: AddSignerSelection;
  confirmationConfig?: Partial<ConfirmationConfig>;
  options?: Record<string, unknown>;
}

export interface PMAddPasskeyPayload {
  walletId: WalletId | string;
  rpId: string;
  authorization: AddPasskeyAuthorization;
  confirmationConfig?: Partial<ConfirmationConfig>;
  options?: Record<string, unknown>;
}

export type PMGoogleEmailOtpWalletAuthStartPayload = {
  idToken: string;
  mode: GoogleEmailOtpWalletAuthRequestedMode;
  relayUrl?: string;
  sessionKind?: 'jwt' | 'cookie';
  ecdsaTargets?: GoogleEmailOtpWalletAuthEcdsaTargets;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  diagnostics: {
    emailOtpUnlockTimings: boolean;
    registrationBenchmarkTimings: boolean;
  };
};

export type PMGoogleEmailOtpWalletAuthHandlePayload = {
  flowHandleId: string;
  flowId: string;
  walletId: string;
  mode: GoogleEmailOtpWalletAuthResolvedMode;
};

export type PMGoogleEmailOtpWalletAuthSubmitPayload = PMGoogleEmailOtpWalletAuthHandlePayload & {
  otpCode: string;
};

export type PMGoogleEmailOtpWalletAuthRegistrationWireFlow = {
  kind: 'google_email_otp_wallet_auth_flow_v1';
  state: 'registration_ready';
  flowHandleId: string;
  flowId: string;
  requestedMode: GoogleEmailOtpWalletAuthRequestedMode;
  mode: 'register';
  walletId: string;
  emailHint: string;
  prompt: GoogleEmailOtpWalletAuthPromptCopy;
  expiresAtMs: number;
};

export type PMGoogleEmailOtpWalletAuthLoginWireFlow = {
  kind: 'google_email_otp_wallet_auth_flow_v1';
  state: 'challenge_sent';
  flowHandleId: string;
  flowId: string;
  requestedMode: GoogleEmailOtpWalletAuthRequestedMode;
  mode: 'login';
  walletId: string;
  emailHint: string;
  prompt: GoogleEmailOtpWalletAuthPromptCopy;
  delivery: GoogleEmailOtpWalletAuthDelivery;
  expiresAtMs: number;
};

export type PMGoogleEmailOtpWalletAuthWireFlow =
  | PMGoogleEmailOtpWalletAuthRegistrationWireFlow
  | PMGoogleEmailOtpWalletAuthLoginWireFlow;

export type PMGoogleEmailOtpWalletAuthWireResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: GoogleEmailOtpWalletAuthFailure };

export type PMGoogleEmailOtpWalletAuthRegistrationWireResult =
  PMGoogleEmailOtpWalletAuthWireResult<PMGoogleEmailOtpWalletAuthRegistrationWireFlow>;

export type PMGoogleEmailOtpWalletAuthSubmitWireResult =
  PMGoogleEmailOtpWalletAuthWireResult<GoogleEmailOtpWalletAuthSubmitSuccess>;

export type PMGoogleEmailOtpWalletAuthCompleteRegistrationWireResult =
  PMGoogleEmailOtpWalletAuthWireResult<GoogleEmailOtpWalletAuthRegistrationCompleted>;

export interface PMSignTxPayload {
  walletId: string;
  nearAccountId: string;
  transaction: TransactionInput;
  options: {
    signerSlot?: number;
    confirmationConfig?: Partial<ConfirmationConfig>;
    confirmerText?: { title?: string; body?: string };
    [key: string]: unknown;
  };
}

export interface PMSignAndSendTxPayload {
  walletId: string;
  nearAccountId: string;
  transaction: TransactionInput;
  options: {
    signerSlot?: number;
    // Keep only serializable fields; functions are bridged via PROGRESS
    waitUntil?:
      | 'NONE'
      | 'INCLUDED'
      | 'INCLUDED_FINAL'
      | 'EXECUTED'
      | 'FINAL'
      | 'EXECUTED_OPTIMISTIC';
    confirmationConfig?: Partial<ConfirmationConfig>;
    confirmerText?: { title?: string; body?: string };
    [key: string]: unknown;
  };
}

export interface PMFundImplicitNearAccountForTestingPayload {
  walletId: string;
  nearAccountId: string;
  nearPublicKey: string;
}

export interface PMSendTxPayload {
  walletId: string;
  nearAccountId: string;
  signedTransaction: SignedTransaction; // SignedTransaction-like
  options?: Record<string, unknown>;
}

export interface PMExecuteActionPayload {
  walletId: string;
  nearAccountId: string;
  receiverId: string;
  actionArgs: ActionArgs | ActionArgs[];
  options: {
    waitUntil?: unknown;
    signerSlot?: number;
    confirmationConfig?: Partial<ConfirmationConfig>;
    confirmerText?: { title?: string; body?: string };
    [key: string]: unknown;
  };
}

export interface PMSignDelegateActionPayload {
  walletId: string;
  nearAccountId: string;
  delegate: DelegateActionInput;
  options: {
    signerSlot?: number;
    confirmationConfig?: Partial<ConfirmationConfig>;
    confirmerText?: { title?: string; body?: string };
    [key: string]: unknown;
  };
}

export interface PMSignNep413Payload {
  walletId: string;
  nearAccountId: string;
  params: { message: string; recipient: string; state?: string };
  options: {
    signerSlot?: number;
    confirmationConfig?: Partial<ConfirmationConfig>;
    confirmerText?: { title?: string; body?: string };
    [key: string]: unknown;
  };
}

type PMSignTempoPayloadBase = {
  walletSession: WalletSessionRef;
  options?: {
    confirmationConfig?: Partial<ConfirmationConfig>;
  };
};

export type PMSignTempoPayload =
  | (PMSignTempoPayloadBase & {
      operationKind: 'tempo_transaction';
      request: TempoSigningRequest;
      chainTarget: TempoChainTarget;
    })
  | (PMSignTempoPayloadBase & {
      operationKind: 'evm_transaction';
      request: EvmSigningRequest;
      chainTarget: EvmEip155ChainTarget;
    })
  | (PMSignTempoPayloadBase & {
      operationKind: 'tempo_fee_token_preference';
      request: TempoFeeTokenPreferenceSigningRequest;
      chainTarget: TempoChainTarget;
    });

export interface PMTempoNonceLifecyclePayloadBase {
  walletSession: WalletSessionRef;
  signedResult: TempoSignedResult | EvmSignedResult;
}

export interface PMReportTempoBroadcastAcceptedPayload extends PMTempoNonceLifecyclePayloadBase {
  txHash: `0x${string}`;
}

export interface PMReportTempoBroadcastRejectedPayload extends PMTempoNonceLifecyclePayloadBase {
  error?: {
    code?: string;
    message?: string;
    details?: unknown;
  };
}

export interface PMReportTempoFinalizedPayload extends PMTempoNonceLifecyclePayloadBase {
  txHash?: `0x${string}`;
  receiptStatus?: 'success' | 'reverted';
}

export interface PMReportTempoDroppedOrReplacedPayload extends PMTempoNonceLifecyclePayloadBase {
  reason: 'dropped' | 'replaced';
  txHash?: `0x${string}`;
}

export type PMReconcileTempoNonceLanePayload = PMTempoNonceLifecyclePayloadBase;

export type PMResolveExactKeyExportLanePayload = ResolveExactKeyExportLaneInput;

type PMExportKeypairUiOptions = {
  variant?: 'modal' | 'drawer';
  theme?: 'dark' | 'light';
};

export type PMExportKeypairUiPayload =
  | {
      kind: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
      walletSession: WalletSessionRef;
      laneIdentity: unknown;
      nearAccount?: never;
      options: PMExportKeypairUiOptions;
    }
  | {
      kind: 'ed25519';
      nearAccount: NearAccountRef;
      walletSession: WalletSessionRef;
      laneIdentity: unknown;
      materialActivation: MpcMaterialActivationRef;
      chainTarget?: never;
      options: PMExportKeypairUiOptions;
    };

export interface PMSetConfirmBehaviorPayload {
  behavior: 'requireClick' | 'skipClick';
  walletId?: string;
}

export interface PMSetConfirmationConfigPayload {
  config: Partial<ConfirmationConfig>;
  walletId?: string;
}

export interface PMGetWalletSessionPayload {
  walletId?: string;
}

export type PMGetExactWalletSessionStatePayload =
  | {
      readonly authenticationRead: 'restore';
      readonly wallet: { readonly kind: 'current' };
    }
  | {
      readonly authenticationRead: 'current';
      readonly wallet:
        | { readonly kind: 'current' }
        | { readonly kind: 'exact'; readonly walletId: string };
    };

export interface PMEmailOtpChallengePayload {
  walletId: string;
  relayUrl?: string;
  operation?: WalletEmailOtpLoginOperation;
}

export interface PMEmailOtpSigningSessionChallengePayload {
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
}

export interface PMExchangeGoogleEmailOtpSessionPayload {
  idToken: string;
  accountMode: 'register' | 'login';
  relayUrl?: string;
  sessionKind?: 'jwt' | 'cookie';
}

export interface PMEnrollEmailOtpPayload {
  walletId: string;
  otpCode: string;
  relayUrl?: string;
  challengeId?: string;
  groupId?: string;
  appSessionJwt?: never;
}

export interface PMWalletRecoverySessionPayload {
  walletId: string;
}

export interface PMRotateWalletRecoveryCodesPayload extends PMWalletRecoverySessionPayload {
  authorization: WalletRecoveryRotationAuthorization;
}

export interface PMRequestWalletRecoveryBootstrapChallengePayload {
  walletId: string;
  orgId: string;
  relayUrl?: string;
}

export interface PMVerifyWalletRecoveryBootstrapPayload {
  walletId: string;
  orgId: string;
  challengeId: string;
  otpCode: string;
  relayUrl?: string;
}

export interface PMPrepareWalletRecoveryWithBootstrapPayload {
  walletId: string;
  orgId: string;
  challengeId: string;
  recoveryBootstrapGrant: string;
  replacedCredentialIdB64u: string;
  recoveryCode: string;
  relayUrl?: string;
}

export interface PMCompleteWalletRecoveryPayload {
  walletId: string;
  recoveryOperationId: string;
  relayUrl?: string;
}

export interface PMEmailOtpEcdsaCapabilityPayload {
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
  publicationChainTargets?: readonly ThresholdEcdsaChainTarget[];
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  relayUrl?: string;
  challengeId?: string;
  otpCode: string;
  groupId?: string;
  appSessionJwt?: never;
  registrationAttemptId?: string;
  emailOtpAuthorityEmail?: string;
}

export interface PMRefreshEmailOtpSigningSessionPayload {
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
  ttlMs?: number;
  remainingUses?: number;
}

export interface PMPrefillRouterAbEcdsaDerivationPresignaturePoolPayload {
  walletSession: WalletSessionRef;
  options: {
    chainTarget: ThresholdEcdsaChainTarget;
    waitForPoolReady?: boolean;
    poolReadyTimeoutMs?: number;
    poolReadyPollIntervalMs?: number;
    minRemainingUsesBeforePrefill?: number;
  };
}

export interface PMHasPasskeyPayload {
  walletId: string;
}

export interface PMViewAccessKeysPayload {
  walletId: string;
  nearAccountId: string;
}

export interface PMDeleteDeviceKeyPayload {
  walletId: string;
  nearAccountId: string;
  publicKeyToDelete: string;
  options: {
    [key: string]: unknown;
  };
}

export interface PMListWalletCredentialsPayload {
  walletId: string;
}

export interface PMRenameWalletCredentialPayload {
  walletId: string;
  envelopeId: string;
  label?: string;
}

export interface PMRevokeWalletCredentialPayload {
  walletId: string;
  rpId: string;
  credentialIdB64u: string;
}

export interface PMGetRecoveryEmailsPayload {
  walletId: string;
}

export interface PMSetRecoveryEmailsPayload {
  walletId: string;
  recoveryEmails: string[];
  options: {
    waitUntil?: unknown;
    confirmationConfig?: Partial<ConfirmationConfig>;
    [key: string]: unknown;
  };
}

export type ProgressPayload = WalletFlowEvent | RegistrationTimingSpanV1;

export function isRegistrationTimingSpanV1(value: unknown): value is RegistrationTimingSpanV1 {
  if (!isPlainObject(value)) return false;
  const span = value;
  return (
    span.event === 'seams_registration_timing_span_v1' &&
    (span.span === 'registration.post_touch_id' || span.span === 'frontend.wallet_ready') &&
    span.operation === 'registration' &&
    (span.outcome === 'success' || span.outcome === 'failure') &&
    typeof span.duration_ms === 'number' &&
    Number.isFinite(span.duration_ms) &&
    typeof span.trace_id === 'string' &&
    /^[0-9a-f]{32}$/.test(span.trace_id)
  );
}

export interface PMResultPayload {
  ok: boolean;
  result?: unknown;
  error?: string;
}

export type PMGetNearProvisioningStatePayload = {
  walletId: string;
};

export interface ErrorPayload {
  code: string;
  message: string;
  details?: unknown;
}

export type ParentToChildEnvelope =
  | RpcEnvelope<'PING'>
  | RpcEnvelope<'PM_SET_CONFIG', PMSetConfigPayload>
  | RpcEnvelope<'PM_CANCEL', PMCancelPayload>
  | RpcEnvelope<'PM_OPEN_AUTH_MENU', PMOpenAuthMenuPayload>
  | RpcEnvelope<'PM_CANCEL_AUTH_MENU', PMCancelAuthMenuPayload>
  | RpcEnvelope<'PM_RESOLVE_AUTH_MENU_EXTERNAL_AUTH', PMResolveAuthMenuExternalAuthPayload>
  | RpcEnvelope<'PM_REDEEM_HOSTED_WALLET_SEAMS_SESSION', PMRedeemHostedWalletSeamsSessionPayload>
  | RpcEnvelope<'PM_REGISTER_WALLET', PMRegisterWalletPayload>
  | RpcEnvelope<'PM_ADD_WALLET_SIGNER', PMAddWalletSignerPayload>
  | RpcEnvelope<'PM_ADD_PASSKEY', PMAddPasskeyPayload>
  | RpcEnvelope<'PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION', BootstrapThresholdEcdsaSessionArgs>
  | RpcEnvelope<'PM_UNLOCK', PMUnlockPayload>
  | RpcEnvelope<'PM_LOCK'>
  | RpcEnvelope<'PM_LOCK_EXACT_WALLET_SESSION', WalletIframeExactSessionIdentity>
  | RpcEnvelope<'PM_GET_WALLET_SESSION', PMGetWalletSessionPayload>
  | RpcEnvelope<'PM_GET_EXACT_WALLET_SESSION_STATE', PMGetExactWalletSessionStatePayload>
  | RpcEnvelope<'PM_GET_NEAR_PROVISIONING_STATE', PMGetNearProvisioningStatePayload>
  | RpcEnvelope<'PM_REQUEST_EMAIL_OTP_CHALLENGE', PMEmailOtpChallengePayload>
  | RpcEnvelope<'PM_REQUEST_EMAIL_OTP_ENROLLMENT_CHALLENGE', PMEmailOtpChallengePayload>
  | RpcEnvelope<
      'PM_REQUEST_EMAIL_OTP_SIGNING_SESSION_CHALLENGE',
      PMEmailOtpSigningSessionChallengePayload
    >
  | RpcEnvelope<'PM_EXCHANGE_GOOGLE_EMAIL_OTP_SESSION', PMExchangeGoogleEmailOtpSessionPayload>
  | RpcEnvelope<'PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH', PMGoogleEmailOtpWalletAuthStartPayload>
  | RpcEnvelope<'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_RESEND', PMGoogleEmailOtpWalletAuthHandlePayload>
  | RpcEnvelope<
      'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_REROLL_WALLET_ID',
      PMGoogleEmailOtpWalletAuthHandlePayload
    >
  | RpcEnvelope<'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT', PMGoogleEmailOtpWalletAuthSubmitPayload>
  | RpcEnvelope<
      'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION',
      PMGoogleEmailOtpWalletAuthHandlePayload
    >
  | RpcEnvelope<'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_CANCEL', PMGoogleEmailOtpWalletAuthHandlePayload>
  | RpcEnvelope<'PM_ENROLL_EMAIL_OTP', PMEnrollEmailOtpPayload>
  | RpcEnvelope<'PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY', PMEmailOtpEcdsaCapabilityPayload>
  | RpcEnvelope<'PM_REFRESH_EMAIL_OTP_SIGNING_SESSION', PMRefreshEmailOtpSigningSessionPayload>
  | RpcEnvelope<'PM_GET_WALLET_RECOVERY_CODE_STATUS', PMWalletRecoverySessionPayload>
  | RpcEnvelope<'PM_ACKNOWLEDGE_WALLET_RECOVERY_CODE_BACKUP', PMWalletRecoverySessionPayload>
  | RpcEnvelope<'PM_ROTATE_WALLET_RECOVERY_CODES', PMRotateWalletRecoveryCodesPayload>
  | RpcEnvelope<
      'PM_REQUEST_WALLET_RECOVERY_BOOTSTRAP_CHALLENGE',
      PMRequestWalletRecoveryBootstrapChallengePayload
    >
  | RpcEnvelope<'PM_VERIFY_WALLET_RECOVERY_BOOTSTRAP', PMVerifyWalletRecoveryBootstrapPayload>
  | RpcEnvelope<
      'PM_PREPARE_WALLET_RECOVERY_WITH_BOOTSTRAP',
      PMPrepareWalletRecoveryWithBootstrapPayload
    >
  | RpcEnvelope<'PM_COMPLETE_WALLET_RECOVERY', PMCompleteWalletRecoveryPayload>
  | RpcEnvelope<'PM_GET_RECOVERY_EMAILS', PMGetRecoveryEmailsPayload>
  | RpcEnvelope<'PM_SET_RECOVERY_EMAILS', PMSetRecoveryEmailsPayload>
  | RpcEnvelope<'PM_SIGN_TX_WITH_ACTIONS', PMSignTxPayload>
  | RpcEnvelope<'PM_SIGN_AND_SEND_TX', PMSignAndSendTxPayload>
  | RpcEnvelope<
      'PM_FUND_IMPLICIT_NEAR_ACCOUNT_FOR_TESTING',
      PMFundImplicitNearAccountForTestingPayload
    >
  | RpcEnvelope<'PM_SEND_TRANSACTION', PMSendTxPayload>
  | RpcEnvelope<'PM_EXECUTE_ACTION', PMExecuteActionPayload>
  | RpcEnvelope<'PM_SIGN_DELEGATE_ACTION', PMSignDelegateActionPayload>
  | RpcEnvelope<'PM_SIGN_NEP413', PMSignNep413Payload>
  | RpcEnvelope<'PM_SIGN_TEMPO', PMSignTempoPayload>
  | RpcEnvelope<'PM_REPORT_TEMPO_BROADCAST_ACCEPTED', PMReportTempoBroadcastAcceptedPayload>
  | RpcEnvelope<'PM_REPORT_TEMPO_BROADCAST_REJECTED', PMReportTempoBroadcastRejectedPayload>
  | RpcEnvelope<'PM_REPORT_TEMPO_FINALIZED', PMReportTempoFinalizedPayload>
  | RpcEnvelope<'PM_REPORT_TEMPO_DROPPED_OR_REPLACED', PMReportTempoDroppedOrReplacedPayload>
  | RpcEnvelope<'PM_RECONCILE_TEMPO_NONCE_LANE', PMReconcileTempoNonceLanePayload>
  | RpcEnvelope<'PM_RESOLVE_EXACT_KEY_EXPORT_LANE', PMResolveExactKeyExportLanePayload>
  | RpcEnvelope<'PM_EXPORT_KEYPAIR_UI', PMExportKeypairUiPayload>
  | RpcEnvelope<'PM_GET_RECENT_UNLOCKS'>
  | RpcEnvelope<'PM_PREFETCH_BLOCKHEIGHT'>
  | RpcEnvelope<
      'PM_PREFILL_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL',
      PMPrefillRouterAbEcdsaDerivationPresignaturePoolPayload
    >
  | RpcEnvelope<'PM_SET_CONFIRM_BEHAVIOR', PMSetConfirmBehaviorPayload>
  | RpcEnvelope<'PM_SET_CONFIRMATION_CONFIG', PMSetConfirmationConfigPayload>
  | RpcEnvelope<'PM_GET_CONFIRMATION_CONFIG'>
  | RpcEnvelope<'PM_HAS_PASSKEY', PMHasPasskeyPayload>
  | RpcEnvelope<'PM_VIEW_ACCESS_KEYS', PMViewAccessKeysPayload>
  | RpcEnvelope<'PM_DELETE_DEVICE_KEY', PMDeleteDeviceKeyPayload>
  | RpcEnvelope<'PM_LIST_WALLET_CREDENTIALS', PMListWalletCredentialsPayload>
  | RpcEnvelope<'PM_RENAME_WALLET_CREDENTIAL', PMRenameWalletCredentialPayload>
  | RpcEnvelope<'PM_REVOKE_WALLET_CREDENTIAL', PMRevokeWalletCredentialPayload>
  | RpcEnvelope<
      'PM_LINK_DEVICE_WITH_SCANNED_QR_DATA',
      {
        qrData: DeviceLinkingQRData;
        fundingAmount: string;
        options?: {
          confirmationConfig?: Partial<ConfirmationConfig>;
          confirmerText?: { title?: string; body?: string };
        };
      }
    >
  | RpcEnvelope<
      'PM_START_DEVICE2_LINKING_FLOW',
      {
        ui?: 'modal' | 'inline';
        cameraId?: string;
        signerSlot?: number;
        options?: {
          confirmationConfig?: Partial<ConfirmationConfig>;
          confirmerText?: { title?: string; body?: string };
        };
      }
    >
  | RpcEnvelope<'PM_STOP_DEVICE2_LINKING_FLOW'>
  | RpcEnvelope<'PM_SYNC_ACCOUNT_FLOW', { walletId?: string }>;

export type ChildToParentEnvelope =
  | RpcEnvelope<'READY', ReadyPayload>
  | RpcEnvelope<'PONG'>
  | RpcEnvelope<'PROGRESS', ProgressPayload>
  | RpcEnvelope<'SDK_LIFECYCLE_EVENT', SdkLifecycleEvent>
  | RpcEnvelope<'PREFERENCES_CHANGED', PreferencesChangedPayload>
  | RpcEnvelope<'AUTH_MENU_EXTERNAL_AUTH_REQUEST', HostedAuthMenuExternalAuthRequest>
  | RpcEnvelope<'AUTH_MENU_DEMO_EMAIL_OTP_DELIVERY', HostedAuthMenuDemoEmailOtpDelivery>
  | RpcEnvelope<'SURFACE_MEASUREMENT', WalletIframeSurfaceMeasurement>
  | RpcEnvelope<'PM_RESULT', PMResultPayload>
  | RpcEnvelope<'ERROR', ErrorPayload>;
