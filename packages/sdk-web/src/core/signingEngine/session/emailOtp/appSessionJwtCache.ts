import type { WalletId, WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EmailOtpAuthLane } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import { authLaneAppSessionJwt } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import {
  exactSigningLaneWalletId,
  exactSigningLaneIdentityKey,
  type ExactEcdsaSigningLaneIdentity,
  type ExactEd25519SigningLaneIdentity,
  type ExactSigningLaneIdentity,
  type ExactSigningLaneIdentityKey,
} from '../identity/exactSigningLaneIdentity';
import type { SigningOperationFingerprint, SigningOperationId } from '../operationState/types';
import {
  decodeJwtPayloadRecord,
  isAppSessionJwt,
  isSessionJwtUnexpired,
  requireAppSessionJwt,
} from '@shared/utils/sessionTokens';
import {
  parseAppSessionJwt,
  parseProviderSubject,
  parseWalletId,
  type AppSessionJwt,
  type ProviderSubject,
} from '@shared/utils/domainIds';
import { joinNormalizedUrl } from '@shared/utils/normalize';

type EmailOtpSigningLaneAuth = Extract<
  ExactSigningLaneIdentity['auth'],
  { kind: 'email_otp' }
>;

type ExactEmailOtpSigningLaneIdentity =
  | (Omit<ExactEd25519SigningLaneIdentity, 'auth'> & { auth: EmailOtpSigningLaneAuth })
  | (Omit<ExactEcdsaSigningLaneIdentity, 'auth'> & { auth: EmailOtpSigningLaneAuth });

function isExactEmailOtpSigningLaneIdentity(
  identity: ExactSigningLaneIdentity,
): identity is ExactEmailOtpSigningLaneIdentity {
  return identity.auth.kind === 'email_otp';
}

export type EmailOtpAppSessionBinding = Readonly<{
  kind: 'email_otp_app_session_binding';
  walletId: WalletId;
  providerSubject: ProviderSubject;
  appSessionJwt: AppSessionJwt;
}>;

export type EmailOtpRefreshIdentity = {
  kind: 'email_otp_refresh_identity';
  walletId: WalletId;
  walletSessionUserId: string;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  laneIdentity: ExactEmailOtpSigningLaneIdentity;
  laneIdentityKey: ExactSigningLaneIdentityKey;
};

export type EmailOtpSessionRefreshResult =
  | {
      kind: 'cached_email_otp_session';
      identity: EmailOtpRefreshIdentity;
      appSessionJwt: string;
    }
  | {
      kind: 'refreshed_email_otp_session';
      identity: EmailOtpRefreshIdentity;
      appSessionJwt: string;
    }
  | {
      kind: 'email_otp_refresh_rejected';
      identity: EmailOtpRefreshIdentity;
      reason: 'session_refresh_unauthorized';
      httpStatus: 401 | 403;
      appSessionJwt?: never;
    };

const EMAIL_OTP_APP_SESSION_STORAGE_PREFIX = 'seams:email-otp-app-session:v1:';

type StoredEmailOtpAppSessionBinding = {
  version: 1;
  walletId: string;
  providerSubject: string;
  appSessionJwt: string;
};

function emailOtpAppSessionStorage(): Storage | null {
  try {
    return typeof sessionStorage === 'undefined' ? null : sessionStorage;
  } catch {
    return null;
  }
}

function emailOtpAppSessionStorageWalletPrefix(walletId: WalletId): string {
  return `${EMAIL_OTP_APP_SESSION_STORAGE_PREFIX}${encodeURIComponent(String(walletId))}:`;
}

function emailOtpAppSessionStorageKey(binding: {
  walletId: WalletId;
  providerSubject: ProviderSubject;
}): string {
  return `${emailOtpAppSessionStorageWalletPrefix(binding.walletId)}${encodeURIComponent(String(binding.providerSubject))}`;
}

function parseStoredEmailOtpAppSessionBinding(
  raw: string,
): EmailOtpAppSessionBinding | null {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    const record = parsed as Record<string, unknown>;
    if (
      record.version !== 1 ||
      typeof record.walletId !== 'string' ||
      typeof record.providerSubject !== 'string' ||
      typeof record.appSessionJwt !== 'string'
    ) {
      return null;
    }
    const walletId = parseWalletId(record.walletId);
    const providerSubject = parseProviderSubject(record.providerSubject);
    if (!walletId.ok || !providerSubject.ok) return null;
    const binding = emailOtpAppSessionBindingFromJwt({
      walletId: walletId.value,
      appSessionJwt: record.appSessionJwt,
    });
    return binding.providerSubject === providerSubject.value ? binding : null;
  } catch {
    return null;
  }
}

function persistEmailOtpAppSessionBinding(binding: EmailOtpAppSessionBinding): void {
  const storage = emailOtpAppSessionStorage();
  if (!storage) return;
  const record: StoredEmailOtpAppSessionBinding = {
    version: 1,
    walletId: String(binding.walletId),
    providerSubject: String(binding.providerSubject),
    appSessionJwt: binding.appSessionJwt,
  };
  try {
    storage.setItem(emailOtpAppSessionStorageKey(binding), JSON.stringify(record));
  } catch {
    return;
  }
}

function readPersistedEmailOtpAppSessionBinding(args: {
  walletId: WalletId;
  providerSubject: ProviderSubject;
}): EmailOtpAppSessionBinding | null {
  const storage = emailOtpAppSessionStorage();
  if (!storage) return null;
  const key = emailOtpAppSessionStorageKey(args);
  try {
    const raw = storage.getItem(key);
    if (!raw) return null;
    const binding = parseStoredEmailOtpAppSessionBinding(raw);
    if (
      !binding ||
      binding.walletId !== args.walletId ||
      binding.providerSubject !== args.providerSubject
    ) {
      storage.removeItem(key);
      return null;
    }
    return binding;
  } catch {
    return null;
  }
}

function listPersistedEmailOtpAppSessionBindings(
  walletId: WalletId,
): EmailOtpAppSessionBinding[] {
  const storage = emailOtpAppSessionStorage();
  if (!storage) return [];
  const prefix = emailOtpAppSessionStorageWalletPrefix(walletId);
  const bindings: EmailOtpAppSessionBinding[] = [];
  try {
    for (let index = 0; index < storage.length; index += 1) {
      const key = storage.key(index);
      if (!key || !key.startsWith(prefix)) continue;
      const raw = storage.getItem(key);
      const binding = raw ? parseStoredEmailOtpAppSessionBinding(raw) : null;
      if (!binding || binding.walletId !== walletId) {
        storage.removeItem(key);
        index -= 1;
        continue;
      }
      bindings.push(binding);
    }
  } catch {
    return [];
  }
  return bindings;
}

function deletePersistedEmailOtpAppSessionBinding(binding: {
  walletId: WalletId;
  providerSubject: ProviderSubject;
}): void {
  try {
    emailOtpAppSessionStorage()?.removeItem(emailOtpAppSessionStorageKey(binding));
  } catch {
    return;
  }
}

export class EmailOtpAppSessionJwtCache {
  private readonly byWallet = new Map<string, Map<string, EmailOtpAppSessionBinding>>();

  constructor(
    private readonly deps: {
      refreshAppSessionJwt?: (args: { relayUrl: string }) => Promise<string>;
    } = {},
  ) {}

  remember(binding: EmailOtpAppSessionBinding): void {
    const walletId = String(binding.walletId);
    const providerSubject = String(binding.providerSubject);
    const entries = this.byWallet.get(walletId) ?? new Map<string, EmailOtpAppSessionBinding>();
    entries.set(providerSubject, binding);
    this.byWallet.set(walletId, entries);
    persistEmailOtpAppSessionBinding(binding);
  }

  async resolve(args: {
    identity: EmailOtpRefreshIdentity;
    relayUrl: string;
  }): Promise<EmailOtpSessionRefreshResult> {
    const cached = this.cachedBindingForIdentity(args.identity);
    if (cached && isSessionJwtUnexpired(cached.appSessionJwt, { skewMs: 30_000 })) {
      return {
        kind: 'cached_email_otp_session',
        identity: args.identity,
        appSessionJwt: cached.appSessionJwt,
      };
    }
    const refreshCandidate =
      cached &&
      isAppSessionJwt(cached.appSessionJwt) &&
      isSessionJwtUnexpired(cached.appSessionJwt)
        ? cached.appSessionJwt
        : '';
    this.deleteBindingForIdentity(args.identity);
    const refreshed = this.deps.refreshAppSessionJwt
      ? {
          kind: 'refreshed_email_otp_session' as const,
          identity: args.identity,
          appSessionJwt: await this.deps.refreshAppSessionJwt({ relayUrl: args.relayUrl }),
        }
      : await refreshEmailOtpAppSessionJwt({
          identity: args.identity,
          relayUrl: args.relayUrl,
          ...(refreshCandidate ? { appSessionJwt: refreshCandidate } : {}),
        });
    if (refreshed.kind === 'refreshed_email_otp_session') {
      const binding = emailOtpAppSessionBindingFromJwt({
        walletId: args.identity.walletId,
        appSessionJwt: refreshed.appSessionJwt,
      });
      if (binding.providerSubject !== args.identity.laneIdentity.auth.providerSubjectId) {
        throw new Error('Refreshed Email OTP app session belongs to a different provider subject');
      }
      this.remember(binding);
    }
    return refreshed;
  }

  async resolveJwt(args: { walletSession: WalletSessionRef; relayUrl: string }): Promise<string> {
    const walletId = String(args.walletSession.walletId || '').trim();
    const cached = walletId ? this.uniqueBindingForWallet(walletId) : null;
    if (
      cached &&
      isAppSessionJwt(cached.appSessionJwt) &&
      isSessionJwtUnexpired(cached.appSessionJwt, { skewMs: 30_000 })
    ) {
      return cached.appSessionJwt;
    }
    const refreshCandidate =
      cached &&
      isAppSessionJwt(cached.appSessionJwt) &&
      isSessionJwtUnexpired(cached.appSessionJwt)
        ? cached.appSessionJwt
        : '';
    if (walletId) this.byWallet.delete(walletId);
    const refreshed = this.deps.refreshAppSessionJwt
      ? await this.deps.refreshAppSessionJwt({ relayUrl: args.relayUrl })
      : await refreshEmailOtpAppSessionJwtRaw({
          relayUrl: args.relayUrl,
          ...(refreshCandidate ? { appSessionJwt: refreshCandidate } : {}),
        });
    if (typeof refreshed !== 'string') {
      throw new Error('Email OTP export session refresh requires fresh Email OTP verification');
    }
    if (walletId && refreshed) {
      this.remember(
        emailOtpAppSessionBindingFromJwt({
          walletId: args.walletSession.walletId,
          appSessionJwt: refreshed,
        }),
      );
    }
    return refreshed;
  }

  private cachedBindingForIdentity(
    identity: EmailOtpRefreshIdentity,
  ): EmailOtpAppSessionBinding | null {
    const entries = this.byWallet.get(String(identity.walletId));
    const providerSubject = parseProviderSubject(identity.laneIdentity.auth.providerSubjectId);
    if (!providerSubject.ok) return null;
    const cached = entries?.get(providerSubject.value) ?? null;
    if (cached) return cached;
    const persisted = readPersistedEmailOtpAppSessionBinding({
      walletId: identity.walletId,
      providerSubject: providerSubject.value,
    });
    if (persisted) this.remember(persisted);
    return persisted;
  }

  private deleteBindingForIdentity(identity: EmailOtpRefreshIdentity): void {
    const walletId = String(identity.walletId);
    const entries = this.byWallet.get(walletId);
    entries?.delete(identity.laneIdentity.auth.providerSubjectId);
    const providerSubject = parseProviderSubject(identity.laneIdentity.auth.providerSubjectId);
    if (providerSubject.ok) {
      deletePersistedEmailOtpAppSessionBinding({
        walletId: identity.walletId,
        providerSubject: providerSubject.value,
      });
    }
    if (entries?.size === 0) this.byWallet.delete(walletId);
  }

  private uniqueBindingForWallet(walletId: string): EmailOtpAppSessionBinding | null {
    let entries = this.byWallet.get(walletId);
    if (!entries || entries.size === 0) {
      const parsedWalletId = parseWalletId(walletId);
      if (!parsedWalletId.ok) return null;
      for (const binding of listPersistedEmailOtpAppSessionBindings(parsedWalletId.value)) {
        this.remember(binding);
      }
      entries = this.byWallet.get(walletId);
    }
    if (!entries || entries.size === 0) return null;
    if (entries.size !== 1) {
      throw new Error('Email OTP app-session resolution requires one exact provider subject');
    }
    return entries.values().next().value ?? null;
  }
}

export function emailOtpAppSessionBindingFromJwt(args: {
  walletId: WalletId;
  appSessionJwt: string;
}): EmailOtpAppSessionBinding {
  const jwt = requireAppSessionJwt(args.appSessionJwt, 'Email OTP appSessionJwt');
  const parsedJwt = parseAppSessionJwt(jwt);
  if (!parsedJwt.ok) throw new Error(parsedJwt.error.message);
  const payload = decodeJwtPayloadRecord(jwt);
  const parsedSubject = parseProviderSubject(payload?.sub);
  if (!parsedSubject.ok) {
    throw new Error(`Email OTP app-session subject is invalid: ${parsedSubject.error.message}`);
  }
  const parsedWalletId = parseWalletId(payload?.walletId);
  if (!parsedWalletId.ok || parsedWalletId.value !== args.walletId) {
    throw new Error('Email OTP app-session wallet does not match the requested wallet binding');
  }
  return {
    kind: 'email_otp_app_session_binding',
    walletId: parsedWalletId.value,
    providerSubject: parsedSubject.value,
    appSessionJwt: parsedJwt.value,
  };
}

export function appSessionJwtFromEmailOtpAuthLane(authLane: EmailOtpAuthLane): string {
  return authLaneAppSessionJwt(authLane);
}

export function appSessionSubjectFromEmailOtpAuthLane(authLane: EmailOtpAuthLane): string {
  const jwt = appSessionJwtFromEmailOtpAuthLane(authLane);
  if (!jwt) return '';
  const payload = decodeJwtPayloadRecord(jwt);
  const sub = typeof payload?.sub === 'string' ? payload.sub.trim() : '';
  return sub || '';
}

export async function refreshEmailOtpAppSessionJwt(args: {
  identity: EmailOtpRefreshIdentity;
  relayUrl: string;
  appSessionJwt?: string;
}): Promise<EmailOtpSessionRefreshResult> {
  const result = await refreshEmailOtpAppSessionJwtRaw({
    relayUrl: args.relayUrl,
    appSessionJwt: args.appSessionJwt,
    identity: args.identity,
  });
  if (typeof result !== 'string') return result;
  return {
    kind: 'refreshed_email_otp_session',
    identity: args.identity,
    appSessionJwt: result,
  };
}

async function readEmailOtpSessionRefreshJson(
  response: Response,
): Promise<Record<string, unknown> | null> {
  try {
    const value = (await response.json()) as unknown;
    return value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

async function refreshEmailOtpAppSessionJwtRaw(args: {
  relayUrl: string;
  appSessionJwt?: string;
  identity?: EmailOtpRefreshIdentity;
}): Promise<
  string | Extract<EmailOtpSessionRefreshResult, { kind: 'email_otp_refresh_rejected' }>
> {
  const relayUrl = String(args.relayUrl || '').trim();
  if (!relayUrl) {
    throw new Error('Missing relayer url for Email OTP export session refresh');
  }
  const appSessionJwt = String(args.appSessionJwt || '').trim();
  const response = await fetch(joinNormalizedUrl(relayUrl, '/session/refresh'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(appSessionJwt ? { Authorization: `Bearer ${appSessionJwt}` } : {}),
    },
    credentials: 'include',
    body: JSON.stringify({ session_kind: 'jwt' }),
  });
  const json = await readEmailOtpSessionRefreshJson(response);
  if (!response.ok || !json || json.ok === false) {
    if (response.status === 401 || response.status === 403) {
      if (!args.identity) {
        throw new Error('Email OTP export session refresh requires fresh Email OTP verification');
      }
      return {
        kind: 'email_otp_refresh_rejected',
        identity: args.identity,
        reason: 'session_refresh_unauthorized',
        httpStatus: response.status,
      };
    }
    const message =
      (typeof json?.message === 'string' && json.message.trim()) ||
      `Email OTP export session refresh failed (HTTP ${response.status})`;
    throw new Error(message);
  }
  const jwt = typeof json.jwt === 'string' ? json.jwt.trim() : '';
  if (!jwt) {
    throw new Error('Email OTP export session refresh did not return a JWT');
  }
  return jwt;
}

export function emailOtpRefreshIdentity(args: {
  walletId: WalletId;
  walletSessionUserId: string;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  laneIdentity: ExactSigningLaneIdentity;
}): EmailOtpRefreshIdentity {
  const laneWalletId = String(exactSigningLaneWalletId(args.laneIdentity));
  if (String(args.walletId) !== laneWalletId) {
    throw new Error('[email-otp] refresh identity wallet does not match exact lane identity');
  }
  const walletSessionUserId = String(args.walletSessionUserId || '').trim();
  if (!walletSessionUserId) {
    throw new Error('[email-otp] refresh identity requires walletSessionUserId');
  }
  if (!isExactEmailOtpSigningLaneIdentity(args.laneIdentity)) {
    throw new Error('[email-otp] refresh identity requires an Email OTP exact lane');
  }
  return {
    kind: 'email_otp_refresh_identity',
    walletId: args.walletId,
    walletSessionUserId,
    operationId: args.operationId,
    operationFingerprint: args.operationFingerprint,
    laneIdentity: args.laneIdentity,
    laneIdentityKey: exactSigningLaneIdentityKey(args.laneIdentity),
  };
}
