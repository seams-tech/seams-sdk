import {
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';
import { parseWebAuthnCredentialIdB64u } from '@shared/utils/domainIds';

const BOOTSTRAP_CHALLENGE_PATH = '/wallet/email-otp/recovery-bootstrap/challenge';
const BOOTSTRAP_VERIFY_PATH = '/wallet/email-otp/recovery-bootstrap/verify';

export type WalletRecoveryBootstrapChallengeResult =
  | {
      readonly kind: 'ready';
      readonly challengeId: string;
      readonly otpChannel: 'email_otp';
      readonly expiresAtMs: number;
      readonly emailHint: string;
    }
  | { readonly kind: 'unavailable'; readonly message: string }
  | { readonly kind: 'transport_failed'; readonly message: string };

export async function requestWalletRecoveryBootstrapChallenge(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoveryBootstrapChallengeResult> {
  let response: Response;
  try {
    response = await post({
      relayUrl: args.relayUrl,
      path: BOOTSTRAP_CHALLENGE_PATH,
      body: { walletId: args.walletId, orgId: args.orgId },
      fetchImpl: args.fetchImpl,
    });
  } catch (error: unknown) {
    return {
      kind: 'transport_failed',
      message: error instanceof Error ? error.message : 'recovery challenge request failed',
    };
  }
  const body = asRecord(await response.json().catch(() => ({})));
  const message = typeof body.message === 'string' ? body.message : '';
  if (response.status !== 200 || body.ok !== true) {
    return { kind: response.status === 404 ? 'unavailable' : 'transport_failed', message: message || 'recovery challenge unavailable' };
  }
  const challengeId = stringField(body.challengeId);
  const emailHint = stringField(body.emailHint);
  const expiresAtMs = Number(body.expiresAtMs);
  if (body.otpChannel !== 'email_otp' || !challengeId || !emailHint || !Number.isSafeInteger(expiresAtMs)) {
    return { kind: 'transport_failed', message: 'recovery challenge returned an unusable payload' };
  }
  return { kind: 'ready', challengeId, otpChannel: 'email_otp', expiresAtMs, emailHint };
}

export type WalletRecoveryBootstrapVerifyResult =
  | {
      readonly kind: 'verified';
      readonly walletId: string;
      readonly challengeId: string;
      readonly recoveryBootstrapGrant: string;
      readonly recoveryBootstrapGrantExpiresAtMs: number;
      readonly replaceableCredentials: readonly {
        readonly credentialIdB64u: string;
        readonly label?: string;
      }[];
    }
  | { readonly kind: 'rejected'; readonly message: string }
  | { readonly kind: 'transport_failed'; readonly message: string };

export async function verifyWalletRecoveryBootstrap(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly challengeId: string;
  readonly otpCode: string;
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoveryBootstrapVerifyResult> {
  let response: Response;
  try {
    response = await post({
      relayUrl: args.relayUrl,
      path: BOOTSTRAP_VERIFY_PATH,
      body: {
        walletId: args.walletId,
        orgId: args.orgId,
        challengeId: args.challengeId,
        otpCode: args.otpCode,
      },
      fetchImpl: args.fetchImpl,
    });
  } catch (error: unknown) {
    return {
      kind: 'transport_failed',
      message: error instanceof Error ? error.message : 'recovery verification request failed',
    };
  }
  const body = asRecord(await response.json().catch(() => ({})));
  const message = typeof body.message === 'string' ? body.message : '';
  if (response.status !== 200 || body.ok !== true) {
    return { kind: response.status === 401 ? 'rejected' : 'transport_failed', message: message || 'recovery verification failed' };
  }
  const walletId = stringField(body.walletId);
  const challengeId = stringField(body.challengeId);
  const recoveryBootstrapGrant = stringField(body.recoveryBootstrapGrant);
  const recoveryBootstrapGrantExpiresAtMs = Number(body.recoveryBootstrapGrantExpiresAtMs);
  const replaceableCredentials = parseReplaceableCredentials(body.replaceableCredentials);
  if (
    walletId !== args.walletId ||
    challengeId !== args.challengeId ||
    !recoveryBootstrapGrant ||
    !Number.isSafeInteger(recoveryBootstrapGrantExpiresAtMs) ||
    !replaceableCredentials
  ) {
    return { kind: 'transport_failed', message: 'recovery verification returned an unusable payload' };
  }
  return {
    kind: 'verified',
    walletId,
    challengeId,
    recoveryBootstrapGrant,
    recoveryBootstrapGrantExpiresAtMs,
    replaceableCredentials,
  };
}

function parseReplaceableCredentials(
  value: unknown,
): readonly { readonly credentialIdB64u: string; readonly label?: string }[] | null {
  if (!Array.isArray(value)) return null;
  const seen = new Set<string>();
  const parsed: { credentialIdB64u: string; label?: string }[] = [];
  for (const item of value) {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) return null;
    const record = item as Record<string, unknown>;
    const parsedCredentialId = parseWebAuthnCredentialIdB64u(record.credentialIdB64u);
    if (!parsedCredentialId.ok || seen.has(parsedCredentialId.value)) return null;
    const credentialIdB64u = parsedCredentialId.value;
    const label = record.label === undefined ? undefined : stringField(record.label);
    if (record.label !== undefined && !label) return null;
    seen.add(credentialIdB64u);
    parsed.push({
      credentialIdB64u,
      ...(label ? { label } : {}),
    });
  }
  return parsed;
}

async function post(args: {
  readonly relayUrl: string;
  readonly path: string;
  readonly body: Record<string, unknown>;
  readonly fetchImpl?: typeof fetch;
}): Promise<Response> {
  const doFetch = args.fetchImpl || fetch;
  return await doFetch(
    `${normalizeRelayerBaseUrl(args.relayUrl)}${args.path}`,
    buildRelayerJsonPostRequestInit({ body: args.body }),
  );
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function stringField(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}
