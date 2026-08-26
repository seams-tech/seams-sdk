import { useEffect } from 'react';
import type { useSeams } from '@seams/wallet/react';

const REQUEST_EVENT = 'seams:intended-email-otp-unlock-request';
const RESULT_EVENT = 'seams:intended-email-otp-unlock-result';

type SeamsClient = ReturnType<typeof useSeams>['seams'];

type IntendedEmailOtpUnlockRequest =
  | {
      readonly kind: 'request_challenge';
      readonly requestId: string;
      readonly walletId: string;
      readonly walletAuthMethodId: string;
    }
  | {
      readonly kind: 'complete_unlock';
      readonly requestId: string;
      readonly walletId: string;
      readonly walletAuthMethodId: string;
      readonly email: string;
      readonly providerSubjectId: string;
      readonly challengeId: string;
      readonly otpCode: string;
      readonly relayUrl: string;
    };

export function useIntendedEmailOtpUnlockBridge(seams: SeamsClient): void {
  useEffect(() => {
    if (!import.meta.env.DEV) return;
    const handleRequest = createIntendedEmailOtpUnlockHandler(seams);
    window.addEventListener(REQUEST_EVENT, handleRequest);
    return () => window.removeEventListener(REQUEST_EVENT, handleRequest);
  }, [seams]);
}

function createIntendedEmailOtpUnlockHandler(seams: SeamsClient): EventListener {
  return (event: Event) => {
    const request = parseIntendedEmailOtpUnlockRequest(event);
    if (!request) return;
    void executeIntendedEmailOtpUnlockRequest(seams, request);
  };
}

async function executeIntendedEmailOtpUnlockRequest(
  seams: SeamsClient,
  request: IntendedEmailOtpUnlockRequest,
): Promise<void> {
  try {
    if (request.kind === 'request_challenge') {
      const challenge = await seams.auth.requestEmailOtpChallenge({
        walletId: request.walletId,
        walletAuthMethodId: request.walletAuthMethodId,
      });
      dispatchIntendedEmailOtpUnlockResult({
        requestId: request.requestId,
        ok: true,
        challengeId: challenge.challengeId,
      });
      return;
    }
    await seams.auth.unlockAddedEmailOtpWallet({
      walletId: request.walletId,
      walletAuthMethodId: request.walletAuthMethodId,
      email: request.email,
      providerSubjectId: request.providerSubjectId,
      challengeId: request.challengeId,
      otpCode: request.otpCode,
      relayUrl: request.relayUrl,
    });
    dispatchIntendedEmailOtpUnlockResult({ requestId: request.requestId, ok: true });
  } catch (error: unknown) {
    dispatchIntendedEmailOtpUnlockResult({
      requestId: request.requestId,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

function parseIntendedEmailOtpUnlockRequest(event: Event): IntendedEmailOtpUnlockRequest | null {
  if (!(event instanceof CustomEvent) || !isRecord(event.detail)) return null;
  const detail = event.detail;
  const requestId = readString(detail, 'requestId');
  const walletId = readString(detail, 'walletId');
  const walletAuthMethodId = readString(detail, 'walletAuthMethodId');
  if (detail.kind === 'request_challenge') {
    return { kind: detail.kind, requestId, walletId, walletAuthMethodId };
  }
  if (detail.kind !== 'complete_unlock') return null;
  return {
    kind: detail.kind,
    requestId,
    walletId,
    walletAuthMethodId,
    email: readString(detail, 'email'),
    providerSubjectId: readString(detail, 'providerSubjectId'),
    challengeId: readString(detail, 'challengeId'),
    otpCode: readString(detail, 'otpCode'),
    relayUrl: readString(detail, 'relayUrl'),
  };
}

function dispatchIntendedEmailOtpUnlockResult(detail: Record<string, unknown>): void {
  window.dispatchEvent(new CustomEvent(RESULT_EVENT, { detail }));
}

function readString(record: Record<string, unknown>, field: string): string {
  const value = typeof record[field] === 'string' ? record[field].trim() : '';
  if (!value) throw new Error(`Intended Email OTP unlock ${field} is missing`);
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
