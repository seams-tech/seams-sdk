export interface GoogleIdCredentialResponse {
  credential?: string;
}

export interface GoogleIdPromptMomentNotification {
  isDisplayMoment?: () => boolean;
  isDisplayed?: () => boolean;
  isNotDisplayed?: () => boolean;
  isSkippedMoment?: () => boolean;
  isDismissedMoment?: () => boolean;
  getNotDisplayedReason?: () => string;
  getSkippedReason?: () => string;
  getDismissedReason?: () => string;
}

export interface GoogleAuthOptions {
  configured: boolean;
  clientId?: string;
  message?: string;
}

export interface GoogleIdentityApi {
  initialize(config: {
    client_id: string;
    callback: (response: GoogleIdCredentialResponse) => void;
    auto_select?: boolean;
    cancel_on_tap_outside?: boolean;
    use_fedcm_for_prompt?: boolean;
  }): void;
  prompt(notification?: (event: GoogleIdPromptMomentNotification) => void): void;
  cancel?: () => void;
  disableAutoSelect?: () => void;
}

declare global {
  interface Window {
    google?: {
      accounts?: {
        id?: GoogleIdentityApi;
      };
    };
  }
}

let googleIdentityScriptLoadPromise: Promise<void> | null = null;
const GOOGLE_ID_TOKEN_TIMEOUT_MS = 60_000;
const GOOGLE_IDENTITY_SCRIPT_TIMEOUT_MS = 15_000;
const GOOGLE_IDENTITY_PROMPT_DISPLAY_TIMEOUT_MS = 12_000;
const GOOGLE_IDENTITY_FEDCM_PROMPT_DISPLAY_TIMEOUT_MS = 25_000;
const GOOGLE_IDENTITY_PROMPT_TOTAL_TIMEOUT_MS = 60_000;

function normalizeRelayBaseUrl(input: unknown): string {
  return String(input || '')
    .trim()
    .replace(/\/+$/, '');
}

async function parseOptionalJson(response: Response): Promise<any> {
  return response.json().catch(() => null);
}

export async function fetchGoogleAuthOptions(relayerBaseUrl: string): Promise<GoogleAuthOptions> {
  const baseUrl = normalizeRelayBaseUrl(relayerBaseUrl);
  if (!baseUrl) {
    return { configured: false, message: 'Relayer base URL is not configured' };
  }

  const response = await fetch(`${baseUrl}/auth/google/options`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({}),
  });
  const body = await parseOptionalJson(response);
  const configured = response.ok && body?.ok === true && body?.configured === true;
  const clientId = String(body?.clientId || '').trim();
  return {
    configured: configured && clientId.length > 0,
    ...(clientId ? { clientId } : {}),
    ...(typeof body?.message === 'string' && body.message.trim()
      ? { message: body.message.trim() }
      : {}),
  };
}

type GooglePromptStage = 'not_displayed' | 'skipped';
type GooglePromptTerminalStage = GooglePromptStage | 'dismissed';

type GooglePromptFailureDetails = {
  stage: GooglePromptTerminalStage;
  reason: string;
};

type GooglePromptError = Error & {
  details?: GooglePromptFailureDetails;
};

function normalizeGooglePromptReason(value: unknown, fallback: string): string {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  return normalized || fallback;
}

function buildGooglePromptErrorMessage(input: {
  stage: GooglePromptTerminalStage;
  reason: string;
}): string {
  const { stage, reason } = input;
  if (reason === 'unknown_reason') {
    return 'Google sign-in prompt did not appear. Check browser sign-in settings, popup blockers, or third-party sign-in settings and retry.';
  }
  if (stage === 'not_displayed') {
    return `Google sign-in is unavailable (${reason}).`;
  }
  if (stage === 'dismissed') {
    return `Google sign-in was dismissed (${reason}).`;
  }
  return `Google sign-in was skipped (${reason}).`;
}

function makeGooglePromptError(details: GooglePromptFailureDetails): GooglePromptError {
  const error = new Error(buildGooglePromptErrorMessage(details)) as GooglePromptError;
  error.details = details;
  return error;
}

function isUnknownPromptFailure(error: unknown): boolean {
  const details = (error as GooglePromptError | null)?.details;
  return details?.reason === 'unknown_reason';
}

export function ensureGoogleIdentityScriptLoaded(): Promise<void> {
  if (typeof window === 'undefined')
    return Promise.reject(new Error('Browser runtime is required'));
  if (window.google?.accounts?.id) return Promise.resolve();
  if (googleIdentityScriptLoadPromise) return googleIdentityScriptLoadPromise;

  googleIdentityScriptLoadPromise = new Promise<void>((resolve, reject) => {
    const script = document.createElement('script');
    let settled = false;
    let timeout: number | undefined;
    const finishResolve = () => {
      if (settled) return;
      settled = true;
      if (timeout !== undefined) window.clearTimeout(timeout);
      resolve();
    };
    const finishReject = (error: Error) => {
      if (settled) return;
      settled = true;
      if (timeout !== undefined) window.clearTimeout(timeout);
      googleIdentityScriptLoadPromise = null;
      reject(error);
    };
    timeout = window.setTimeout(() => {
      script.remove();
      finishReject(
        new Error('Timed out loading Google Identity script. Check network blockers and retry.'),
      );
    }, GOOGLE_IDENTITY_SCRIPT_TIMEOUT_MS);
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    script.onload = () => {
      if (window.google?.accounts?.id) {
        finishResolve();
        return;
      }
      finishReject(new Error('Google Identity API loaded without accounts.id'));
    };
    script.onerror = () => finishReject(new Error('Failed to load Google Identity script'));
    document.head.appendChild(script);
  });

  return googleIdentityScriptLoadPromise;
}

function requestGoogleIdTokenWithPromptMode(
  clientId: string,
  useFedcmForPrompt: boolean,
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const googleIdApi = window.google?.accounts?.id;
    if (!googleIdApi) {
      reject(new Error('Google Identity API is unavailable'));
      return;
    }

    let settled = false;
    let displayTimeout: number | undefined;
    let totalTimeout: number | undefined;
    let promptDisplayed = false;
    const clearTimers = () => {
      if (displayTimeout !== undefined) window.clearTimeout(displayTimeout);
      if (totalTimeout !== undefined) window.clearTimeout(totalTimeout);
      displayTimeout = undefined;
      totalTimeout = undefined;
    };
    const cancelPrompt = () => {
      try {
        googleIdApi.cancel?.();
      } catch {
        // Best-effort cleanup; Google Identity does not guarantee cancel availability.
      }
    };
    const finishResolve = (token: string) => {
      if (settled) return;
      settled = true;
      clearTimers();
      resolve(token);
    };
    const finishReject = (input: string | Error) => {
      if (settled) return;
      settled = true;
      clearTimers();
      cancelPrompt();
      if (input instanceof Error) {
        reject(input);
        return;
      }
      reject(new Error(input));
    };
    displayTimeout = window.setTimeout(() => {
      if (promptDisplayed) return;
      finishReject(makeGooglePromptError({ stage: 'not_displayed', reason: 'unknown_reason' }));
    }, useFedcmForPrompt
      ? GOOGLE_IDENTITY_FEDCM_PROMPT_DISPLAY_TIMEOUT_MS
      : GOOGLE_IDENTITY_PROMPT_DISPLAY_TIMEOUT_MS);
    totalTimeout = window.setTimeout(() => {
      finishReject(
        new Error(
          'Timed out waiting for Google sign-in. Check browser sign-in settings or close the Google prompt and retry.',
        ),
      );
    }, GOOGLE_IDENTITY_PROMPT_TOTAL_TIMEOUT_MS);

    googleIdApi.initialize({
      client_id: clientId,
      callback: (response) => {
        const token = String(response?.credential || '').trim();
        if (!token) {
          finishReject('Google sign-in did not return an id_token');
          return;
        }
        finishResolve(token);
      },
      // Let Google reuse an existing browser Google session when available.
      // The wallet unlock/signing factor remains the Email OTP flow after SSO.
      auto_select: true,
      cancel_on_tap_outside: true,
      use_fedcm_for_prompt: useFedcmForPrompt,
    });

    googleIdApi.prompt((notification) => {
      if (settled) return;
      const displayed =
        notification?.isDisplayed?.() === true || notification?.isDisplayMoment?.() === true;
      if (displayed) {
        promptDisplayed = true;
        if (displayTimeout !== undefined) {
          window.clearTimeout(displayTimeout);
          displayTimeout = undefined;
        }
        return;
      }
      const notDisplayed = notification?.isNotDisplayed?.() === true;
      const skipped = notification?.isSkippedMoment?.() === true;
      const dismissed = notification?.isDismissedMoment?.() === true;
      if (notDisplayed) {
        const reason = normalizeGooglePromptReason(
          notification?.getNotDisplayedReason?.(),
          'not_displayed',
        );
        finishReject(makeGooglePromptError({ stage: 'not_displayed', reason }));
        return;
      }
      if (skipped) {
        const reason = normalizeGooglePromptReason(notification?.getSkippedReason?.(), 'skipped');
        finishReject(makeGooglePromptError({ stage: 'skipped', reason }));
        return;
      }
      if (dismissed) {
        const reason = normalizeGooglePromptReason(
          notification?.getDismissedReason?.(),
          'dismissed',
        );
        finishReject(makeGooglePromptError({ stage: 'dismissed', reason }));
      }
    });
  });
}

async function withGoogleIdentityTimeout<T>(promise: Promise<T>): Promise<T> {
  return await new Promise<T>((resolve, reject) => {
    const timeoutId = window.setTimeout(() => {
      reject(
        new Error(
          'Google sign-in timed out. Check that the Google popup was not blocked and retry.',
        ),
      );
    }, GOOGLE_ID_TOKEN_TIMEOUT_MS);
    promise.then(
      (value) => {
        window.clearTimeout(timeoutId);
        resolve(value);
      },
      (error) => {
        window.clearTimeout(timeoutId);
        reject(error);
      },
    );
  });
}

export async function requestGoogleIdToken(clientId: string): Promise<string> {
  try {
    // First prefer non-FedCM prompt mode.
    return await withGoogleIdentityTimeout(requestGoogleIdTokenWithPromptMode(clientId, false));
  } catch (error: unknown) {
    if (!isUnknownPromptFailure(error)) {
      throw error;
    }
  }

  // If browser returns unknown prompt failure, retry with FedCM prompt mode.
  return await withGoogleIdentityTimeout(requestGoogleIdTokenWithPromptMode(clientId, true));
}
