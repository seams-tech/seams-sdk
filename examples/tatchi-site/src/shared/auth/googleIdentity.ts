export interface GoogleIdCredentialResponse {
  credential?: string;
}

export interface GoogleIdPromptMomentNotification {
  getMomentType?: () => string;
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
const GOOGLE_IDENTITY_PROMPT_TOTAL_TIMEOUT_MS = 60_000;

function normalizeRelayBaseUrl(input: unknown): string {
  return String(input || '')
    .trim()
    .replace(/\/+$/, '');
}

async function parseOptionalJson(response: Response): Promise<unknown> {
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
  const bodyRecord =
    body && typeof body === 'object' ? (body as Record<string, unknown>) : undefined;
  const configured = response.ok && bodyRecord?.ok === true && bodyRecord?.configured === true;
  const clientId = String(bodyRecord?.clientId || '').trim();
  return {
    configured: configured && clientId.length > 0,
    ...(clientId ? { clientId } : {}),
    ...(typeof bodyRecord?.message === 'string' && bodyRecord.message.trim()
      ? { message: bodyRecord.message.trim() }
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

type GooglePromptMode = 'standard';

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

function readGooglePromptDiagnostics(input: {
  clientId: string;
  mode: GooglePromptMode;
  notification?: GoogleIdPromptMomentNotification;
}): Record<string, unknown> {
  const { clientId, mode, notification } = input;
  const read = (fn?: () => unknown): unknown => {
    try {
      return typeof fn === 'function' ? fn() : undefined;
    } catch (error: unknown) {
      return error instanceof Error ? `threw:${error.message}` : 'threw';
    }
  };
  return {
    mode,
    origin: typeof window !== 'undefined' ? window.location.origin : '',
    protocol: typeof window !== 'undefined' ? window.location.protocol : '',
    inIframe: typeof window !== 'undefined' ? window.self !== window.top : false,
    clientIdSuffix: clientId.slice(-16),
    momentType: read(notification?.getMomentType),
    isDisplayMoment: read(notification?.isDisplayMoment),
    isDisplayed: read(notification?.isDisplayed),
    isNotDisplayed: read(notification?.isNotDisplayed),
    isSkippedMoment: read(notification?.isSkippedMoment),
    isDismissedMoment: read(notification?.isDismissedMoment),
    notDisplayedReason: read(notification?.getNotDisplayedReason),
    skippedReason: read(notification?.getSkippedReason),
    dismissedReason: read(notification?.getDismissedReason),
  };
}

function logGooglePromptDiagnostics(
  event: string,
  diagnostics: Record<string, unknown>,
  level: 'debug' | 'warn' = 'debug',
): void {
  const logger = level === 'warn' ? console.warn : console.debug;
  logger(`[Google SSO] ${event}`, diagnostics);
}

export function ensureGoogleIdentityScriptLoaded(): Promise<void> {
  if (typeof window === 'undefined')
    return Promise.reject(new Error('Browser runtime is required'));
  if (window.google?.accounts?.id) return Promise.resolve();
  if (googleIdentityScriptLoadPromise) return googleIdentityScriptLoadPromise;

  googleIdentityScriptLoadPromise = new Promise<void>((resolve, reject) => {
    const script = document.createElement('script');
    let settled = false;
    const finishResolve = () => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timeout);
      resolve();
    };
    const finishReject = (error: Error) => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timeout);
      googleIdentityScriptLoadPromise = null;
      reject(error);
    };
    const timeout = window.setTimeout(() => {
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
  mode: GooglePromptMode,
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
      logGooglePromptDiagnostics(
        'One Tap display timeout',
        readGooglePromptDiagnostics({ clientId, mode }),
        'warn',
      );
      finishReject(makeGooglePromptError({ stage: 'not_displayed', reason: 'unknown_reason' }));
    }, GOOGLE_IDENTITY_PROMPT_DISPLAY_TIMEOUT_MS);
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
    });
    logGooglePromptDiagnostics(
      'One Tap prompt requested',
      readGooglePromptDiagnostics({ clientId, mode }),
    );

    googleIdApi.prompt((notification) => {
      if (settled) return;
      const diagnostics = readGooglePromptDiagnostics({ clientId, mode, notification });
      logGooglePromptDiagnostics('One Tap prompt moment', diagnostics);
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
        logGooglePromptDiagnostics('One Tap not displayed', diagnostics, 'warn');
        finishReject(makeGooglePromptError({ stage: 'not_displayed', reason }));
        return;
      }
      if (skipped) {
        const reason = normalizeGooglePromptReason(notification?.getSkippedReason?.(), 'skipped');
        logGooglePromptDiagnostics('One Tap skipped', diagnostics, 'warn');
        finishReject(makeGooglePromptError({ stage: 'skipped', reason }));
        return;
      }
      if (dismissed) {
        const reason = normalizeGooglePromptReason(
          notification?.getDismissedReason?.(),
          'dismissed',
        );
        logGooglePromptDiagnostics('One Tap dismissed', diagnostics, 'warn');
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
  return await withGoogleIdentityTimeout(requestGoogleIdTokenWithPromptMode(clientId, 'standard'));
}
