export interface GoogleIdCredentialResponse {
  credential?: string;
}

export interface GoogleAuthOptions {
  configured: boolean;
  clientId?: string;
  message?: string;
}

export interface GoogleIdentityInitializeConfiguration {
  readonly client_id: string;
  readonly callback: (response: GoogleIdCredentialResponse) => void;
  readonly auto_select: boolean;
  readonly cancel_on_tap_outside: boolean;
  readonly ux_mode: 'popup' | 'redirect';
  readonly use_fedcm_for_prompt: boolean;
}

export interface GoogleIdentityApi {
  initialize(config: GoogleIdentityInitializeConfiguration): void;
  prompt(momentListener?: (notification: GooglePromptMomentNotification) => void): void;
  cancel?: () => void;
  disableAutoSelect?: () => void;
}

// Raw GIS prompt notifications vary by browser/FedCM mode; guard method reads at this boundary.
export interface GooglePromptMomentNotification {
  isNotDisplayed?: () => boolean;
  isSkippedMoment?: () => boolean;
  isDismissedMoment?: () => boolean;
  getNotDisplayedReason?: () => string;
  getSkippedReason?: () => string;
  getDismissedReason?: () => string;
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

type ActiveGoogleIdTokenRequest = {
  clientId: string;
  resolve: (token: string) => void;
  reject: (error: Error) => void;
  dispose: () => void;
};

let initializedGoogleClientId: string | null = null;
let activeGoogleIdTokenRequest: ActiveGoogleIdTokenRequest | null = null;

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

function makeGooglePromptTimeoutError(): Error {
  return new Error(
    'Google sign-in timed out. Select a Google account in the sign-in prompt or retry from a fresh Google session.',
  );
}

function readGooglePromptDiagnostics(clientId: string): Record<string, unknown> {
  return {
    mode: 'prompt',
    origin: typeof window !== 'undefined' ? window.location.origin : '',
    protocol: typeof window !== 'undefined' ? window.location.protocol : '',
    inIframe: typeof window !== 'undefined' ? window.self !== window.top : false,
    clientIdSuffix: clientId.slice(-16),
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

function handleGoogleCredentialResponse(response: GoogleIdCredentialResponse): void {
  const request = activeGoogleIdTokenRequest;
  if (!request) {
    console.warn('[Google SSO] Ignoring credential response without an active request');
    return;
  }

  activeGoogleIdTokenRequest = null;
  request.dispose();
  const token = String(response?.credential || '').trim();
  if (!token) {
    request.reject(new Error('Google sign-in did not return an id_token'));
    return;
  }
  request.resolve(token);
}

function initializeGoogleIdentityForClientId(input: {
  googleIdApi: GoogleIdentityApi;
  clientId: string;
}): void {
  if (initializedGoogleClientId === input.clientId) return;

  input.googleIdApi.initialize({
    client_id: input.clientId,
    callback: handleGoogleCredentialResponse,
    auto_select: true,
    cancel_on_tap_outside: false,
    ux_mode: 'popup',
    use_fedcm_for_prompt: true,
  });
  initializedGoogleClientId = input.clientId;
}

function googlePromptMomentFailure(
  notification: GooglePromptMomentNotification,
): Error | null {
  if (notification.isNotDisplayed?.()) {
    const reason = notification.getNotDisplayedReason?.() || 'not_displayed';
    return new Error(`Google sign-in prompt was not displayed (${reason})`);
  }
  if (notification.isSkippedMoment?.()) {
    const reason = notification.getSkippedReason?.() || 'skipped';
    return new Error(`Google sign-in prompt was skipped (${reason})`);
  }
  if (notification.isDismissedMoment?.()) {
    const reason = notification.getDismissedReason?.() || 'dismissed';
    return new Error(`Google sign-in prompt was dismissed (${reason})`);
  }
  return null;
}

function handleGooglePromptMoment(
  finishReject: (input: string | Error) => void,
  notification: GooglePromptMomentNotification,
): void {
  const failure = googlePromptMomentFailure(notification);
  if (failure) finishReject(failure);
}

function requestGoogleIdTokenWithPrompt(clientId: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const googleIdApi = window.google?.accounts?.id;
    if (!googleIdApi) {
      reject(new Error('Google Identity API is unavailable'));
      return;
    }
    if (activeGoogleIdTokenRequest) {
      reject(new Error('A Google sign-in request is already active'));
      return;
    }

    let settled = false;
    let requestTimeout: number | undefined;
    const clearTimers = () => {
      if (requestTimeout !== undefined) window.clearTimeout(requestTimeout);
      requestTimeout = undefined;
    };
    const cancelGooglePrompt = () => {
      try {
        googleIdApi.cancel?.();
      } catch {
        // Best-effort cleanup; Google Identity does not guarantee cancel availability.
      }
    };
    const finishResolve = (token: string) => {
      if (settled) return;
      settled = true;
      if (activeGoogleIdTokenRequest?.clientId === clientId) {
        activeGoogleIdTokenRequest = null;
      }
      clearTimers();
      resolve(token);
    };
    const finishReject = (input: string | Error) => {
      if (settled) return;
      settled = true;
      if (activeGoogleIdTokenRequest?.clientId === clientId) {
        activeGoogleIdTokenRequest = null;
      }
      clearTimers();
      cancelGooglePrompt();
      if (input instanceof Error) {
        reject(input);
        return;
      }
      reject(new Error(input));
    };

    requestTimeout = window.setTimeout(() => {
      finishReject(makeGooglePromptTimeoutError());
    }, GOOGLE_ID_TOKEN_TIMEOUT_MS);

    initializeGoogleIdentityForClientId({ googleIdApi, clientId });
    activeGoogleIdTokenRequest = {
      clientId,
      resolve: finishResolve,
      reject: finishReject,
      dispose: clearTimers,
    };
    logGooglePromptDiagnostics(
      'Google sign-in prompt requested',
      readGooglePromptDiagnostics(clientId),
    );
    try {
      googleIdApi.prompt(handleGooglePromptMoment.bind(null, finishReject));
    } catch (error: unknown) {
      finishReject(error instanceof Error ? error : new Error(String(error)));
    }
  });
}

export async function requestGoogleIdToken(clientId: string): Promise<string> {
  return await requestGoogleIdTokenWithPrompt(clientId);
}
