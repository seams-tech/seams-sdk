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
const GOOGLE_ID_TOKEN_TIMEOUT_MS = 20_000;
const GOOGLE_IDENTITY_SCRIPT_TIMEOUT_MS = 15_000;

let initializedGoogleClientId: string | null = null;
let activeGoogleIdTokenRequest: GoogleIdTokenRequest | null = null;

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
    'Google One Tap did not open or return an id_token. Check FedCM permissions, disable blockers for this site, then retry.',
  );
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

  const token = String(response?.credential || '').trim();
  if (!token) {
    request.fail(new Error('Google sign-in did not return an id_token'));
    return;
  }
  request.succeed(token);
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

function googlePromptFailure(notification: GooglePromptMomentNotification): Error | null {
  if (notification.isNotDisplayed?.()) {
    return new Error(
      `Google One Tap was not displayed (${notification.getNotDisplayedReason?.() || 'not_displayed'})`,
    );
  }
  if (notification.isSkippedMoment?.()) {
    return new Error(
      `Google One Tap was skipped (${notification.getSkippedReason?.() || 'skipped'})`,
    );
  }
  if (notification.isDismissedMoment?.()) {
    return new Error(
      `Google One Tap was dismissed (${notification.getDismissedReason?.() || 'dismissed'})`,
    );
  }
  return null;
}

class GoogleIdTokenRequest {
  private settled = false;
  private timeoutId: number | null = null;

  constructor(
    readonly clientId: string,
    private readonly googleIdApi: GoogleIdentityApi,
    private readonly resolvePromise: (token: string) => void,
    private readonly rejectPromise: (error: Error) => void,
  ) {}

  start(): void {
    this.timeoutId = window.setTimeout(this.onTimeout, GOOGLE_ID_TOKEN_TIMEOUT_MS);
    this.googleIdApi.prompt(this.onPromptMoment);
  }

  succeed(token: string): void {
    if (this.settled) return;
    this.settled = true;
    this.dispose();
    this.resolvePromise(token);
  }

  fail(error: Error): void {
    if (this.settled) return;
    this.settled = true;
    this.dispose();
    this.rejectPromise(error);
  }

  private readonly onPromptMoment = (notification: GooglePromptMomentNotification): void => {
    const failure = googlePromptFailure(notification);
    if (failure) this.fail(failure);
  };

  private readonly onTimeout = (): void => {
    this.fail(makeGooglePromptTimeoutError());
  };

  private dispose(): void {
    if (activeGoogleIdTokenRequest === this) activeGoogleIdTokenRequest = null;
    if (this.timeoutId !== null) window.clearTimeout(this.timeoutId);
    this.timeoutId = null;
    try {
      this.googleIdApi.cancel?.();
    } catch {}
  }
}

function requestGoogleIdTokenWithOneTap(clientId: string): Promise<string> {
  const googleIdApi = window.google?.accounts?.id;
  if (!googleIdApi) return Promise.reject(new Error('Google Identity API is unavailable'));
  if (activeGoogleIdTokenRequest) {
    return Promise.reject(new Error('A Google sign-in request is already active'));
  }
  initializeGoogleIdentityForClientId({ googleIdApi, clientId });
  return new Promise<string>((resolve, reject) => {
    const request = new GoogleIdTokenRequest(clientId, googleIdApi, resolve, reject);
    activeGoogleIdTokenRequest = request;
    try {
      request.start();
    } catch (error: unknown) {
      request.fail(error instanceof Error ? error : new Error(String(error)));
    }
  });
}

export function cancelGoogleIdTokenRequest(): void {
  activeGoogleIdTokenRequest?.fail(new Error('Google sign-in was cancelled'));
}

export async function requestGoogleIdToken(clientId: string): Promise<string> {
  return await requestGoogleIdTokenWithOneTap(clientId);
}
