export interface GoogleIdCredentialResponse {
  credential?: string;
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
    ux_mode?: 'popup' | 'redirect';
    use_fedcm_for_button?: boolean;
    button_auto_select?: boolean;
  }): void;
  renderButton(parent: HTMLElement, options: GoogleSignInButtonConfiguration): void;
  cancel?: () => void;
  disableAutoSelect?: () => void;
}

export interface GoogleSignInButtonConfiguration {
  type?: 'standard' | 'icon';
  theme?: 'outline' | 'filled_blue' | 'filled_black';
  size?: 'large' | 'medium' | 'small';
  text?: 'signin_with' | 'signup_with' | 'continue_with' | 'signin';
  shape?: 'rectangular' | 'pill' | 'circle' | 'square';
  logo_alignment?: 'left' | 'center';
  width?: string | number;
  state?: string;
  click_listener?: () => void;
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

type GoogleSignInButtonPrompt = {
  buttonContainer: HTMLDivElement;
  dispose: () => void;
};

function makeGooglePromptTimeoutError(): Error {
  return new Error(
    'Google sign-in timed out. Select a Google account in the sign-in prompt or retry from a fresh Google session.',
  );
}

function readGoogleButtonDiagnostics(clientId: string): Record<string, unknown> {
  return {
    mode: 'button',
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
    auto_select: false,
    cancel_on_tap_outside: false,
    ux_mode: 'popup',
    use_fedcm_for_button: true,
    button_auto_select: false,
  });
  initializedGoogleClientId = input.clientId;
}

function googleSignInButtonOptions(): GoogleSignInButtonConfiguration {
  return {
    type: 'standard',
    theme: 'outline',
    size: 'large',
    text: 'continue_with',
    shape: 'pill',
    logo_alignment: 'left',
    width: 320,
  };
}

function styleGoogleButtonOverlay(root: HTMLDivElement): void {
  Object.assign(root.style, {
    position: 'fixed',
    inset: '0',
    zIndex: '2147483647',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: 'rgba(32, 28, 38, 0.28)',
  });
}

function styleGoogleButtonPanel(panel: HTMLDivElement): void {
  Object.assign(panel.style, {
    width: 'min(360px, calc(100vw - 32px))',
    padding: '20px',
    borderRadius: '18px',
    border: '1px solid rgba(93, 86, 128, 0.22)',
    background: '#fffaf3',
    boxShadow: '0 18px 50px rgba(32, 28, 38, 0.18)',
    color: '#5d5680',
    fontFamily: 'inherit',
    textAlign: 'center',
  });
}

function styleGoogleButtonTitle(title: HTMLDivElement): void {
  Object.assign(title.style, {
    fontWeight: '700',
    fontSize: '18px',
    marginBottom: '12px',
  });
}

function styleGoogleButtonContainer(container: HTMLDivElement): void {
  Object.assign(container.style, {
    display: 'flex',
    justifyContent: 'center',
    minHeight: '44px',
  });
}

function styleGoogleCancelButton(button: HTMLButtonElement): void {
  Object.assign(button.style, {
    marginTop: '14px',
    border: '0',
    background: 'transparent',
    color: '#7b739e',
    font: 'inherit',
    fontWeight: '600',
    cursor: 'pointer',
  });
}

function createGoogleSignInButtonPrompt(input: { onCancel: () => void }): GoogleSignInButtonPrompt {
  if (!document.body) {
    throw new Error('Google sign-in requires a document body');
  }
  const root = document.createElement('div');
  root.dataset.googleSignInButtonPrompt = 'true';
  styleGoogleButtonOverlay(root);

  const panel = document.createElement('div');
  styleGoogleButtonPanel(panel);

  const title = document.createElement('div');
  title.textContent = 'Continue with Google';
  styleGoogleButtonTitle(title);

  const buttonContainer = document.createElement('div');
  styleGoogleButtonContainer(buttonContainer);

  const cancelButton = document.createElement('button');
  cancelButton.type = 'button';
  cancelButton.textContent = 'Cancel';
  styleGoogleCancelButton(cancelButton);
  cancelButton.addEventListener('click', input.onCancel);

  panel.append(title, buttonContainer, cancelButton);
  root.append(panel);
  document.body.appendChild(root);

  return {
    buttonContainer,
    dispose: () => {
      cancelButton.removeEventListener('click', input.onCancel);
      root.remove();
    },
  };
}

function requestGoogleIdTokenWithButton(clientId: string): Promise<string> {
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
    let prompt: GoogleSignInButtonPrompt | null = null;
    const clearTimers = () => {
      if (requestTimeout !== undefined) window.clearTimeout(requestTimeout);
      requestTimeout = undefined;
    };
    const disposePrompt = () => {
      prompt?.dispose();
      prompt = null;
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
      disposePrompt();
      resolve(token);
    };
    const finishReject = (input: string | Error) => {
      if (settled) return;
      settled = true;
      if (activeGoogleIdTokenRequest?.clientId === clientId) {
        activeGoogleIdTokenRequest = null;
      }
      clearTimers();
      disposePrompt();
      cancelGooglePrompt();
      if (input instanceof Error) {
        reject(input);
        return;
      }
      reject(new Error(input));
    };

    prompt = createGoogleSignInButtonPrompt({
      onCancel: () => finishReject(new Error('Google sign-in was cancelled.')),
    });
    requestTimeout = window.setTimeout(() => {
      finishReject(makeGooglePromptTimeoutError());
    }, GOOGLE_ID_TOKEN_TIMEOUT_MS);

    initializeGoogleIdentityForClientId({ googleIdApi, clientId });
    activeGoogleIdTokenRequest = {
      clientId,
      resolve: finishResolve,
      reject: finishReject,
      dispose: disposePrompt,
    };
    logGooglePromptDiagnostics(
      'Sign in with Google button rendered',
      readGoogleButtonDiagnostics(clientId),
    );
    try {
      googleIdApi.renderButton(prompt.buttonContainer, googleSignInButtonOptions());
    } catch (error: unknown) {
      finishReject(error instanceof Error ? error : new Error(String(error)));
    }
  });
}

export async function requestGoogleIdToken(clientId: string): Promise<string> {
  return await requestGoogleIdTokenWithButton(clientId);
}
