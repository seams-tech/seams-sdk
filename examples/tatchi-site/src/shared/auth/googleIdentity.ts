export interface GoogleIdCredentialResponse {
  credential?: string;
}

export interface GoogleIdPromptMomentNotification {
  isNotDisplayed?: () => boolean;
  isSkippedMoment?: () => boolean;
  getNotDisplayedReason?: () => string;
  getSkippedReason?: () => string;
}

export interface GoogleIdentityApi {
  initialize(config: {
    client_id: string;
    callback: (response: GoogleIdCredentialResponse) => void;
    auto_select?: boolean;
    cancel_on_tap_outside?: boolean;
  }): void;
  prompt(notification?: (event: GoogleIdPromptMomentNotification) => void): void;
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

export function ensureGoogleIdentityScriptLoaded(): Promise<void> {
  if (typeof window === 'undefined') return Promise.reject(new Error('Browser runtime is required'));
  if (window.google?.accounts?.id) return Promise.resolve();
  if (googleIdentityScriptLoadPromise) return googleIdentityScriptLoadPromise;

  googleIdentityScriptLoadPromise = new Promise<void>((resolve, reject) => {
    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    script.onload = () => {
      if (window.google?.accounts?.id) {
        resolve();
        return;
      }
      reject(new Error('Google Identity API loaded without accounts.id'));
    };
    script.onerror = () => reject(new Error('Failed to load Google Identity script'));
    document.head.appendChild(script);
  });

  return googleIdentityScriptLoadPromise;
}

export function requestGoogleIdToken(clientId: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const googleIdApi = window.google?.accounts?.id;
    if (!googleIdApi) {
      reject(new Error('Google Identity API is unavailable'));
      return;
    }

    let settled = false;
    const finishResolve = (token: string) => {
      if (settled) return;
      settled = true;
      resolve(token);
    };
    const finishReject = (message: string) => {
      if (settled) return;
      settled = true;
      reject(new Error(message));
    };

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
      auto_select: false,
      cancel_on_tap_outside: true,
    });

    googleIdApi.prompt((notification) => {
      if (settled) return;
      const notDisplayed = notification?.isNotDisplayed?.() === true;
      const skipped = notification?.isSkippedMoment?.() === true;
      if (notDisplayed) {
        const reason = String(notification?.getNotDisplayedReason?.() || 'not_displayed').trim();
        finishReject(`Google sign-in is unavailable (${reason}).`);
        return;
      }
      if (skipped) {
        const reason = String(notification?.getSkippedReason?.() || 'skipped').trim();
        finishReject(`Google sign-in was skipped (${reason}).`);
      }
    });
  });
}
