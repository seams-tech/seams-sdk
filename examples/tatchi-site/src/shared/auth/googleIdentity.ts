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
    use_fedcm_for_prompt?: boolean;
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

type GooglePromptStage = 'not_displayed' | 'skipped';

type GooglePromptFailureDetails = {
  stage: GooglePromptStage;
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
  stage: 'not_displayed' | 'skipped';
  reason: string;
}): string {
  const { stage, reason } = input;
  if (reason === 'unknown_reason') {
    return 'Google sign-in is blocked by browser sign-in settings (FedCM/third-party sign-in). Enable Google sign-in for this site and retry.';
  }
  if (stage === 'not_displayed') {
    return `Google sign-in is unavailable (${reason}).`;
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
    const finishResolve = (token: string) => {
      if (settled) return;
      settled = true;
      resolve(token);
    };
    const finishReject = (input: string | Error) => {
      if (settled) return;
      settled = true;
      if (input instanceof Error) {
        reject(input);
        return;
      }
      reject(new Error(input));
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
      use_fedcm_for_prompt: useFedcmForPrompt,
    });

    googleIdApi.prompt((notification) => {
      if (settled) return;
      const notDisplayed = notification?.isNotDisplayed?.() === true;
      const skipped = notification?.isSkippedMoment?.() === true;
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
      }
    });
  });
}

export async function requestGoogleIdToken(clientId: string): Promise<string> {
  try {
    // First prefer non-FedCM prompt mode.
    return await requestGoogleIdTokenWithPromptMode(clientId, false);
  } catch (error: unknown) {
    if (!isUnknownPromptFailure(error)) {
      throw error;
    }
  }

  // If browser returns unknown prompt failure, retry with FedCM prompt mode.
  return await requestGoogleIdTokenWithPromptMode(clientId, true);
}
