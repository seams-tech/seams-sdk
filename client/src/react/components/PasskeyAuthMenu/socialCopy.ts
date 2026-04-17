import type { EmailOtpAuthPolicy } from '@/core/types/tatchi';
import { AuthMenuMode } from './authMenuTypes';

export function getGoogleSsoButtonLabel(mode: AuthMenuMode): string {
  if (mode === AuthMenuMode.Register) return 'Register with Google SSO';
  if (mode === AuthMenuMode.Login) return 'Sign in with Google SSO';
  return 'Continue with Google SSO';
}

export function getGoogleSsoHelperText(
  mode: AuthMenuMode,
  emailOtpAuthPolicy: EmailOtpAuthPolicy,
): string {
  if (mode === AuthMenuMode.Register) {
    return 'Creates a Google SSO account that uses a 6-digit Email OTP for signing. Passkey is recommended for stronger security.';
  }

  if (emailOtpAuthPolicy === 'per_operation') {
    return 'Google SSO signs you in, then a 6-digit email code is required for each signing operation. Passkey is recommended for stronger security.';
  }

  return 'Google SSO signs you in, then a 6-digit email code unlocks signing for this session. Passkey is recommended for stronger security.';
}
