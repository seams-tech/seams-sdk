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

  void emailOtpAuthPolicy;
  return '';
}
