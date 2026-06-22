import type { EmailOtpAuthPolicy } from '@/core/types/seams';
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
  void mode;
  void emailOtpAuthPolicy;
  return '';
}
