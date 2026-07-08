import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import type { AuthMenuMode } from './authMenuTypes';

export function getGoogleSsoButtonLabel(mode: AuthMenuMode): string {
  void mode;
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
