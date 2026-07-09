import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import type { AuthMenuMode } from './authMenuTypes';
import { AuthMenuMode as AuthMenuModeValue } from './authMenuTypes';

function assertNeverMode(mode: never): never {
  throw new Error(`Unknown auth menu mode: ${String(mode)}`);
}

export function getPasskeyButtonLabel(mode: AuthMenuMode): string {
  switch (mode) {
    case AuthMenuModeValue.Register:
      return 'Sign up with Passkey';
    case AuthMenuModeValue.Login:
      return 'Sign in with Passkey';
    default:
      return assertNeverMode(mode);
  }
}

export function getGoogleSsoButtonLabel(mode: AuthMenuMode): string {
  switch (mode) {
    case AuthMenuModeValue.Register:
      return 'Sign up with Google';
    case AuthMenuModeValue.Login:
      return 'Sign in with Google';
    default:
      return assertNeverMode(mode);
  }
}

export function getGoogleSsoHelperText(
  mode: AuthMenuMode,
  emailOtpAuthPolicy: EmailOtpAuthPolicy,
): string {
  void mode;
  void emailOtpAuthPolicy;
  return '';
}
