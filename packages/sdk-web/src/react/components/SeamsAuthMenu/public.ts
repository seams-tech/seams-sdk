import { SeamsAuthMenu } from './shell';
import { SeamsAuthMenuSkeleton } from './skeleton';
import type {
  SeamsAuthMenuPasskeyLoginRequest,
  SeamsAuthMenuProps,
  SeamsAuthMenuRegistrationRequest,
  SeamsAuthMenuSocialLoginArgs,
  SeamsAuthMenuSocialLoginHandler,
  SeamsAuthMenuSyncAccountRequest,
} from './types';
import {
  AuthMenuMode,
  AuthMenuModeMap,
  type AuthMenuModeLabel,
  type AuthMenuHeadings,
} from './authMenuTypes';

/**
 * SSR-safe entrypoint for `@seams/sdk/react/seams-auth-menu`.
 *
 * This imports only shell, skeleton, and type exports so SSR can load the
 * public module without browser-only client dependencies.
 */
export { SeamsAuthMenu, SeamsAuthMenuSkeleton };
export type {
  SeamsAuthMenuPasskeyLoginRequest,
  SeamsAuthMenuProps,
  SeamsAuthMenuRegistrationRequest,
  SeamsAuthMenuSocialLoginArgs,
  SeamsAuthMenuSocialLoginHandler,
  SeamsAuthMenuSyncAccountRequest,
};

export { AuthMenuMode, AuthMenuModeMap };
export type { AuthMenuModeLabel, AuthMenuHeadings };

export default SeamsAuthMenu;
