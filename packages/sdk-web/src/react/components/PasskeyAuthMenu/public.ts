import { PasskeyAuthMenu } from './shell';
import { PasskeyAuthMenuSkeleton } from './skeleton';
import type { PasskeyAuthMenuProps } from './types';
import {
  AuthMenuMode,
  AuthMenuModeMap,
  type AuthMenuModeLabel,
  type AuthMenuHeadings,
} from './authMenuTypes';

/**
 * SSR-safe entrypoint for `@seams/sdk/react/passkey-auth-menu`.
 *
 * This imports only shell, skeleton, and type exports so SSR can load the
 * public module without browser-only client dependencies.
 */
export { PasskeyAuthMenu, PasskeyAuthMenuSkeleton };
export type { PasskeyAuthMenuProps };

export { AuthMenuMode, AuthMenuModeMap };
export type { AuthMenuModeLabel, AuthMenuHeadings };

export default PasskeyAuthMenu;
