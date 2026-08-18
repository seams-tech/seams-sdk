import React from 'react';
import type { AuthMenuHeadings } from '../types';
import { AuthMenuMode } from '../types';

export interface AuthMenuTitle {
  title: string;
  subtitle: string;
}

export function resolveDefaultMode(requested?: AuthMenuMode | null): AuthMenuMode {
  if (requested === AuthMenuMode.Register || requested === AuthMenuMode.Login) return requested;
  return AuthMenuMode.Login;
}

export function getModeTitle(
  mode: AuthMenuMode,
  headings?: AuthMenuHeadings | null,
): AuthMenuTitle {
  const defaults: Record<AuthMenuMode, AuthMenuTitle> = {
    [AuthMenuMode.Login]: { title: 'Sign in', subtitle: 'Continue with Passkey or Google SSO' },
    [AuthMenuMode.Register]: {
      title: 'Create your account',
      subtitle: 'Continue with Passkey or Google SSO',
    },
  } as const;

  if (headings) {
    if (mode === AuthMenuMode.Login && headings.login) return headings.login;
    if (mode === AuthMenuMode.Register && headings.registration) return headings.registration;
  }

  return defaults[mode] ?? defaults[AuthMenuMode.Login];
}

export interface UseAuthMenuModeArgs {
  defaultMode?: AuthMenuMode;
  currentValue: string;
  setCurrentValue: (v: string) => void;
  headings?: AuthMenuHeadings | null;
  /**
   * When true, forces the initial client render to start in Register mode.
   * This is used to align hydration with the shell skeleton.
   */
  forceInitialRegister?: boolean;
}

export interface UseAuthMenuModeResult {
  mode: AuthMenuMode;
  setMode: React.Dispatch<React.SetStateAction<AuthMenuMode>>;
  title: AuthMenuTitle;
  onIntentChange: (next: AuthMenuMode) => void;
  onInputChange: (val: string) => void;
  resetToDefault: () => void;
}

/**
 * `useAuthMenuMode`
 *
 * Minimal mode/title controller for SeamsAuthMenu.
 * - No IndexedDB/wallet-prefill logic yet (intentionally).
 * - Pure state transitions to keep the baseline bundle small and predictable.
 */
export function useAuthMenuMode({
  defaultMode,
  currentValue,
  setCurrentValue,
  headings,
  forceInitialRegister = false,
}: UseAuthMenuModeArgs): UseAuthMenuModeResult {
  const preferredDefaultMode = resolveDefaultMode(defaultMode);
  const [mode, setMode] = React.useState<AuthMenuMode>(() => {
    if (forceInitialRegister) return AuthMenuMode.Register;
    return preferredDefaultMode;
  });
  const title = React.useMemo(() => getModeTitle(mode, headings), [mode, headings]);

  const onIntentChange = (nextMode: AuthMenuMode) => {
    setMode(resolveDefaultMode(nextMode));
  };

  const onInputChange = (val: string) => {
    setCurrentValue(val);
  };

  const resetToDefault = () => {
    const nextMode = resolveDefaultMode(defaultMode);
    setMode(nextMode);
    setCurrentValue('');
  };

  return { mode, setMode, title, onIntentChange, onInputChange, resetToDefault };
}

export default useAuthMenuMode;
