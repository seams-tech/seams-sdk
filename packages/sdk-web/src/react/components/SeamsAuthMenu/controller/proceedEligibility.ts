import { AuthMenuMode } from '../types';

export interface ProceedEligibilityArgs {
  mode: AuthMenuMode;
  currentValue: string;
  targetExists: boolean;
  secure: boolean;
  registrationRequiresAccountInput: boolean;
  canRestoreSyncedPasskey: boolean;
}

export interface ProceedEligibilityResult {
  canShowContinue: boolean;
  canSubmit: boolean;
}

export function getProceedEligibility({
  mode,
  currentValue,
  targetExists,
  secure,
  registrationRequiresAccountInput,
  canRestoreSyncedPasskey,
}: ProceedEligibilityArgs): ProceedEligibilityResult {
  const hasInput = currentValue.length > 0;
  if (mode === AuthMenuMode.Register) {
    if (!registrationRequiresAccountInput) {
      return {
        canShowContinue: true,
        canSubmit: hasInput && secure,
      };
    }
    return {
      canShowContinue: hasInput && !targetExists,
      canSubmit: hasInput && secure && !targetExists,
    };
  }
  if (mode === AuthMenuMode.Login) {
    return {
      canShowContinue: hasInput && (targetExists || canRestoreSyncedPasskey),
      canSubmit: hasInput && (targetExists || canRestoreSyncedPasskey),
    };
  }
  return { canShowContinue: true, canSubmit: true };
}

export default getProceedEligibility;
