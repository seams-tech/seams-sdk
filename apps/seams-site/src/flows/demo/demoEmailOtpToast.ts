import { toast } from 'sonner';

const activeDemoEmailOtpCodes = new Map<string, string>();

export type DemoEmailOtpToastInput = {
  otpCode: string;
  toastId: string;
  unavailableDescription: string;
};

export function formatDemoEmailOtpCode(otpCode: string): string {
  return `${otpCode.slice(0, 3)}-${otpCode.slice(3)}`;
}

export function dismissDemoEmailOtpToast(toastId: string): void {
  activeDemoEmailOtpCodes.delete(toastId);
  toast.dismiss(toastId);
}

export async function showCopiedDemoEmailOtpToast(input: DemoEmailOtpToastInput): Promise<void> {
  const formattedCode = formatDemoEmailOtpCode(input.otpCode);
  activeDemoEmailOtpCodes.set(input.toastId, input.otpCode);
  toast.info(`OTP code ${formattedCode}`, {
    id: input.toastId,
    description: 'Copying code to clipboard...',
    duration: Infinity,
  });

  try {
    await navigator.clipboard.writeText(input.otpCode);
    if (activeDemoEmailOtpCodes.get(input.toastId) !== input.otpCode) return;
    toast.success(`OTP code ${formattedCode} copied to clipboard!`, {
      id: input.toastId,
      description: input.unavailableDescription,
      duration: Infinity,
    });
  } catch {
    if (activeDemoEmailOtpCodes.get(input.toastId) !== input.otpCode) return;
    toast.info(`OTP code ${formattedCode}`, {
      id: input.toastId,
      description: 'Clipboard access was unavailable. Enter this code to continue.',
      duration: Infinity,
    });
  }
}
