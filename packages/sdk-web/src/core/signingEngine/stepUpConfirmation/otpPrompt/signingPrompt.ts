import type { EmailOtpConfirmPrompt } from '../types';
import { formatEmailOtpSentText } from './promptText';

export type EmailOtpSigningChallenge = {
  challengeId: string;
  emailHint?: string;
};

export type EmailOtpSigningPromptSource = {
  prepare: () => Promise<EmailOtpSigningChallenge>;
  resend?: () => Promise<EmailOtpSigningChallenge>;
};

export function buildEmailOtpSigningPrompt(args: {
  challenge: EmailOtpSigningChallenge;
  resend?: EmailOtpSigningPromptSource['resend'];
}): EmailOtpConfirmPrompt {
  return {
    challengeId: args.challenge.challengeId,
    ...(args.challenge.emailHint ? { emailHint: args.challenge.emailHint } : {}),
    title: 'Enter email code to sign',
    helperText: formatEmailOtpSentText(args.challenge.emailHint),
    ...(args.resend ? { onResend: args.resend } : {}),
  };
}

export async function prepareEmailOtpSigningPrompt(
  source: EmailOtpSigningPromptSource | undefined,
): Promise<EmailOtpConfirmPrompt | undefined> {
  if (!source) return undefined;
  const challenge = await source.prepare();
  return buildEmailOtpSigningPrompt({ challenge, resend: source.resend });
}
