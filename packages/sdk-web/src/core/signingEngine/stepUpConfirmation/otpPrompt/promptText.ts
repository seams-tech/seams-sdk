export function formatEmailOtpSentText(emailHint?: string): string {
  const recipient = String(emailHint || '').trim() || 'your email';
  return `Enter the 6-digit code sent to ${recipient}`;
}
