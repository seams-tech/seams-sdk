import type {
  CloudflareD1EmailOtpDeliveryProvider,
  CloudflareD1EmailOtpDeliveryProviderInput,
  CloudflareD1EmailOtpDeliveryProviderResult,
} from '@seams/wallet-server/cloud-host';

export type EmailOtpMessage = {
  readonly deliveryId: string;
  readonly recipientEmail: string;
  readonly subject: string;
  readonly text: string;
  readonly html: string;
};

export interface EmailOtpMessageProvider {
  send(message: EmailOtpMessage): Promise<CloudflareD1EmailOtpDeliveryProviderResult>;
}

export interface RenderedEmailOtpMessage {
  readonly subject: string;
  readonly text: string;
  readonly html: string;
}

type EmailOtpOperationCopy = {
  readonly subject: string;
  readonly heading: string;
  readonly introduction: string;
  readonly caution: string;
};

export function createEmailOtpDeliveryAdapter(
  provider: EmailOtpMessageProvider,
  now: () => number = Date.now,
): CloudflareD1EmailOtpDeliveryProvider {
  return new EmailOtpDeliveryAdapter(provider, now);
}

class EmailOtpDeliveryAdapter implements CloudflareD1EmailOtpDeliveryProvider {
  constructor(
    private readonly provider: EmailOtpMessageProvider,
    private readonly now: () => number,
  ) {}

  async deliver(
    input: CloudflareD1EmailOtpDeliveryProviderInput,
  ): Promise<CloudflareD1EmailOtpDeliveryProviderResult> {
    const rendered = renderEmailOtpMessage({
      operation: input.operation,
      otpCode: input.otpCode,
      expiresAtMs: input.expiresAtMs,
      nowMs: this.now(),
    });
    return this.provider.send({
      deliveryId: input.challengeId,
      recipientEmail: input.email,
      subject: rendered.subject,
      text: rendered.text,
      html: rendered.html,
    });
  }
}

export function renderEmailOtpMessage(
  input: Pick<
    CloudflareD1EmailOtpDeliveryProviderInput,
    'operation' | 'otpCode' | 'expiresAtMs'
  > & { readonly nowMs: number },
): RenderedEmailOtpMessage {
  const copy = emailOtpOperationCopy(input.operation);
  const expiry = expiryText(input.expiresAtMs, input.nowMs);
  const text = [
    copy.heading,
    copy.introduction,
    `Your one-time code is: ${input.otpCode}`,
    `This code expires ${expiry}.`,
    copy.caution,
    'Seams staff will never ask for this code. If you did not request this action, ignore this email.',
  ].join('\n\n');
  const htmlCode = escapeHtml(input.otpCode);
  return {
    subject: copy.subject,
    text,
    html: `<!doctype html>
<html lang="en">
  <body style="margin:0;background:#f4f4f5;color:#18181b;font-family:Arial,sans-serif;">
    <div style="display:none;max-height:0;overflow:hidden;opacity:0;">${escapeHtml(copy.introduction)}</div>
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f4f4f5;padding:32px 16px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:520px;background:#ffffff;border:1px solid #e4e4e7;border-radius:12px;">
            <tr>
              <td style="padding:32px;">
                <p style="margin:0 0 20px;color:#52525b;font-size:15px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;">Seams</p>
                <h1 style="margin:0 0 16px;font-size:24px;line-height:1.25;">${escapeHtml(copy.heading)}</h1>
                <p style="margin:0 0 24px;color:#3f3f46;font-size:16px;line-height:1.6;">${escapeHtml(copy.introduction)}</p>
                <div aria-label="One-time code" style="margin:0 0 24px;padding:18px 16px;border-radius:10px;background:#18181b;color:#ffffff;font-family:monospace;font-size:32px;font-weight:700;letter-spacing:0.2em;text-align:center;">${htmlCode}</div>
                <p style="margin:0 0 16px;color:#3f3f46;font-size:15px;line-height:1.6;">This code expires ${escapeHtml(expiry)}.</p>
                <p style="margin:0 0 16px;color:#3f3f46;font-size:15px;line-height:1.6;">${escapeHtml(copy.caution)}</p>
                <p style="margin:0;color:#71717a;font-size:14px;line-height:1.6;">Seams staff will never ask for this code. If you did not request this action, ignore this email.</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`,
  };
}

function emailOtpOperationCopy(
  operation: CloudflareD1EmailOtpDeliveryProviderInput['operation'],
): EmailOtpOperationCopy {
  switch (operation) {
    case 'registration':
      return {
        subject: 'Your Seams registration code',
        heading: 'Confirm your wallet registration',
        introduction: 'Enter this code to finish creating your Seams wallet.',
        caution: 'Continue only if you started this wallet registration.',
      };
    case 'wallet_unlock':
      return {
        subject: 'Your Seams wallet unlock code',
        heading: 'Confirm your wallet unlock',
        introduction: 'Enter this code to unlock your Seams wallet.',
        caution: 'Continue only if you requested access to this wallet.',
      };
    case 'transaction_sign':
      return {
        subject: 'Confirm your Seams transaction',
        heading: 'Confirm transaction signing',
        introduction: 'Enter this code to authorize signing a transaction with your Seams wallet.',
        caution: 'Review the transaction details in your wallet before entering the code.',
      };
    case 'export_key':
      return {
        subject: 'Confirm your Seams key export',
        heading: 'Confirm key export',
        introduction: 'Enter this code to authorize exporting your Seams wallet key material.',
        caution:
          'Exported key material grants full control of your wallet. Continue only if you requested it.',
      };
    default:
      return assertNever(operation);
  }
}

function expiryText(expiresAtMs: number, nowMs: number): string {
  const remainingMinutes = Math.max(1, Math.ceil((expiresAtMs - nowMs) / 60_000));
  return remainingMinutes === 1 ? 'in 1 minute' : `in ${remainingMinutes} minutes`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function assertNever(value: never): never {
  throw new Error(`Unsupported Email OTP operation: ${String(value)}`);
}
