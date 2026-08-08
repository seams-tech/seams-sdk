export type NearAccountFundingNotice = {
  accountId: string;
  shortAccountId: string;
};

export const NEAR_TRANSACTION_SUBMITTING_NOTICE = 'Topping up account...';

const NEAR_ACCOUNT_FUNDING_NOTICE_PATTERN =
  /^NEAR account ([^\s]+) needs funding before signing\.$/;

export function shortenNearAccountForFundingNotice(accountId: string): string {
  const value = String(accountId || '').trim();
  if (value.length <= 8) return value;
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

export function formatNearAccountFundingNotice(nearAccountId: string): string {
  const accountId = String(nearAccountId || '').trim();
  if (!accountId) return 'NEAR account needs funding before signing.';
  return `NEAR account ${accountId} needs funding before signing.`;
}

export function parseNearAccountFundingNotice(body: string): NearAccountFundingNotice | null {
  const value = String(body || '').trim();
  const match = NEAR_ACCOUNT_FUNDING_NOTICE_PATTERN.exec(value);
  if (!match) return null;
  const accountId = String(match[1] || '').trim();
  if (!accountId) return null;
  return {
    accountId,
    shortAccountId: shortenNearAccountForFundingNotice(accountId),
  };
}

export function isNearTransactionSubmittingNotice(body: string): boolean {
  return String(body || '').trim() === NEAR_TRANSACTION_SUBMITTING_NOTICE;
}

/**
 * Shown while an unfunded implicit account is being funded, which happens after
 * the user confirms and before the step-up prompt. Funding is a real NEAR
 * transaction, so this is the one step in the confirmation that can take
 * seconds — without it the prompt keeps saying the account "needs funding" next
 * to a bare spinner, and a legitimate wait reads as a hang.
 */
export function formatNearAccountFundingProgressNotice(nearAccountId: string): string {
  const accountId = shortenNearAccountForFundingNotice(nearAccountId);
  return accountId ? `Funding NEAR account ${accountId}...` : 'Funding NEAR account...';
}

function isNearAccountFundingProgressNotice(body: string): boolean {
  const value = String(body || '').trim();
  return value.startsWith('Funding NEAR account') && value.endsWith('...');
}

/** Body copy that reports work in progress rather than describing the request. */
export function isNearSigningProgressNotice(body: string): boolean {
  return isNearTransactionSubmittingNotice(body) || isNearAccountFundingProgressNotice(body);
}

function copyTextWithTextArea(text: string): void {
  const textArea = document.createElement('textarea');
  textArea.value = text;
  textArea.setAttribute('readonly', '');
  textArea.style.position = 'fixed';
  textArea.style.inset = '0 auto auto 0';
  textArea.style.opacity = '0';
  textArea.style.pointerEvents = 'none';
  document.body.appendChild(textArea);
  textArea.select();
  document.execCommand('copy');
  textArea.remove();
}

export async function copyTextToClipboard(text: string): Promise<void> {
  const value = String(text || '').trim();
  if (!value) return;
  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {}
  }
  if (typeof document !== 'undefined') copyTextWithTextArea(value);
}
