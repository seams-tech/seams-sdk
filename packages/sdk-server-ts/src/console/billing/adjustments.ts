import { ConsoleBillingError } from './errors';
import type { BillingManualAdjustmentRequest } from './types';

export const LARGE_MANUAL_ADMIN_DEBIT_THRESHOLD_MINOR = 50_000;

interface BillingAdjustmentActorContext {
  roles: string[];
}

function hasConsoleRole(roles: readonly string[], targetRole: string): boolean {
  return roles.some(
    (role) =>
      String(role || '')
        .trim()
        .toLowerCase() === targetRole,
  );
}

export function requireBillingAdjustmentRole(ctx: BillingAdjustmentActorContext): void {
  if (hasConsoleRole(ctx.roles || [], 'platform_admin')) return;
  throw new ConsoleBillingError(
    'forbidden',
    403,
    'Only platform_admin can append manual billing adjustments',
  );
}

export function requireLargeManualAdminDebitEscalationRole(
  ctx: BillingAdjustmentActorContext,
  amountMinor: number,
): void {
  if (Math.trunc(Number(amountMinor || 0)) < LARGE_MANUAL_ADMIN_DEBIT_THRESHOLD_MINOR) return;
  if (
    hasConsoleRole(ctx.roles || [], 'owner') ||
    hasConsoleRole(ctx.roles || [], 'platform_admin')
  ) {
    return;
  }
  throw new ConsoleBillingError(
    'forbidden',
    403,
    `Manual admin debits of ${formatUsdMinor(LARGE_MANUAL_ADMIN_DEBIT_THRESHOLD_MINOR)} or more require owner or platform_admin role`,
  );
}

export function normalizeManualAdjustmentRequest(
  request: BillingManualAdjustmentRequest,
): BillingManualAdjustmentRequest {
  const amountMinor = Math.trunc(Number(request.amountMinor || 0));
  const reasonCode = String(request.reasonCode || '').trim();
  const note = String(request.note || '').trim();
  const idempotencyKey = String(request.idempotencyKey || '').trim();
  const relatedInvoiceId = String(request.relatedInvoiceId || '').trim();

  if (amountMinor <= 0) {
    throw new ConsoleBillingError(
      'invalid_manual_adjustment',
      400,
      'Manual adjustment amount must be positive',
    );
  }
  if (!reasonCode) {
    throw new ConsoleBillingError(
      'invalid_manual_adjustment',
      400,
      'Manual adjustment reasonCode is required',
    );
  }
  if (!note) {
    throw new ConsoleBillingError(
      'invalid_manual_adjustment',
      400,
      'Manual adjustment note is required',
    );
  }
  if (!idempotencyKey) {
    throw new ConsoleBillingError(
      'invalid_manual_adjustment',
      400,
      'Manual adjustment idempotencyKey is required',
    );
  }

  return {
    amountMinor,
    reasonCode,
    note,
    idempotencyKey,
    ...(relatedInvoiceId ? { relatedInvoiceId } : {}),
  };
}

export function requireKnownManualAdjustmentRelatedInvoiceId(input: {
  relatedInvoiceId: string | null | undefined;
  knownInvoiceIds: ReadonlySet<string>;
}): string | null {
  const relatedInvoiceId = String(input.relatedInvoiceId || '').trim();
  if (!relatedInvoiceId) return null;
  if (input.knownInvoiceIds.has(relatedInvoiceId)) return relatedInvoiceId;
  throw new ConsoleBillingError(
    'invalid_manual_adjustment',
    400,
    `Manual adjustment relatedInvoiceId was not found: ${relatedInvoiceId}`,
  );
}

function formatUsdMinor(amountMinor: number): string {
  const n = Number(amountMinor || 0);
  return `$${(n / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}
