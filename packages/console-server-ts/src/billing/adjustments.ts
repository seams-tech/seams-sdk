import { ConsoleBillingError } from './errors';
import type { BillingManualAdjustmentRequest } from './types';

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
