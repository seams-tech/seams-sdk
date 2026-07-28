import { ConsoleBillingError } from './errors';
import type {
  BillingCreditPackId,
  StripeProviderRefundStatus,
  StripeRefundEventItem,
  StripeWebhookEventRequest,
} from './types';

type UnknownRecord = Readonly<Record<string, unknown>>;

export interface StripeWebhookVerificationInput {
  rawBody: string | Uint8Array;
  signatureHeader: string;
  secret: string;
  now?: Date;
  toleranceSeconds?: number;
}

interface ParsedStripeSignature {
  timestampSeconds: number;
  signatures: readonly string[];
}

const DEFAULT_SIGNATURE_TOLERANCE_SECONDS = 300;

function invalidSignature(message: string): ConsoleBillingError {
  return new ConsoleBillingError('invalid_stripe_signature', 400, message);
}

function invalidPayload(message: string): ConsoleBillingError {
  return new ConsoleBillingError('invalid_stripe_payload', 400, message);
}

function toRecord(value: unknown): UnknownRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return {};
  return value as UnknownRecord;
}

function readString(record: UnknownRecord, field: string): string {
  return typeof record[field] === 'string' ? record[field].trim() : '';
}

function readPositiveInteger(record: UnknownRecord, field: string): number {
  const value = Number(record[field]);
  if (!Number.isInteger(value) || value <= 0) {
    throw invalidPayload(`Stripe field ${field} must be a positive integer`);
  }
  return value;
}

function readMetadata(record: UnknownRecord): UnknownRecord {
  return toRecord(record.metadata);
}

function nullableString(value: string): string | null {
  return value || null;
}

function parseCreditPackId(value: string): BillingCreditPackId {
  switch (value) {
    case 'usd_10':
    case 'usd_25':
    case 'usd_50':
      return value;
    default:
      throw invalidPayload(`Unsupported Stripe credit pack: ${value || 'empty'}`);
  }
}

function parseSignatureHeader(signatureHeader: string): ParsedStripeSignature {
  let timestampSeconds = 0;
  const signatures: string[] = [];
  for (const part of signatureHeader.split(',')) {
    const separator = part.indexOf('=');
    if (separator <= 0) continue;
    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (key === 't' && !timestampSeconds) {
      const parsed = Number(value);
      if (Number.isInteger(parsed) && parsed > 0) timestampSeconds = parsed;
    }
    if (key === 'v1' && /^[0-9a-fA-F]{64}$/.test(value)) {
      signatures.push(value.toLowerCase());
    }
  }
  if (!timestampSeconds || signatures.length === 0) {
    throw invalidSignature('Stripe-Signature must include a timestamp and v1 signature');
  }
  return { timestampSeconds, signatures };
}

function bodyBytes(rawBody: string | Uint8Array): Uint8Array {
  return typeof rawBody === 'string' ? new TextEncoder().encode(rawBody) : rawBody;
}

function signedPayloadBytes(timestampSeconds: number, rawBody: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(`${timestampSeconds}.`);
  const payload = new Uint8Array(prefix.length + rawBody.length);
  payload.set(prefix);
  payload.set(rawBody, prefix.length);
  return payload;
}

function bytesToHex(bytes: Uint8Array): string {
  let output = '';
  for (const byte of bytes) output += byte.toString(16).padStart(2, '0');
  return output;
}

function constantTimeHexEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let mismatch = 0;
  for (let index = 0; index < left.length; index += 1) {
    mismatch |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return mismatch === 0;
}

function signatureMatches(expected: string, supplied: readonly string[]): boolean {
  let matched = false;
  for (const signature of supplied) {
    matched = constantTimeHexEqual(expected, signature) || matched;
  }
  return matched;
}

export async function verifyStripeWebhookSignature(
  input: StripeWebhookVerificationInput,
): Promise<void> {
  const secret = input.secret.trim();
  if (!secret) throw invalidSignature('Stripe webhook secret is required');
  const parsed = parseSignatureHeader(input.signatureHeader);
  const nowSeconds = Math.floor((input.now || new Date()).getTime() / 1000);
  const toleranceSeconds = input.toleranceSeconds ?? DEFAULT_SIGNATURE_TOLERANCE_SECONDS;
  if (!Number.isInteger(toleranceSeconds) || toleranceSeconds < 0) {
    throw new Error('Stripe signature tolerance must be a non-negative integer');
  }
  if (Math.abs(nowSeconds - parsed.timestampSeconds) > toleranceSeconds) {
    throw invalidSignature('Stripe webhook signature timestamp is outside the allowed tolerance');
  }
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    signedPayloadBytes(parsed.timestampSeconds, bodyBytes(input.rawBody)),
  );
  const expected = bytesToHex(new Uint8Array(signature));
  if (!signatureMatches(expected, parsed.signatures)) {
    throw invalidSignature('Stripe webhook signature does not match the raw request body');
  }
}

function parseProviderRefundStatus(value: string): StripeProviderRefundStatus {
  switch (value.toLowerCase()) {
    case 'succeeded':
      return 'succeeded';
    case 'failed':
      return 'failed';
    case 'canceled':
      return 'canceled';
    case 'pending':
    case 'requires_action':
      return 'pending';
    default:
      throw invalidPayload(`Unsupported Stripe refund status: ${value || 'empty'}`);
  }
}

function resolvePaymentRef(record: UnknownRecord, fallback: string): string {
  return readString(record, 'payment_intent') || readString(record, 'charge') || fallback;
}

function parseRefundItem(
  record: UnknownRecord,
  fallback: {
    orgId: string | null;
    purchaseId: string | null;
    providerPaymentRef: string;
  },
): StripeRefundEventItem {
  const metadata = readMetadata(record);
  const providerRefundId = readString(record, 'id');
  if (!providerRefundId) throw invalidPayload('Stripe refund id is required');
  const status = readString(record, 'status');
  return {
    providerRefundId,
    refundId: nullableString(readString(metadata, 'refund_id')),
    purchaseId: nullableString(readString(metadata, 'purchase_id')) || fallback.purchaseId,
    orgId: nullableString(readString(metadata, 'org_id')) || fallback.orgId,
    providerPaymentRef: resolvePaymentRef(record, fallback.providerPaymentRef),
    amountMinor: readPositiveInteger(record, 'amount'),
    status: parseProviderRefundStatus(status),
    reason: readString(metadata, 'reason') || readString(record, 'reason') || 'provider_refund',
    failureCode: nullableString(readString(record, 'failure_reason')),
  };
}

function parseCheckoutCompleted(eventId: string, object: UnknownRecord): StripeWebhookEventRequest {
  const metadata = readMetadata(object);
  const checkoutSessionId = readString(object, 'id');
  const providerPaymentRef = readString(object, 'payment_intent');
  const paymentStatus = readString(object, 'payment_status').toLowerCase();
  const currency = readString(object, 'currency').toLowerCase();
  const purchaseId = readString(metadata, 'purchase_id');
  const creditPackId = parseCreditPackId(readString(metadata, 'credit_pack_id'));
  if (!checkoutSessionId || !providerPaymentRef || !purchaseId) {
    throw invalidPayload(
      'Completed Stripe checkout requires id, payment_intent, and purchase metadata',
    );
  }
  if (paymentStatus !== 'paid') throw invalidPayload('Completed Stripe checkout is not paid');
  if (currency !== 'usd') throw invalidPayload('Completed Stripe checkout currency must be USD');
  return {
    eventId,
    eventType: 'checkout.session.completed',
    orgId:
      nullableString(readString(object, 'client_reference_id')) ||
      nullableString(readString(metadata, 'org_id')),
    providerCustomerRef: nullableString(readString(object, 'customer')),
    checkoutSessionId,
    providerPaymentRef,
    providerRef: checkoutSessionId,
    purchaseId,
    creditPackId,
    amountMinor: readPositiveInteger(object, 'amount_total'),
    currency: 'USD',
    paymentStatus: 'paid',
  };
}

function parseCheckoutExpired(eventId: string, object: UnknownRecord): StripeWebhookEventRequest {
  const metadata = readMetadata(object);
  const checkoutSessionId = readString(object, 'id');
  const purchaseId = readString(metadata, 'purchase_id');
  if (!checkoutSessionId || !purchaseId) {
    throw invalidPayload('Expired Stripe checkout requires id and purchase metadata');
  }
  return {
    eventId,
    eventType: 'checkout.session.expired',
    orgId:
      nullableString(readString(object, 'client_reference_id')) ||
      nullableString(readString(metadata, 'org_id')),
    checkoutSessionId,
    providerRef: checkoutSessionId,
    purchaseId,
  };
}

function parseRefundChanged(
  eventId: string,
  eventType: 'refund.created' | 'refund.updated',
  object: UnknownRecord,
): StripeWebhookEventRequest {
  return {
    eventId,
    eventType,
    refund: parseRefundItem(object, {
      orgId: null,
      purchaseId: null,
      providerPaymentRef: '',
    }),
  };
}

function parseChargeRefunded(eventId: string, object: UnknownRecord): StripeWebhookEventRequest {
  const metadata = readMetadata(object);
  const orgId = nullableString(readString(metadata, 'org_id'));
  const purchaseId = nullableString(readString(metadata, 'purchase_id'));
  const providerPaymentRef = readString(object, 'payment_intent') || readString(object, 'id');
  if (!providerPaymentRef)
    throw invalidPayload('Refunded Stripe charge requires a payment reference');
  const refundsEnvelope = toRecord(object.refunds);
  const data = Array.isArray(refundsEnvelope.data) ? refundsEnvelope.data : [];
  const refunds = data.map((refund) =>
    parseRefundItem(toRecord(refund), { orgId, purchaseId, providerPaymentRef }),
  );
  if (refunds.length === 0) {
    throw invalidPayload('Refunded Stripe charge must include at least one refund');
  }
  return {
    eventId,
    eventType: 'charge.refunded',
    orgId,
    purchaseId,
    providerPaymentRef,
    refunds,
  };
}

function parseDispute(
  eventId: string,
  eventType: 'charge.dispute.created' | 'charge.dispute.closed',
  object: UnknownRecord,
): StripeWebhookEventRequest {
  const metadata = readMetadata(object);
  const providerDisputeId = readString(object, 'id');
  const providerPaymentRef = resolvePaymentRef(object, '');
  if (!providerDisputeId || !providerPaymentRef) {
    throw invalidPayload('Stripe dispute requires id and payment reference');
  }
  const orgId = nullableString(readString(metadata, 'org_id'));
  const purchaseId = nullableString(readString(metadata, 'purchase_id'));
  const amountMinor = readPositiveInteger(object, 'amount');
  if (eventType === 'charge.dispute.created') {
    return {
      eventId,
      eventType,
      orgId,
      purchaseId,
      providerPaymentRef,
      providerDisputeId,
      amountMinor,
    };
  }
  const status = readString(object, 'status').toLowerCase();
  if (status !== 'won' && status !== 'lost') {
    throw invalidPayload(`Closed Stripe dispute has unsupported status: ${status || 'empty'}`);
  }
  return {
    eventId,
    eventType,
    orgId,
    purchaseId,
    providerPaymentRef,
    providerDisputeId,
    amountMinor,
    outcome: status,
  };
}

export function parseStripeWebhookEventEnvelope(
  payload: unknown,
): StripeWebhookEventRequest | null {
  const envelope = toRecord(payload);
  const eventId = readString(envelope, 'id');
  const eventType = readString(envelope, 'type');
  const object = toRecord(toRecord(envelope.data).object);
  if (!eventId || !eventType) throw invalidPayload('Stripe event id and type are required');
  switch (eventType) {
    case 'checkout.session.completed':
      return parseCheckoutCompleted(eventId, object);
    case 'checkout.session.expired':
      return parseCheckoutExpired(eventId, object);
    case 'refund.created':
    case 'refund.updated':
      return parseRefundChanged(eventId, eventType, object);
    case 'charge.refunded':
      return parseChargeRefunded(eventId, object);
    case 'charge.dispute.created':
    case 'charge.dispute.closed':
      return parseDispute(eventId, eventType, object);
    default:
      return null;
  }
}

function parseRawJson(rawBody: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder().decode(rawBody));
  } catch {
    throw invalidPayload('Stripe webhook body must be valid JSON');
  }
}

export async function verifyAndParseStripeWebhookRequest(
  input: StripeWebhookVerificationInput,
): Promise<StripeWebhookEventRequest | null> {
  await verifyStripeWebhookSignature(input);
  return parseStripeWebhookEventEnvelope(parseRawJson(bodyBytes(input.rawBody)));
}
