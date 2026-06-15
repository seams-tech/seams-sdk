import { alphabetizeStringify, sha256BytesUtf8 } from '../utils/digests';
import { base64UrlEncode } from '../utils/encoders';
import {
  parseDelegatedIdempotencyKey,
  parseDelegatedIntentDigest,
  type DelegatedIdempotencyKey,
  type DelegatedIntentDigest,
  type LaneShareEpoch,
  type SigningLaneId,
  type WalletKeyId,
} from './ids';
import type { AgentPrincipalId, WalletId } from '../utils/domainIds';

export type AssetDescriptor = {
  kind: 'asset_descriptor_v1';
  assetId: string;
  decimals: number;
};

export type AddressDescriptor = {
  kind: 'address_descriptor_v1';
  chainId: string;
  address: string;
};

export type CounterpartyDescriptor = {
  kind: 'counterparty_descriptor_v1';
  counterpartyId: string;
  displayName: string;
};

export type AtomicAmount = {
  kind: 'atomic_amount_v1';
  amountAtomic: string;
  asset: AssetDescriptor;
};

export type SpecificPurchasePaymentIntent = {
  kind: 'specific_purchase_payment_v1';
  paymentProtocol: 'x402' | 'merchant_checkout' | 'app_invoice';
  chainId: string;
  asset: AssetDescriptor;
  amount: AtomicAmount;
  destination: AddressDescriptor;
  counterparty: CounterpartyDescriptor;
  orderId: string;
  invoiceId: string;
  resourceId: string;
  expiresAtMs: number;
  nonce: string;
  purpose: string;
};

export type AllowanceGrantIntent = {
  kind: 'allowance_grant_v1';
  chainId: string;
  asset: AssetDescriptor;
  spender: AddressDescriptor;
  allowanceLimit: AtomicAmount;
  expiresAtMs: number;
  nonce: string;
  purpose: string;
};

export type DelegatedSigningIntent = SpecificPurchasePaymentIntent | AllowanceGrantIntent;

export type DelegatedSigningRequest = {
  kind: 'delegated_signing_request_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  revocationEpoch: number;
  delegatePrincipalId: AgentPrincipalId;
  idempotencyKey: DelegatedIdempotencyKey;
  intent: DelegatedSigningIntent;
  intentDigest: DelegatedIntentDigest;
  requestedAtMs: number;
};

export type DelegatedSigningAuditEvent = {
  kind: 'delegated_signing_audit_event_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  idempotencyKey: DelegatedIdempotencyKey;
  intentDigest: DelegatedIntentDigest;
  result: 'admitted' | 'denied' | 'signed';
  createdAtMs: number;
};

export async function computeDelegatedIntentDigest(
  intent: DelegatedSigningIntent,
): Promise<DelegatedIntentDigest> {
  const json = alphabetizeStringify(intent);
  const digest = base64UrlEncode(await sha256BytesUtf8(json));
  const parsed = parseDelegatedIntentDigest(`delegated-intent:${digest}`);
  if (!parsed.ok) {
    throw new Error(parsed.error.message);
  }
  return parsed.value;
}

export function parseDelegatedRequestIdempotencyKey(
  value: unknown,
): DelegatedIdempotencyKey {
  const parsed = parseDelegatedIdempotencyKey(value);
  if (!parsed.ok) {
    throw new Error(parsed.error.message);
  }
  return parsed.value;
}
