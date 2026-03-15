export type ConsoleSponsoredCallApiKeyKind = 'secret_key' | 'publishable_key';
export type ConsoleSponsoredCallChainFamily = 'evm' | 'near';
export type ConsoleSponsoredCallIntentKind = 'evm_call' | 'near_delegate';
export type ConsoleSponsoredCallFeeUnit = 'wei' | 'yocto_near';

export type ConsoleSponsoredCallReceiptStatus =
  | 'success'
  | 'reverted'
  | 'broadcast_failed'
  | 'rpc_rejected';

export interface ConsoleSponsoredCallRecord {
  id: string;
  orgId: string;
  environmentId: string;
  apiKeyId: string;
  apiKeyKind: ConsoleSponsoredCallApiKeyKind;
  route: string;
  policyId: string;
  policyNameAtEvent: string | null;
  chainFamily: ConsoleSponsoredCallChainFamily;
  intentKind: ConsoleSponsoredCallIntentKind;
  accountRef: string;
  targetRef: string;
  sponsorRef: string;
  txOrExecutionRef: string | null;
  receiptStatus: ConsoleSponsoredCallReceiptStatus;
  feeUnit: ConsoleSponsoredCallFeeUnit;
  feeAmount: string;
  detailsJson: string;
  errorCode: string | null;
  errorMessage: string | null;
  idempotencyKey: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateConsoleSponsoredCallRecordRequest {
  id?: string;
  environmentId: string;
  apiKeyId: string;
  apiKeyKind: ConsoleSponsoredCallApiKeyKind;
  route: string;
  policyId: string;
  policyNameAtEvent?: string | null;
  chainFamily: ConsoleSponsoredCallChainFamily;
  intentKind: ConsoleSponsoredCallIntentKind;
  accountRef: string;
  targetRef: string;
  sponsorRef: string;
  txOrExecutionRef?: string | null;
  receiptStatus: ConsoleSponsoredCallReceiptStatus;
  feeUnit: ConsoleSponsoredCallFeeUnit;
  feeAmount: string;
  detailsJson: string;
  errorCode?: string | null;
  errorMessage?: string | null;
  idempotencyKey?: string | null;
}
