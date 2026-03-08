export type ConsoleBootstrapTokenStatus = 'issued' | 'redeemed' | 'expired' | 'canceled';

export interface ConsoleBootstrapTokenRecord {
  id: string;
  orgId: string;
  projectId: string;
  environmentId: string;
  publishableKeyId: string;
  tokenPrefix: string;
  tokenHash: string;
  method: string;
  path: string;
  origin: string;
  requestHashSha256: string;
  status: ConsoleBootstrapTokenStatus;
  riskDecision: string;
  paymentReference: string | null;
  replacementForTokenId: string | null;
  issuedAt: string;
  expiresAt: string;
  redeemedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateConsoleBootstrapTokenRequest {
  publishableKeyId: string;
  projectId: string;
  environmentId: string;
  origin: string;
  method: string;
  path: string;
  requestHashSha256: string;
  ttlMs: number;
  riskDecision?: string;
  paymentReference?: string | null;
  replacementForTokenId?: string | null;
}

export interface CreateConsoleBootstrapTokenResult {
  token: string;
  record: ConsoleBootstrapTokenRecord;
}

export interface CountConsoleBootstrapTokensRequest {
  publishableKeyId: string;
  issuedSince?: string;
}

export type RedeemConsoleBootstrapTokenFailureCode =
  | 'bootstrap_token_missing'
  | 'bootstrap_token_invalid'
  | 'bootstrap_token_expired'
  | 'bootstrap_token_already_used'
  | 'bootstrap_token_request_mismatch'
  | 'bootstrap_token_origin_mismatch';

export interface RedeemConsoleBootstrapTokenRequest {
  token: string;
  origin: string;
  method: string;
  path: string;
  requestHashSha256: string;
}

export type RedeemConsoleBootstrapTokenResult =
  | {
      ok: true;
      record: ConsoleBootstrapTokenRecord;
    }
  | {
      ok: false;
      status: 401 | 403 | 409;
      code: RedeemConsoleBootstrapTokenFailureCode;
      message: string;
    };

