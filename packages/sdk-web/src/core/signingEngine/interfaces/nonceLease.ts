export type NonceLeaseRef = {
  leaseId: string;
  operationId: string;
  operationFingerprint: string;
  nonce: string;
  batchId?: string;
  txIndex?: number;
};
