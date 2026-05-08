export type NonceLeaseRef = {
  leaseId: string;
  operationId: string;
  nonce: string;
  batchId?: string;
  txIndex?: number;
};
