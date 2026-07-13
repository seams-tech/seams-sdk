import type { TransactionContext } from '@/core/types/rpc';
import type { NearFundingRequest, NearTransactionReadiness } from './nearTransactionReadiness';

const request = {} as NearFundingRequest;
const transactionContext = {} as TransactionContext;

const invalidFundingWithContext = {
  kind: 'funding_required',
  request,
  transactionContext,
  // @ts-expect-error Funding-required readiness cannot carry transaction context.
} satisfies NearTransactionReadiness;

const invalidReadyWithFundingRequest = {
  kind: 'context_ready',
  transactionContext,
  nonceLeases: [],
  request,
  // @ts-expect-error Context-ready readiness cannot carry a funding request.
} satisfies NearTransactionReadiness;

void invalidFundingWithContext;
void invalidReadyWithFundingRequest;
