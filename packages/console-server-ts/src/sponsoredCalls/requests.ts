import {
  readOptionalQueryBooleanField as readOptionalQueryBoolean,
  readOptionalQueryPositiveIntegerField as readOptionalQueryInteger,
  readOptionalQueryStringField as readOptionalQueryString,
  requireQueryObject,
} from '../shared/requestParse';
import { ConsoleSponsoredCallError } from './errors';
import type {
  ConsoleSponsoredCallChainFamily,
  ConsoleSponsoredCallReceiptStatus,
  ListConsoleSponsoredCallRecordsRequest,
} from './types';

const SPONSORED_CALL_CHAIN_FAMILIES = new Set<ConsoleSponsoredCallChainFamily>(['evm', 'near']);
const SPONSORED_CALL_RECEIPT_STATUSES = new Set<ConsoleSponsoredCallReceiptStatus>([
  'success',
  'reverted',
  'broadcast_failed',
  'rpc_rejected',
]);

function createParseError(code: string, status: number, message: string): ConsoleSponsoredCallError {
  return new ConsoleSponsoredCallError(code, status, message);
}

function parseOptionalChainFamily(
  value: string | undefined,
): ConsoleSponsoredCallChainFamily | undefined {
  if (!value) return undefined;
  if (!SPONSORED_CALL_CHAIN_FAMILIES.has(value as ConsoleSponsoredCallChainFamily)) {
    throw new ConsoleSponsoredCallError('invalid_query', 400, `Unsupported chainFamily: ${value}`);
  }
  return value as ConsoleSponsoredCallChainFamily;
}

function parseOptionalReceiptStatus(
  value: string | undefined,
): ConsoleSponsoredCallReceiptStatus | undefined {
  if (!value) return undefined;
  if (!SPONSORED_CALL_RECEIPT_STATUSES.has(value as ConsoleSponsoredCallReceiptStatus)) {
    throw new ConsoleSponsoredCallError('invalid_query', 400, `Unsupported receiptStatus: ${value}`);
  }
  return value as ConsoleSponsoredCallReceiptStatus;
}

export function parseListConsoleSponsoredCallRecordsRequest(
  query: unknown,
): ListConsoleSponsoredCallRecordsRequest {
  const obj = requireQueryObject(query, createParseError);
  return {
    environmentId: readOptionalQueryString(obj, 'environmentId'),
    policyId: readOptionalQueryString(obj, 'policyId'),
    chainFamily: parseOptionalChainFamily(readOptionalQueryString(obj, 'chainFamily')),
    receiptStatus: parseOptionalReceiptStatus(readOptionalQueryString(obj, 'receiptStatus')),
    charged: readOptionalQueryBoolean(obj, 'charged', createParseError),
    limit: readOptionalQueryInteger(obj, 'limit', createParseError),
    cursor: readOptionalQueryString(obj, 'cursor'),
    lookbackDays: readOptionalQueryInteger(obj, 'lookbackDays', createParseError),
  };
}
