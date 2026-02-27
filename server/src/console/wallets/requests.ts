import { ConsoleWalletError } from './errors';
import {
  readOptionalQueryPositiveIntegerField as readOptionalQueryInteger,
  readOptionalQueryStringField as readOptionalQueryString,
  requireQueryObject,
} from '../shared/requestParse';
import type {
  ConsoleWalletChain,
  ConsoleWalletSortBy,
  ConsoleWalletSortOrder,
  ConsoleWalletStatus,
  ConsoleWalletType,
  ListConsoleWalletsRequest,
  SearchConsoleWalletsRequest,
} from './types';

const WALLET_CHAINS: Set<ConsoleWalletChain> = new Set([
  'Ethereum',
  'Base',
  'Tempo',
  'Arc Circle',
  'NEAR',
]);

const WALLET_TYPES: Set<ConsoleWalletType> = new Set(['EOA', 'SMART']);
const WALLET_STATUSES: Set<ConsoleWalletStatus> = new Set(['ACTIVE', 'FROZEN', 'ARCHIVED']);
const WALLET_SORT_BY: Set<ConsoleWalletSortBy> = new Set(['createdAt', 'balance', 'lastActivity']);
const WALLET_SORT_ORDER: Set<ConsoleWalletSortOrder> = new Set(['asc', 'desc']);

function createParseError(code: string, status: number, message: string): ConsoleWalletError {
  return new ConsoleWalletError(code, status, message);
}

function parseWalletChain(value: string | undefined): ConsoleWalletChain | undefined {
  if (!value) return undefined;
  if (!WALLET_CHAINS.has(value as ConsoleWalletChain)) {
    throw new ConsoleWalletError('invalid_query', 400, `Unsupported chain: ${value}`);
  }
  return value as ConsoleWalletChain;
}

function parseWalletType(value: string | undefined): ConsoleWalletType | undefined {
  if (!value) return undefined;
  const normalized = value.toUpperCase();
  if (!WALLET_TYPES.has(normalized as ConsoleWalletType)) {
    throw new ConsoleWalletError('invalid_query', 400, `Unsupported walletType: ${value}`);
  }
  return normalized as ConsoleWalletType;
}

function parseWalletStatus(value: string | undefined): ConsoleWalletStatus | undefined {
  if (!value) return undefined;
  const normalized = value.toUpperCase();
  if (!WALLET_STATUSES.has(normalized as ConsoleWalletStatus)) {
    throw new ConsoleWalletError('invalid_query', 400, `Unsupported status: ${value}`);
  }
  return normalized as ConsoleWalletStatus;
}

function parseSortBy(value: string | undefined): ConsoleWalletSortBy | undefined {
  if (!value) return undefined;
  if (!WALLET_SORT_BY.has(value as ConsoleWalletSortBy)) {
    throw new ConsoleWalletError('invalid_query', 400, `Unsupported sortBy: ${value}`);
  }
  return value as ConsoleWalletSortBy;
}

function parseSortOrder(value: string | undefined): ConsoleWalletSortOrder | undefined {
  if (!value) return undefined;
  const normalized = value.toLowerCase();
  if (!WALLET_SORT_ORDER.has(normalized as ConsoleWalletSortOrder)) {
    throw new ConsoleWalletError('invalid_query', 400, `Unsupported sortOrder: ${value}`);
  }
  return normalized as ConsoleWalletSortOrder;
}

export function parseListConsoleWalletsRequest(query: unknown): ListConsoleWalletsRequest {
  const obj = requireQueryObject(query, createParseError);
  return {
    limit: readOptionalQueryInteger(obj, 'limit', createParseError),
    cursor: readOptionalQueryString(obj, 'cursor'),
    projectId: readOptionalQueryString(obj, 'projectId'),
    environmentId: readOptionalQueryString(obj, 'environmentId'),
    chain: parseWalletChain(readOptionalQueryString(obj, 'chain')),
    walletType: parseWalletType(readOptionalQueryString(obj, 'walletType')),
    status: parseWalletStatus(readOptionalQueryString(obj, 'status')),
    policyId: readOptionalQueryString(obj, 'policyId'),
    userId: readOptionalQueryString(obj, 'userId'),
    externalRefId: readOptionalQueryString(obj, 'externalRefId'),
    sortBy: parseSortBy(readOptionalQueryString(obj, 'sortBy')),
    sortOrder: parseSortOrder(readOptionalQueryString(obj, 'sortOrder')),
  };
}

export function parseSearchConsoleWalletsRequest(query: unknown): SearchConsoleWalletsRequest {
  const parsed = parseListConsoleWalletsRequest(query);
  const obj = requireQueryObject(query, createParseError);
  const q = readOptionalQueryString(obj, 'q');
  if (!q) {
    throw new ConsoleWalletError('invalid_query', 400, 'Query parameter q is required');
  }
  return {
    ...parsed,
    q,
  };
}
