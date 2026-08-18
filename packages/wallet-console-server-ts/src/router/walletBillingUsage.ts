import { ConsoleBillingError } from '@seams-internal/console-server/billing/errors';
import type { BillingUsageEventRequest } from '@seams-internal/console-server/billing/types';
import {
  readOptionalStringField,
  readRequiredStringField,
  requireBodyObject,
} from '@seams-internal/console-server/shared/requestParse';

type WalletBillingAction = 'transfer' | 'swap' | 'approve' | 'contract_call' | 'wallet_created';

function createParseError(code: string, status: number, message: string): ConsoleBillingError {
  return new ConsoleBillingError(code, status, message);
}

function parseWalletBillingAction(value: string): WalletBillingAction {
  const normalized = value.toLowerCase();
  switch (normalized) {
    case 'transfer':
      return 'transfer';
    case 'swap':
      return 'swap';
    case 'approve':
      return 'approve';
    case 'contract_call':
      return 'contract_call';
    case 'wallet_created':
      return 'wallet_created';
    default:
      throw new ConsoleBillingError('invalid_body', 400, `Unsupported action: ${value}`);
  }
}

function isBillableWalletAction(action: WalletBillingAction): boolean {
  return action !== 'wallet_created';
}

function optionalBoolean(body: Record<string, unknown>, key: string): boolean | undefined {
  const value = body[key];
  if (value === undefined) return undefined;
  if (typeof value !== 'boolean') {
    throw new ConsoleBillingError('invalid_body', 400, `Field ${key} must be boolean`);
  }
  return value;
}

function optionalIsoDate(body: Record<string, unknown>): string | undefined {
  const value = readOptionalStringField(body, 'occurredAt');
  if (!value) return undefined;
  if (!Number.isFinite(Date.parse(value))) {
    throw new ConsoleBillingError('invalid_body', 400, 'Field occurredAt must be an ISO date');
  }
  return value;
}

export function parseWalletBillingUsageEventRequest(body: unknown): BillingUsageEventRequest {
  const input = requireBodyObject(body, createParseError);
  const walletId = readRequiredStringField(input, 'walletId', createParseError);
  const action = parseWalletBillingAction(
    readRequiredStringField(input, 'action', createParseError),
  );
  const succeeded = optionalBoolean(input, 'succeeded');
  if (succeeded === undefined) {
    throw new ConsoleBillingError('invalid_body', 400, 'Field succeeded must be boolean');
  }
  const isSimulation = optionalBoolean(input, 'isSimulation') ?? false;
  const isInternalRetry = optionalBoolean(input, 'isInternalRetry') ?? false;
  const sourceEventId = readOptionalStringField(input, 'sourceEventId');
  const occurredAt = optionalIsoDate(input);
  return {
    resourceId: walletId,
    shouldCount: isBillableWalletAction(action) && succeeded && !isSimulation && !isInternalRetry,
    ...(sourceEventId ? { sourceEventId } : {}),
    ...(occurredAt ? { occurredAt } : {}),
  };
}
