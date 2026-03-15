import type {
  BillingUsageAction,
  ConsoleBillingService,
} from '../console/billing';
import type {
  ConsoleSponsoredCallRecord,
  ConsoleSponsoredCallService,
  CreateConsoleSponsoredCallRecordRequest,
} from '../console/sponsoredCalls';

export interface MeteredGasExecutionContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
}

export interface RecordMeteredGasExecutionInput {
  billing: ConsoleBillingService;
  billingAction?: BillingUsageAction;
  billingSourceEventIdPrefix: string;
  context: MeteredGasExecutionContext;
  ledger: ConsoleSponsoredCallService;
  occurredAt?: string;
  record: CreateConsoleSponsoredCallRecordRequest;
  succeeded: boolean;
  walletId: string;
}

export async function recordMeteredGasExecution(
  input: RecordMeteredGasExecutionInput,
): Promise<ConsoleSponsoredCallRecord> {
  const record = await input.ledger.createRecord(input.context, input.record);
  await input.billing.recordUsageEvent(input.context, {
    walletId: input.walletId,
    action: input.billingAction || 'contract_call',
    succeeded: input.succeeded,
    occurredAt: input.occurredAt || new Date().toISOString(),
    sourceEventId: `${input.billingSourceEventIdPrefix}:${record.id}`,
  });
  return record;
}
