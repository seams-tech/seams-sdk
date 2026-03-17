import type { BillingUsageAction, ConsoleBillingService } from '../console/billing';
import type {
  ConsoleSponsoredCallExecutorKind,
  ConsoleSponsoredCallFeeUnit,
  ConsoleSponsoredCallReceiptStatus,
  ConsoleSponsoredCallRecord,
  ConsoleSponsoredCallService,
  CreateConsoleSponsoredCallRecordRequest,
} from '../console/sponsoredCalls';
import type { MeteredGasExecutionContext } from './recordMeteredGasExecution';
import { recordMeteredGasExecution } from './recordMeteredGasExecution';
import type { RouteResponse } from './routeExecutionContext';

export interface SponsorshipExecutionAssessment {
  succeeded: boolean;
  txOrExecutionRef: string | null;
  receiptStatus: ConsoleSponsoredCallReceiptStatus;
  feeUnit: ConsoleSponsoredCallFeeUnit;
  feeAmount: string;
  executorKind: ConsoleSponsoredCallExecutorKind;
  responseCode: string;
  responseMessage: string;
  recordErrorCode: string | null;
  recordErrorMessage: string | null;
}

export interface RecordSponsoredExecutionInput {
  billing: ConsoleBillingService;
  billingAction?: BillingUsageAction;
  billingSourceEventIdPrefix: string;
  context: MeteredGasExecutionContext;
  ledger: ConsoleSponsoredCallService;
  occurredAt?: string;
  record: Omit<
    CreateConsoleSponsoredCallRecordRequest,
    'txOrExecutionRef' | 'receiptStatus' | 'feeUnit' | 'feeAmount' | 'executorKind' | 'errorCode' | 'errorMessage'
  >;
  assessment: SponsorshipExecutionAssessment;
  walletId: string;
}

export interface RunSponsorshipExecutionOnResultInput<
  TResult,
  TAssessment extends SponsorshipExecutionAssessment,
> {
  result: TResult;
  assessment: TAssessment;
}

export interface RunSponsorshipExecutionOnThrownErrorInput<
  TAssessment extends SponsorshipExecutionAssessment,
> {
  error: unknown;
  assessment: TAssessment;
}

export interface RunSponsorshipExecutionInput<
  TResult,
  TAssessment extends SponsorshipExecutionAssessment,
  TResponseBody extends Record<string, unknown>,
> {
  execute: () => Promise<TResult>;
  assessResult: (result: TResult) => TAssessment;
  onResult: (
    input: RunSponsorshipExecutionOnResultInput<TResult, TAssessment>,
  ) => Promise<RouteResponse<TResponseBody>> | RouteResponse<TResponseBody>;
  assessThrownError?: (error: unknown) => TAssessment;
  onThrownError?: (
    input: RunSponsorshipExecutionOnThrownErrorInput<TAssessment>,
  ) => Promise<RouteResponse<TResponseBody>> | RouteResponse<TResponseBody>;
}

export async function recordSponsoredExecution(
  input: RecordSponsoredExecutionInput,
): Promise<ConsoleSponsoredCallRecord> {
  return await recordMeteredGasExecution({
    billing: input.billing,
    billingAction: input.billingAction,
    billingSourceEventIdPrefix: input.billingSourceEventIdPrefix,
    context: input.context,
    ledger: input.ledger,
    occurredAt: input.occurredAt,
    record: {
      ...input.record,
      txOrExecutionRef: input.assessment.txOrExecutionRef,
      receiptStatus: input.assessment.receiptStatus,
      feeUnit: input.assessment.feeUnit,
      feeAmount: input.assessment.feeAmount,
      executorKind: input.assessment.executorKind,
      errorCode: input.assessment.recordErrorCode,
      errorMessage: input.assessment.recordErrorMessage,
    },
    succeeded: input.assessment.succeeded,
    walletId: input.walletId,
  });
}

export async function runSponsorshipExecution<
  TResult,
  TAssessment extends SponsorshipExecutionAssessment,
  TResponseBody extends Record<string, unknown>,
>(
  input: RunSponsorshipExecutionInput<TResult, TAssessment, TResponseBody>,
): Promise<RouteResponse<TResponseBody>> {
  try {
    const result = await input.execute();
    const assessment = input.assessResult(result);
    return await input.onResult({
      result,
      assessment,
    });
  } catch (error: unknown) {
    if (!input.assessThrownError || !input.onThrownError) {
      throw error;
    }
    const assessment = input.assessThrownError(error);
    return await input.onThrownError({
      error,
      assessment,
    });
  }
}
