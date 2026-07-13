import type { TransactionContext } from '@/core/types/rpc';
import type { NonceLeaseRef } from '../interfaces/nonceLease';
import type {
  SerializableCredential,
  UserConfirmDecision,
} from './types';
import type { WorkerConfirmationResponse } from './channel/confirmTypes';
import type { NearTransactionReadiness } from '../nonce/nearTransactionReadiness';

const credential = {} as SerializableCredential;
const transactionContext = {} as TransactionContext;
const nonceLeases = [] as NonceLeaseRef[];
const nearTransactionReadiness = {
  kind: 'context_ready',
  transactionContext,
  nonceLeases,
} satisfies NearTransactionReadiness;

const successDecision: UserConfirmDecision = {
  requestId: 'request-1',
  confirmed: true,
  credential,
  transactionContext,
  nonceLeases,
};

const failureDecision: UserConfirmDecision = {
  requestId: 'request-2',
  confirmed: false,
  error: 'cancelled',
};

const failureWithDiagnostics: UserConfirmDecision = {
  requestId: 'request-3',
  confirmed: false,
  registrationDiagnostics: {
    kind: 'registration_confirmation_diagnostics_v1',
    workerReadyMs: 0,
    workerRequestRoundTripMs: 0,
    workerResponseValidationMs: 0,
    requestSetupMs: 0,
    promptUserMs: 0,
    promptElementDefineMs: 0,
    promptMountMs: 0,
    promptHostFirstUpdateMs: 0,
    promptHostInteractiveMs: 0,
    promptConfirmEventMs: 0,
    promptDecisionWaitMs: 0,
    credentialCreateStartMs: 0,
    credentialCreateMs: 0,
    credentialSerializeMs: 0,
    duplicateRetryCount: 0,
    mainThreadTotalMs: 0,
  },
};

const workerFailure: WorkerConfirmationResponse = {
  request_id: 'request-4',
  confirmed: false,
  error: 'cancelled',
};

const workerSuccess: WorkerConfirmationResponse = {
  request_id: 'request-5',
  confirmed: true,
  credential,
};

const workerTransactionSuccess: WorkerConfirmationResponse = {
  request_id: 'request-5-transaction',
  confirmed: true,
  transaction_context: transactionContext,
  nonce_leases: nonceLeases,
};

const nearReadinessSuccess: UserConfirmDecision = {
  requestId: 'request-5-near-readiness',
  confirmed: true,
  nearTransactionReadiness,
};

const workerNearReadinessSuccess: WorkerConfirmationResponse = {
  request_id: 'request-5-worker-near-readiness',
  confirmed: true,
  near_transaction_readiness: nearTransactionReadiness,
};

const invalidNearReadinessWithTopLevelContext = {
  requestId: 'request-5-invalid-near-readiness',
  confirmed: true,
  nearTransactionReadiness,
  transactionContext,
  // @ts-expect-error NEAR readiness replaces the legacy top-level transaction context branch.
} satisfies UserConfirmDecision;

const invalidWorkerNearReadinessWithTopLevelContext = {
  request_id: 'request-5-invalid-worker-near-readiness',
  confirmed: true,
  near_transaction_readiness: nearTransactionReadiness,
  transaction_context: transactionContext,
  nonce_leases: nonceLeases,
  // @ts-expect-error Worker NEAR readiness replaces the top-level transaction context branch.
} satisfies WorkerConfirmationResponse;

const invalidFailureCredential = {
  requestId: 'request-6',
  confirmed: false,
  credential,
  // @ts-expect-error Failed decisions cannot carry success credential payload.
} satisfies UserConfirmDecision;

const invalidFailureOtp = {
  requestId: 'request-7',
  confirmed: false,
  otpCode: '123456',
  // @ts-expect-error Failed decisions cannot carry Email OTP payload.
} satisfies UserConfirmDecision;

const invalidFailureNonceLeases = {
  requestId: 'request-8',
  confirmed: false,
  nonceLeases,
  // @ts-expect-error Failed decisions cannot keep reserved nonce payload.
} satisfies UserConfirmDecision;

const invalidWorkerFailureCredential = {
  request_id: 'request-9',
  confirmed: false,
  credential,
  // @ts-expect-error Failed worker responses cannot carry success credential payload.
} satisfies WorkerConfirmationResponse;

const invalidWorkerSuccessError = {
  request_id: 'request-10',
  confirmed: true,
  error: 'should not be present',
  // @ts-expect-error Successful worker responses cannot carry an error.
} satisfies WorkerConfirmationResponse;

const invalidWorkerSuccessNonceLeasesWithoutContext = {
  request_id: 'request-10-nonce-without-context',
  confirmed: true,
  nonce_leases: nonceLeases,
  // @ts-expect-error Worker nonce leases require transaction context.
} satisfies WorkerConfirmationResponse;

const invalidWorkerSuccessTransactionContextWithoutNonceLeases = {
  request_id: 'request-10-context-without-nonce',
  confirmed: true,
  transaction_context: transactionContext,
  // @ts-expect-error Worker transaction context requires nonce leases.
} satisfies WorkerConfirmationResponse;

const invalidWorkerFailureNonceLeases = {
  request_id: 'request-11',
  confirmed: false,
  nonce_leases: nonceLeases,
  // @ts-expect-error Failed worker responses cannot keep reserved nonce payload.
} satisfies WorkerConfirmationResponse;

void successDecision;
void failureDecision;
void failureWithDiagnostics;
void workerFailure;
void workerSuccess;
void workerTransactionSuccess;
void nearReadinessSuccess;
void workerNearReadinessSuccess;
void invalidNearReadinessWithTopLevelContext;
void invalidWorkerNearReadinessWithTopLevelContext;
void invalidFailureCredential;
void invalidFailureOtp;
void invalidFailureNonceLeases;
void invalidWorkerFailureCredential;
void invalidWorkerSuccessError;
void invalidWorkerSuccessNonceLeasesWithoutContext;
void invalidWorkerSuccessTransactionContextWithoutNonceLeases;
void invalidWorkerFailureNonceLeases;
