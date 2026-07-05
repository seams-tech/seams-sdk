import {
  buildThresholdEd25519SeedExportArtifactFromHssReport as buildThresholdEd25519SeedExportArtifactFromHssReportValue,
  deriveThresholdEd25519ClientVerifyingShareFromCredential as deriveThresholdEd25519ClientVerifyingShareFromCredentialValue,
  deriveThresholdEd25519HssClientInputsFromCredential as deriveThresholdEd25519HssClientInputsFromCredentialValue,
  deriveThresholdEd25519HssClientInputsFromCredentialAndContext as deriveThresholdEd25519HssClientInputsFromCredentialAndContextValue,
  deriveThresholdEd25519HssClientInputsFromPrfFirst as deriveThresholdEd25519HssClientInputsFromPrfFirstValue,
  openThresholdEd25519HssSeedOutput as openThresholdEd25519HssSeedOutputValue,
  prepareThresholdEd25519HssClientCeremonyFromCanonicalContext as prepareThresholdEd25519HssClientCeremonyFromCanonicalContextValue,
  prepareThresholdEd25519HssClientCeremonyFromCredential as prepareThresholdEd25519HssClientCeremonyFromCredentialValue,
  prepareThresholdEd25519HssClientCeremonyFromPrfFirst as prepareThresholdEd25519HssClientCeremonyFromPrfFirstValue,
  runThresholdEd25519HssCeremonyWithMaterialHandle as runThresholdEd25519HssCeremonyWithMaterialHandleValue,
  runThresholdEd25519HssCeremonyWithSession as runThresholdEd25519HssCeremonyWithSessionValue,
  storeThresholdEd25519WorkerMaterialFromFinalizedHssReport as storeThresholdEd25519WorkerMaterialFromFinalizedHssReportValue,
  type ThresholdEd25519LifecycleDeps,
} from './hssLifecycle';
import {
  buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandleWasm,
  prepareThresholdEd25519HssClientOutputMaskHandleWasm,
  prepareThresholdEd25519HssClientRequestWasm,
} from '../crypto/hssClientSignerWasm';
import {
  prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorizationNearSignerWasm,
  prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorizationNearSignerWasm,
} from '../../chains/near/nearSignerWasm';

export type ThresholdEd25519PublicDeps = ThresholdEd25519LifecycleDeps;

export function deriveThresholdEd25519ClientVerifyingShareFromCredential(
  deps: ThresholdEd25519PublicDeps,
  args: Parameters<typeof deriveThresholdEd25519ClientVerifyingShareFromCredentialValue>[1],
): ReturnType<typeof deriveThresholdEd25519ClientVerifyingShareFromCredentialValue> {
  return deriveThresholdEd25519ClientVerifyingShareFromCredentialValue(deps, args);
}

export function deriveThresholdEd25519HssClientInputsFromCredential(
  deps: ThresholdEd25519PublicDeps,
  args: Parameters<typeof deriveThresholdEd25519HssClientInputsFromCredentialValue>[1],
): ReturnType<typeof deriveThresholdEd25519HssClientInputsFromCredentialValue> {
  return deriveThresholdEd25519HssClientInputsFromCredentialValue(deps, args);
}

export function deriveThresholdEd25519HssClientInputsFromCredentialAndContext(
  deps: ThresholdEd25519PublicDeps,
  args: Parameters<typeof deriveThresholdEd25519HssClientInputsFromCredentialAndContextValue>[1],
): ReturnType<typeof deriveThresholdEd25519HssClientInputsFromCredentialAndContextValue> {
  return deriveThresholdEd25519HssClientInputsFromCredentialAndContextValue(deps, args);
}

export function deriveThresholdEd25519HssClientInputsFromPrfFirst(
  deps: ThresholdEd25519PublicDeps,
  args: Parameters<typeof deriveThresholdEd25519HssClientInputsFromPrfFirstValue>[1],
): ReturnType<typeof deriveThresholdEd25519HssClientInputsFromPrfFirstValue> {
  return deriveThresholdEd25519HssClientInputsFromPrfFirstValue(deps, args);
}

export function prepareThresholdEd25519HssClientCeremonyFromCanonicalContext(
  deps: ThresholdEd25519PublicDeps,
  args: Parameters<typeof prepareThresholdEd25519HssClientCeremonyFromCanonicalContextValue>[1],
): ReturnType<typeof prepareThresholdEd25519HssClientCeremonyFromCanonicalContextValue> {
  return prepareThresholdEd25519HssClientCeremonyFromCanonicalContextValue(deps, args);
}

export function prepareThresholdEd25519HssClientCeremonyFromCredential(
  deps: ThresholdEd25519PublicDeps,
  args: Parameters<typeof prepareThresholdEd25519HssClientCeremonyFromCredentialValue>[1],
): ReturnType<typeof prepareThresholdEd25519HssClientCeremonyFromCredentialValue> {
  return prepareThresholdEd25519HssClientCeremonyFromCredentialValue(deps, args);
}

export function prepareThresholdEd25519HssClientCeremonyFromPrfFirst(
  deps: ThresholdEd25519PublicDeps,
  args: Parameters<typeof prepareThresholdEd25519HssClientCeremonyFromPrfFirstValue>[1],
): ReturnType<typeof prepareThresholdEd25519HssClientCeremonyFromPrfFirstValue> {
  return prepareThresholdEd25519HssClientCeremonyFromPrfFirstValue(deps, args);
}

export function prepareThresholdEd25519HssClientRequest(
  deps: ThresholdEd25519PublicDeps,
  args: Omit<Parameters<typeof prepareThresholdEd25519HssClientRequestWasm>[0], 'workerCtx'>,
): ReturnType<typeof prepareThresholdEd25519HssClientRequestWasm> {
  return prepareThresholdEd25519HssClientRequestWasm({
    ...args,
    workerCtx: deps.getSignerWorkerContext(),
  });
}

export function prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorization(
  deps: ThresholdEd25519PublicDeps,
  args: Omit<
    Parameters<typeof prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorizationNearSignerWasm>[0],
    'workerCtx'
  >,
): ReturnType<typeof prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorizationNearSignerWasm> {
  return prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorizationNearSignerWasm({
    ...args,
    workerCtx: deps.getSignerWorkerContext(),
  });
}

export function prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorization(
  deps: ThresholdEd25519PublicDeps,
  args: Omit<
    Parameters<typeof prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorizationNearSignerWasm>[0],
    'workerCtx'
  >,
): ReturnType<typeof prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorizationNearSignerWasm> {
  return prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorizationNearSignerWasm({
    ...args,
    workerCtx: deps.getSignerWorkerContext(),
  });
}

export function prepareThresholdEd25519HssClientOutputMaskHandle(
  deps: ThresholdEd25519PublicDeps,
  args: Omit<
    Parameters<typeof prepareThresholdEd25519HssClientOutputMaskHandleWasm>[0],
    'workerCtx'
  >,
): ReturnType<typeof prepareThresholdEd25519HssClientOutputMaskHandleWasm> {
  return prepareThresholdEd25519HssClientOutputMaskHandleWasm({
    ...args,
    workerCtx: deps.getSignerWorkerContext(),
  });
}

export function buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandle(
  deps: ThresholdEd25519PublicDeps,
  args: Omit<
    Parameters<typeof buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandleWasm>[0],
    'workerCtx'
  >,
): ReturnType<typeof buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandleWasm> {
  return buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandleWasm({
    ...args,
    workerCtx: deps.getSignerWorkerContext(),
  });
}

export function runThresholdEd25519HssCeremonyWithSession(
  deps: ThresholdEd25519PublicDeps,
  args: Omit<Parameters<typeof runThresholdEd25519HssCeremonyWithSessionValue>[0], 'workerCtx'>,
): ReturnType<typeof runThresholdEd25519HssCeremonyWithSessionValue> {
  return runThresholdEd25519HssCeremonyWithSessionValue({
    ...args,
    workerCtx: deps.getSignerWorkerContext(),
  });
}

export function runThresholdEd25519HssCeremonyWithMaterialHandle(
  deps: ThresholdEd25519PublicDeps,
  args: Omit<
    Parameters<typeof runThresholdEd25519HssCeremonyWithMaterialHandleValue>[0],
    'workerCtx'
  >,
): ReturnType<typeof runThresholdEd25519HssCeremonyWithMaterialHandleValue> {
  return runThresholdEd25519HssCeremonyWithMaterialHandleValue({
    ...args,
    workerCtx: deps.getSignerWorkerContext(),
  });
}

export function storeThresholdEd25519WorkerMaterialFromFinalizedHssReport(
  deps: ThresholdEd25519PublicDeps,
  args: Omit<
    Parameters<typeof storeThresholdEd25519WorkerMaterialFromFinalizedHssReportValue>[0],
    'workerCtx'
  >,
): ReturnType<typeof storeThresholdEd25519WorkerMaterialFromFinalizedHssReportValue> {
  return storeThresholdEd25519WorkerMaterialFromFinalizedHssReportValue({
    ...args,
    workerCtx: deps.getSignerWorkerContext(),
  });
}

export function openThresholdEd25519HssSeedOutput(
  deps: ThresholdEd25519PublicDeps,
  args: Omit<Parameters<typeof openThresholdEd25519HssSeedOutputValue>[0], 'workerCtx'>,
): ReturnType<typeof openThresholdEd25519HssSeedOutputValue> {
  return openThresholdEd25519HssSeedOutputValue({
    ...args,
    workerCtx: deps.getSignerWorkerContext(),
  });
}

export function buildThresholdEd25519SeedExportArtifactFromHssReport(
  deps: ThresholdEd25519PublicDeps,
  args: Omit<
    Parameters<typeof buildThresholdEd25519SeedExportArtifactFromHssReportValue>[0],
    'workerCtx'
  >,
): ReturnType<typeof buildThresholdEd25519SeedExportArtifactFromHssReportValue> {
  return buildThresholdEd25519SeedExportArtifactFromHssReportValue({
    ...args,
    workerCtx: deps.getSignerWorkerContext(),
  });
}
