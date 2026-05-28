import {
  buildThresholdEd25519SeedExportArtifactFromHssReport as buildThresholdEd25519SeedExportArtifactFromHssReportValue,
  completeThresholdEd25519HssClientCeremony as completeThresholdEd25519HssClientCeremonyValue,
  deriveThresholdEd25519ClientVerifyingShareFromCredential as deriveThresholdEd25519ClientVerifyingShareFromCredentialValue,
  deriveThresholdEd25519HssClientInputsFromCredential as deriveThresholdEd25519HssClientInputsFromCredentialValue,
  deriveThresholdEd25519HssClientInputsFromPrfFirst as deriveThresholdEd25519HssClientInputsFromPrfFirstValue,
  openThresholdEd25519HssSeedOutput as openThresholdEd25519HssSeedOutputValue,
  prepareThresholdEd25519HssClientCeremonyFromCredential as prepareThresholdEd25519HssClientCeremonyFromCredentialValue,
  prepareThresholdEd25519HssClientCeremonyFromPrfFirst as prepareThresholdEd25519HssClientCeremonyFromPrfFirstValue,
  runThresholdEd25519HssCeremonyWithSession as runThresholdEd25519HssCeremonyWithSessionValue,
  type ThresholdEd25519LifecycleDeps,
} from './hssLifecycle';
import {
  buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactWasm,
  deriveThresholdEd25519HssClientOutputMaskWasm,
  prepareThresholdEd25519HssClientRequestWasm,
} from '../crypto/hssClientSignerWasm';

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

export function deriveThresholdEd25519HssClientInputsFromPrfFirst(
  deps: ThresholdEd25519PublicDeps,
  args: Parameters<typeof deriveThresholdEd25519HssClientInputsFromPrfFirstValue>[1],
): ReturnType<typeof deriveThresholdEd25519HssClientInputsFromPrfFirstValue> {
  return deriveThresholdEd25519HssClientInputsFromPrfFirstValue(deps, args);
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

export function deriveThresholdEd25519HssClientOutputMask(
  deps: ThresholdEd25519PublicDeps,
  args: Omit<Parameters<typeof deriveThresholdEd25519HssClientOutputMaskWasm>[0], 'workerCtx'>,
): ReturnType<typeof deriveThresholdEd25519HssClientOutputMaskWasm> {
  return deriveThresholdEd25519HssClientOutputMaskWasm({
    ...args,
    workerCtx: deps.getSignerWorkerContext(),
  });
}

export function buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact(
  deps: ThresholdEd25519PublicDeps,
  args: Omit<
    Parameters<typeof buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactWasm>[0],
    'workerCtx'
  >,
): ReturnType<typeof buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactWasm> {
  return buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactWasm({
    ...args,
    workerCtx: deps.getSignerWorkerContext(),
  });
}

export function completeThresholdEd25519HssClientCeremony(
  deps: ThresholdEd25519PublicDeps,
  args: Omit<Parameters<typeof completeThresholdEd25519HssClientCeremonyValue>[0], 'workerCtx'>,
): ReturnType<typeof completeThresholdEd25519HssClientCeremonyValue> {
  return completeThresholdEd25519HssClientCeremonyValue({
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
