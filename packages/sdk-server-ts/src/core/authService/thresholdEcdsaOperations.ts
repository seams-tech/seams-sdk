import type { RouterAbEcdsaHssWalletSessionClaims } from '../ThresholdService/validation';
import type { ThresholdSigningService as ThresholdSigningServiceType } from '../ThresholdService';
import type {
  EcdsaHssClientBootstrapRequest,
  EcdsaHssExportShareRequest,
  EcdsaHssExportShareResponse,
  EcdsaHssRouteResult,
  EcdsaHssServerBootstrapResponse,
} from '../types';

type ThresholdEcdsaOperationsInput = {
  readonly threshold: ThresholdSigningServiceType | null;
};

function missingThresholdServiceResult<T>(): EcdsaHssRouteResult<T> {
  return {
    ok: false,
    code: 'internal',
    message: 'Threshold signing service is not configured',
  };
}

export async function ecdsaHssRoleLocalBootstrapWithThreshold(input: {
  readonly deps: ThresholdEcdsaOperationsInput;
  readonly request: EcdsaHssClientBootstrapRequest;
}): Promise<EcdsaHssRouteResult<EcdsaHssServerBootstrapResponse>> {
  if (!input.deps.threshold) return missingThresholdServiceResult();
  return await input.deps.threshold.ecdsaHssRoleLocalBootstrap(input.request);
}

export async function verifyEcdsaHssRoleLocalClientRootProofForExistingKeyWithThreshold(input: {
  readonly deps: ThresholdEcdsaOperationsInput;
  readonly request: EcdsaHssClientBootstrapRequest & {
    readonly clientRootProof: NonNullable<EcdsaHssClientBootstrapRequest['clientRootProof']>;
  };
}): Promise<EcdsaHssRouteResult<{ keyHandle: string }>> {
  if (!input.deps.threshold) return missingThresholdServiceResult();
  return await input.deps.threshold.verifyEcdsaHssRoleLocalClientRootProofForExistingKey(
    input.request,
  );
}

export async function ecdsaHssRoleLocalExportShareWithThreshold(input: {
  readonly deps: ThresholdEcdsaOperationsInput;
  readonly request: EcdsaHssExportShareRequest;
  readonly keyHandle: string;
  readonly claims: RouterAbEcdsaHssWalletSessionClaims;
}): Promise<EcdsaHssRouteResult<EcdsaHssExportShareResponse>> {
  if (!input.deps.threshold) return missingThresholdServiceResult();
  return await input.deps.threshold.ecdsaHssRoleLocalExportShare({
    request: input.request,
    keyHandle: input.keyHandle,
    claims: input.claims,
  });
}
