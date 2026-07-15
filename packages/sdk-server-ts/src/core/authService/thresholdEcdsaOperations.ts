import type { RouterAbEcdsaHssWalletSessionClaims } from '../ThresholdService/validation';
import type { RouterAbEcdsaBootstrapExportRuntime } from '../routerAbSigning/RouterAbEcdsaBootstrapExportRuntime';
import type {
  EcdsaHssClientBootstrapRequest,
  EcdsaHssExportShareRequest,
  EcdsaHssExportShareResponse,
  EcdsaHssRouteResult,
  EcdsaHssServerBootstrapResponse,
} from '../types';

type ThresholdEcdsaOperationsInput = {
  readonly runtime: RouterAbEcdsaBootstrapExportRuntime | null;
};

function missingThresholdServiceResult<T>(): EcdsaHssRouteResult<T> {
  return {
    ok: false,
    code: 'internal',
    message: 'Threshold signing service is not configured',
  };
}

export async function ecdsaHssRoleLocalBootstrapWithRuntime(input: {
  readonly deps: ThresholdEcdsaOperationsInput;
  readonly request: EcdsaHssClientBootstrapRequest;
}): Promise<EcdsaHssRouteResult<EcdsaHssServerBootstrapResponse>> {
  if (!input.deps.runtime) return missingThresholdServiceResult();
  return await input.deps.runtime.ecdsaHssRoleLocalBootstrap(input.request);
}

export async function verifyEcdsaHssRoleLocalClientRootProofForExistingKeyWithRuntime(input: {
  readonly deps: ThresholdEcdsaOperationsInput;
  readonly request: EcdsaHssClientBootstrapRequest & {
    readonly clientRootProof: NonNullable<EcdsaHssClientBootstrapRequest['clientRootProof']>;
  };
}): Promise<EcdsaHssRouteResult<{ keyHandle: string }>> {
  if (!input.deps.runtime) return missingThresholdServiceResult();
  return await input.deps.runtime.verifyEcdsaHssRoleLocalClientRootProofForExistingKey(
    input.request,
  );
}

export async function ecdsaHssRoleLocalExportShareWithRuntime(input: {
  readonly deps: ThresholdEcdsaOperationsInput;
  readonly request: EcdsaHssExportShareRequest;
  readonly keyHandle: string;
  readonly claims: RouterAbEcdsaHssWalletSessionClaims;
}): Promise<EcdsaHssRouteResult<EcdsaHssExportShareResponse>> {
  if (!input.deps.runtime) return missingThresholdServiceResult();
  return await input.deps.runtime.ecdsaHssRoleLocalExportShare({
    request: input.request,
    keyHandle: input.keyHandle,
    claims: input.claims,
  });
}
