import type { RouterAbEcdsaDerivationWalletSessionClaims } from '../ThresholdService/validation';
import type { RouterAbEcdsaBootstrapExportPort } from '../routerAbSigning/RouterAbEcdsaBootstrapExportRuntime';
import type {
  EcdsaDerivationClientBootstrapRequest,
  EcdsaDerivationExportShareRequest,
  EcdsaDerivationExportShareResponse,
  EcdsaDerivationRouteResult,
  EcdsaDerivationServerBootstrapResponse,
} from '../types';

type ThresholdEcdsaOperationsInput = {
  readonly runtime: RouterAbEcdsaBootstrapExportPort | null;
};

function missingRouterAbEcdsaRuntimeResult<T>(): EcdsaDerivationRouteResult<T> {
  return {
    ok: false,
    code: 'internal',
    message: 'Router A/B ECDSA runtime is not configured',
  };
}

export async function ecdsaDerivationRoleLocalBootstrapWithRuntime(input: {
  readonly deps: ThresholdEcdsaOperationsInput;
  readonly request: EcdsaDerivationClientBootstrapRequest;
}): Promise<EcdsaDerivationRouteResult<EcdsaDerivationServerBootstrapResponse>> {
  if (!input.deps.runtime) return missingRouterAbEcdsaRuntimeResult();
  return await input.deps.runtime.ecdsaDerivationRoleLocalBootstrap(input.request);
}

export async function verifyEcdsaDerivationRoleLocalClientRootProofForExistingKeyWithRuntime(input: {
  readonly deps: ThresholdEcdsaOperationsInput;
  readonly request: EcdsaDerivationClientBootstrapRequest & {
    readonly clientRootProof: NonNullable<EcdsaDerivationClientBootstrapRequest['clientRootProof']>;
  };
}): Promise<EcdsaDerivationRouteResult<{ keyHandle: string }>> {
  if (!input.deps.runtime) return missingRouterAbEcdsaRuntimeResult();
  return await input.deps.runtime.verifyEcdsaDerivationRoleLocalClientRootProofForExistingKey(
    input.request,
  );
}

export async function ecdsaDerivationRoleLocalExportShareWithRuntime(input: {
  readonly deps: ThresholdEcdsaOperationsInput;
  readonly request: EcdsaDerivationExportShareRequest;
  readonly keyHandle: string;
  readonly claims: RouterAbEcdsaDerivationWalletSessionClaims;
}): Promise<EcdsaDerivationRouteResult<EcdsaDerivationExportShareResponse>> {
  if (!input.deps.runtime) return missingRouterAbEcdsaRuntimeResult();
  return await input.deps.runtime.ecdsaDerivationRoleLocalExportShare({
    request: input.request,
    keyHandle: input.keyHandle,
    claims: input.claims,
  });
}
