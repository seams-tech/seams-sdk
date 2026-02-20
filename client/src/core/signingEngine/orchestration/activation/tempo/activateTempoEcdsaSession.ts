import {
  activateEcdsaSession,
  type ActivateEcdsaSessionDeps,
  type ActivateEcdsaSessionRequest,
  type ThresholdEcdsaSessionBootstrapResult,
} from '../thresholdEcdsa';

export async function activateTempoEcdsaSession(
  deps: ActivateEcdsaSessionDeps,
  args: ActivateEcdsaSessionRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  return await activateEcdsaSession(deps, args);
}
