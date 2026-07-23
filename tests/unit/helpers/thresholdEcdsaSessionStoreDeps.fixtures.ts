import type { ThresholdEcdsaSessionStoreDeps } from '@/core/signingEngine/session/persistence/records';

/**
 * Store-deps wiring for the runtime threshold ECDSA session store. Tests override
 * only the members they exercise (e.g. a deterministic `now`, or an
 * `exportArtifactsByLane` cache).
 *
 * Note: `signingSessionRecord.fixtures.ts` has a zero-argument
 * `createThresholdEcdsaStoreFixture()` for the warm-session suites; this builder
 * exists so store-focused tests can override individual deps members without
 * touching that helper.
 */
export function makeThresholdEcdsaSessionStoreDeps(
  overrides: Partial<ThresholdEcdsaSessionStoreDeps> = {},
): ThresholdEcdsaSessionStoreDeps {
  return {
    recordsByLane: new Map(),
    ...overrides,
  };
}
