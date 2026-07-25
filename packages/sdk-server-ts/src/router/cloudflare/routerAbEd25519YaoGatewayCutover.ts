export type RouterAbEd25519YaoGatewayRegistrationOperationV1 =
  | 'registration_admission'
  | 'registration_execute';

export type RouterAbEd25519YaoGatewayRegistrationRouteV1 =
  | {
      readonly kind: 'legacy_runtime';
      readonly admissionCutoffMs: number;
      readonly drainUntilMs: number;
    }
  | {
      readonly kind: 'admission_blocked';
      readonly admissionCutoffMs: number;
      readonly drainUntilMs: number;
    }
  | {
      readonly kind: 'partitioned_d1';
      readonly admissionCutoffMs: number;
      readonly drainUntilMs: number;
    };

/**
 * A deployment changes the backing store for both halves of registration at
 * once. New admissions stop at the first boundary, while executes continue on
 * the legacy runtime until every admission made before that boundary expires.
 * This keeps one admission and execute pair on one backing store across a
 * deployment. The operation is accepted to make the admission cutoff explicit
 * at the request boundary.
 */
export function resolveRouterAbEd25519YaoGatewayRegistrationRouteV1(input: {
  readonly operation: RouterAbEd25519YaoGatewayRegistrationOperationV1;
  readonly nowMs: number;
  readonly admissionCutoffMs: number;
  readonly drainUntilMs: number;
}): RouterAbEd25519YaoGatewayRegistrationRouteV1 {
  validateTimestamp(input.nowMs, 'nowMs');
  validateTimestamp(input.admissionCutoffMs, 'admissionCutoffMs');
  validateTimestamp(input.drainUntilMs, 'drainUntilMs');
  if (input.admissionCutoffMs > input.drainUntilMs) {
    throw new Error('Router A/B Gateway admissionCutoffMs must not exceed drainUntilMs');
  }
  if (input.nowMs < input.admissionCutoffMs) {
    return {
      kind: 'legacy_runtime',
      admissionCutoffMs: input.admissionCutoffMs,
      drainUntilMs: input.drainUntilMs,
    };
  }
  if (input.nowMs < input.drainUntilMs && input.operation === 'registration_admission') {
    return {
      kind: 'admission_blocked',
      admissionCutoffMs: input.admissionCutoffMs,
      drainUntilMs: input.drainUntilMs,
    };
  }
  if (input.nowMs < input.drainUntilMs) {
    return {
      kind: 'legacy_runtime',
      admissionCutoffMs: input.admissionCutoffMs,
      drainUntilMs: input.drainUntilMs,
    };
  }
  return {
    kind: 'partitioned_d1',
    admissionCutoffMs: input.admissionCutoffMs,
    drainUntilMs: input.drainUntilMs,
  };
}

function validateTimestamp(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`Router A/B Gateway ${label} must be a non-negative safe integer`);
  }
}
