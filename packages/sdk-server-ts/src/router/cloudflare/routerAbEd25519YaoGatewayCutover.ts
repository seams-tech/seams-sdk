export type RouterAbEd25519YaoGatewayRegistrationOperationV1 =
  | 'registration_admission'
  | 'registration_execute'
  | 'recovery_admission'
  | 'recovery_execute'
  | 'recovery_activate'
  | 'export_admission'
  | 'export_execute';

/**
 * Admission opens a ceremony; every other phase continues one that already
 * exists. Only admission stops at the cutoff, so a ceremony admitted before the
 * boundary finishes on the store it started on.
 */
function isAdmissionOperation(
  operation: RouterAbEd25519YaoGatewayRegistrationOperationV1,
): boolean {
  switch (operation) {
    case 'registration_admission':
    case 'recovery_admission':
    case 'export_admission':
      return true;
    case 'registration_execute':
    case 'recovery_execute':
    case 'recovery_activate':
    case 'export_execute':
      return false;
  }
}

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
 * A deployment changes the backing store for every phase of a ceremony at once.
 * New admissions stop at the first boundary, while the continuation phases stay
 * on the legacy runtime until every ceremony admitted before that boundary
 * expires. This keeps all phases of one ceremony — registration admission and
 * execute, recovery admission, execute and activate, export admission and
 * execute — on the store it was admitted against. The operation is accepted to
 * make the admission cutoff explicit at the request boundary.
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
  if (input.nowMs < input.drainUntilMs && isAdmissionOperation(input.operation)) {
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
