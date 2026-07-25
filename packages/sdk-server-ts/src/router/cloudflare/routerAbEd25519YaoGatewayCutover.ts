export type RouterAbEd25519YaoGatewayRegistrationOperationV1 =
  | 'registration_admission'
  | 'registration_execute';

export type RouterAbEd25519YaoGatewayRegistrationRouteV1 =
  | {
      readonly kind: 'legacy_runtime';
      readonly drainUntilMs: number;
    }
  | {
      readonly kind: 'partitioned_d1';
      readonly drainUntilMs: number;
    };

/**
 * A deployment changes the backing store for both halves of registration at
 * once. During the drain window both operations stay on the legacy runtime,
 * so an admission issued before a deployment cannot strand its execute call
 * on the new store. The operation is intentionally accepted as an argument to
 * keep the boundary explicit while returning one shared route decision.
 */
export function resolveRouterAbEd25519YaoGatewayRegistrationRouteV1(input: {
  readonly operation: RouterAbEd25519YaoGatewayRegistrationOperationV1;
  readonly nowMs: number;
  readonly drainUntilMs: number;
}): RouterAbEd25519YaoGatewayRegistrationRouteV1 {
  validateTimestamp(input.nowMs, 'nowMs');
  validateTimestamp(input.drainUntilMs, 'drainUntilMs');
  void input.operation;
  return input.nowMs < input.drainUntilMs
    ? { kind: 'legacy_runtime', drainUntilMs: input.drainUntilMs }
    : { kind: 'partitioned_d1', drainUntilMs: input.drainUntilMs };
}

function validateTimestamp(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`Router A/B Gateway ${label} must be a non-negative safe integer`);
  }
}
