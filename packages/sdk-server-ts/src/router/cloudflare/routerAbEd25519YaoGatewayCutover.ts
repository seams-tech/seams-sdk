export type RouterAbEd25519YaoGatewayCutoverFamilyV1 = 'registration' | 'recovery' | 'export';

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

function familyOfOperation(
  operation: RouterAbEd25519YaoGatewayRegistrationOperationV1,
): RouterAbEd25519YaoGatewayCutoverFamilyV1 {
  switch (operation) {
    case 'registration_admission':
    case 'registration_execute':
      return 'registration';
    case 'recovery_admission':
    case 'recovery_execute':
    case 'recovery_activate':
      return 'recovery';
    case 'export_admission':
    case 'export_execute':
      return 'export';
  }
}

export type RouterAbEd25519YaoGatewayCutoverWindowV1 = {
  readonly admissionCutoffMs: number;
  readonly drainUntilMs: number;
};

/**
 * Each family carries its own window. A family with no window has not begun its
 * cutover and stays on the legacy runtime indefinitely. Sharing one window
 * across families would mean a family wired after an earlier family's drain had
 * already elapsed would inherit that expired window and switch stores with no
 * drain of its own, stranding ceremonies admitted against the legacy runtime.
 */
export type RouterAbEd25519YaoGatewayCutoverStateV1 = {
  readonly [Family in RouterAbEd25519YaoGatewayCutoverFamilyV1]?:
    | RouterAbEd25519YaoGatewayCutoverWindowV1
    | undefined;
};

export type RouterAbEd25519YaoGatewayRegistrationRouteV1 =
  | { readonly kind: 'legacy_runtime'; readonly window: RouterAbEd25519YaoGatewayCutoverWindowV1 | null }
  | { readonly kind: 'admission_blocked'; readonly window: RouterAbEd25519YaoGatewayCutoverWindowV1 }
  | { readonly kind: 'partitioned_d1'; readonly window: RouterAbEd25519YaoGatewayCutoverWindowV1 };

/**
 * A deployment changes the backing store for every phase of one family at once.
 * New admissions stop at that family's cutoff, while its continuation phases
 * stay on the legacy runtime until every ceremony admitted before the cutoff
 * expires. This keeps all phases of one ceremony on the store it was admitted
 * against, and keeps families independent so they can be cut over one at a time.
 */
export function resolveRouterAbEd25519YaoGatewayRegistrationRouteV1(input: {
  readonly operation: RouterAbEd25519YaoGatewayRegistrationOperationV1;
  readonly nowMs: number;
  readonly cutover: RouterAbEd25519YaoGatewayCutoverStateV1;
}): RouterAbEd25519YaoGatewayRegistrationRouteV1 {
  validateTimestamp(input.nowMs, 'nowMs');
  const window = input.cutover[familyOfOperation(input.operation)];
  if (!window) return { kind: 'legacy_runtime', window: null };
  validateTimestamp(window.admissionCutoffMs, 'admissionCutoffMs');
  validateTimestamp(window.drainUntilMs, 'drainUntilMs');
  if (window.admissionCutoffMs > window.drainUntilMs) {
    throw new Error('Router A/B Gateway admissionCutoffMs must not exceed drainUntilMs');
  }
  if (input.nowMs < window.admissionCutoffMs) return { kind: 'legacy_runtime', window };
  if (input.nowMs < window.drainUntilMs) {
    return isAdmissionOperation(input.operation)
      ? { kind: 'admission_blocked', window }
      : { kind: 'legacy_runtime', window };
  }
  return { kind: 'partitioned_d1', window };
}

function validateTimestamp(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`Router A/B Gateway ${label} must be a non-negative safe integer`);
  }
}
