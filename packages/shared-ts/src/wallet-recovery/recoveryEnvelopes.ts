export type RecoveryCodeLifecycleState =
  | {
      state: 'active';
      issuedAtMs: number;
      consumedAtMs?: never;
      revokedAtMs?: never;
    }
  | {
      state: 'consumed';
      issuedAtMs: number;
      consumedAtMs: number;
      revokedAtMs?: never;
    }
  | {
      state: 'revoked';
      issuedAtMs: number;
      revokedAtMs: number;
      consumedAtMs?: never;
    };
