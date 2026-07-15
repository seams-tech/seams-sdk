import { secureRandomId } from '@shared/utils/secureRandomId';

const EMAIL_OTP_ED25519_YAO_ROOT_BYTES = 32;
const MAX_EMAIL_OTP_ED25519_YAO_ROOT_HANDLES = 64;

export type EmailOtpEd25519YaoRootPurpose = 'registration' | 'recovery';

export type EmailOtpEd25519YaoRootScope = {
  kind: 'email_otp_ed25519_yao_root_scope_v1';
  purpose: EmailOtpEd25519YaoRootPurpose;
  walletId: string;
  providerSubject: string;
  nearEd25519SigningKeyId: string;
  signingRootId: string;
  signerSlot: number;
  participantIds: readonly [number, number];
};

export type EmailOtpEd25519YaoRootBinding = {
  kind: 'email_otp_ed25519_yao_root_binding_v1';
  lifecycleId: string;
  scope: EmailOtpEd25519YaoRootScope;
};

export type EmailOtpEd25519YaoRootHandle = {
  kind: 'email_otp_ed25519_yao_root_handle_v1';
  handleId: string;
  purpose: EmailOtpEd25519YaoRootPurpose;
  expiresAtMs: number;
};

export type EmailOtpEd25519YaoPendingFactorHandle = {
  kind: 'email_otp_ed25519_yao_pending_factor_handle_v1';
  handleId: string;
  purpose: EmailOtpEd25519YaoRootPurpose;
  expiresAtMs: number;
};

export type EmailOtpEd25519YaoOwnedFactorSecret = {
  kind: 'email_otp_ed25519_yao_owned_factor_secret_v1';
  binding: EmailOtpEd25519YaoRootBinding;
  factorSecret32: Uint8Array;
};

export type EmailOtpEd25519YaoRootConsumerResult<T> =
  | { ok: true; value: T }
  | { ok: false; code: string; message: string };

export type EmailOtpEd25519YaoRootConsumer<T> = {
  consumeOwnedFactorSecret(
    input: EmailOtpEd25519YaoOwnedFactorSecret,
  ): Promise<EmailOtpEd25519YaoRootConsumerResult<T>>;
};

export type EmailOtpEd25519YaoRootConsumeResult<T> =
  | EmailOtpEd25519YaoRootConsumerResult<T>
  | {
      ok: false;
      code: 'root_handle_missing' | 'root_handle_expired' | 'root_handle_scope_mismatch';
      message: string;
    };

type AvailableEmailOtpEd25519YaoRootEntry = {
  kind: 'available';
  handle: EmailOtpEd25519YaoRootHandle;
  scope: EmailOtpEd25519YaoRootScope;
  factorSecret32: Uint8Array;
};

type AvailableEmailOtpEd25519YaoPendingFactorEntry = {
  kind: 'pending_factor';
  handle: EmailOtpEd25519YaoPendingFactorHandle;
  walletId: string;
  providerSubject: string;
  factorSecret32: Uint8Array;
};

function requireNonEmpty(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function requirePositiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return value;
}

function requireParticipantIds(
  participantIds: readonly [number, number],
): readonly [number, number] {
  const first = requirePositiveInteger(participantIds[0], 'participantIds[0]');
  const second = requirePositiveInteger(participantIds[1], 'participantIds[1]');
  if (first === second) throw new Error('participantIds must be distinct');
  return [first, second];
}

function copyScope(scope: EmailOtpEd25519YaoRootScope): EmailOtpEd25519YaoRootScope {
  return {
    kind: 'email_otp_ed25519_yao_root_scope_v1',
    purpose: scope.purpose,
    walletId: requireNonEmpty(scope.walletId, 'walletId'),
    providerSubject: requireNonEmpty(scope.providerSubject, 'providerSubject'),
    nearEd25519SigningKeyId: requireNonEmpty(
      scope.nearEd25519SigningKeyId,
      'nearEd25519SigningKeyId',
    ),
    signingRootId: requireNonEmpty(scope.signingRootId, 'signingRootId'),
    signerSlot: requirePositiveInteger(scope.signerSlot, 'signerSlot'),
    participantIds: requireParticipantIds(scope.participantIds),
  };
}

function scopesMatch(
  left: EmailOtpEd25519YaoRootScope,
  right: EmailOtpEd25519YaoRootScope,
): boolean {
  return (
    left.kind === right.kind &&
    left.purpose === right.purpose &&
    left.walletId === right.walletId &&
    left.providerSubject === right.providerSubject &&
    left.nearEd25519SigningKeyId === right.nearEd25519SigningKeyId &&
    left.signingRootId === right.signingRootId &&
    left.signerSlot === right.signerSlot &&
    left.participantIds[0] === right.participantIds[0] &&
    left.participantIds[1] === right.participantIds[1]
  );
}

function zeroizeEntry(entry: AvailableEmailOtpEd25519YaoRootEntry): void {
  entry.factorSecret32.fill(0);
}

function zeroizePendingEntry(entry: AvailableEmailOtpEd25519YaoPendingFactorEntry): void {
  entry.factorSecret32.fill(0);
}

function missingHandleResult<T>(): EmailOtpEd25519YaoRootConsumeResult<T> {
  return {
    ok: false,
    code: 'root_handle_missing',
    message: 'Email OTP Ed25519 Yao root handle is unavailable or already consumed',
  };
}

export class EmailOtpEd25519YaoRootVault {
  private readonly entries = new Map<string, AvailableEmailOtpEd25519YaoRootEntry>();
  private readonly pendingEntries = new Map<
    string,
    AvailableEmailOtpEd25519YaoPendingFactorEntry
  >();

  issuePendingOwned(input: {
    purpose: EmailOtpEd25519YaoRootPurpose;
    walletId: string;
    providerSubject: string;
    ownedFactorSecret32: Uint8Array;
    expiresAtMs: number;
    nowMs: number;
  }): EmailOtpEd25519YaoPendingFactorHandle {
    const factorSecret32 = input.ownedFactorSecret32;
    try {
      if (
        !(factorSecret32 instanceof Uint8Array) ||
        factorSecret32.length !== EMAIL_OTP_ED25519_YAO_ROOT_BYTES
      ) {
        throw new Error('Email OTP Ed25519 Yao factor secret must contain 32 bytes');
      }
      if (!Number.isSafeInteger(input.nowMs) || input.nowMs < 0) {
        throw new Error('nowMs must be a non-negative safe integer');
      }
      if (!Number.isSafeInteger(input.expiresAtMs) || input.expiresAtMs <= input.nowMs) {
        throw new Error('expiresAtMs must be a future safe integer');
      }
      this.removeExpired(input.nowMs);
      if (this.entries.size + this.pendingEntries.size >= MAX_EMAIL_OTP_ED25519_YAO_ROOT_HANDLES) {
        throw new Error('Email OTP Ed25519 Yao root handle capacity is exhausted');
      }
      const handle: EmailOtpEd25519YaoPendingFactorHandle = {
        kind: 'email_otp_ed25519_yao_pending_factor_handle_v1',
        handleId: secureRandomId(
          'email-otp-ed25519-yao-pending-factor',
          32,
          'Email OTP Ed25519 Yao pending factor handles',
        ),
        purpose: input.purpose,
        expiresAtMs: input.expiresAtMs,
      };
      this.pendingEntries.set(handle.handleId, {
        kind: 'pending_factor',
        handle,
        walletId: requireNonEmpty(input.walletId, 'walletId'),
        providerSubject: requireNonEmpty(input.providerSubject, 'providerSubject'),
        factorSecret32: factorSecret32.slice(),
      });
      return handle;
    } finally {
      factorSecret32.fill(0);
    }
  }

  bindPending(input: {
    handle: EmailOtpEd25519YaoPendingFactorHandle;
    scope: EmailOtpEd25519YaoRootScope;
    expiresAtMs: number;
    nowMs: number;
  }): EmailOtpEd25519YaoRootHandle {
    const entry = this.pendingEntries.get(input.handle.handleId);
    if (!entry) throw new Error('Email OTP Ed25519 Yao pending factor handle is unavailable');
    if (
      entry.handle.kind !== input.handle.kind ||
      entry.handle.purpose !== input.handle.purpose ||
      entry.handle.expiresAtMs !== input.handle.expiresAtMs
    ) {
      throw new Error('Email OTP Ed25519 Yao pending factor handle metadata changed');
    }
    if (input.nowMs >= entry.handle.expiresAtMs) {
      this.pendingEntries.delete(entry.handle.handleId);
      zeroizePendingEntry(entry);
      throw new Error('Email OTP Ed25519 Yao pending factor handle expired');
    }
    if (input.expiresAtMs > entry.handle.expiresAtMs) {
      throw new Error('Email OTP Ed25519 Yao root expiry exceeds pending factor expiry');
    }
    const scope = copyScope(input.scope);
    if (
      scope.purpose !== entry.handle.purpose ||
      scope.walletId !== entry.walletId ||
      scope.providerSubject !== entry.providerSubject
    ) {
      throw new Error('Email OTP Ed25519 Yao pending factor scope changed');
    }
    this.pendingEntries.delete(entry.handle.handleId);
    const ownedFactorSecret32 = entry.factorSecret32.slice();
    zeroizePendingEntry(entry);
    return this.issueOwned({
      scope,
      ownedFactorSecret32,
      expiresAtMs: input.expiresAtMs,
      nowMs: input.nowMs,
    });
  }

  issueOwned(input: {
    scope: EmailOtpEd25519YaoRootScope;
    ownedFactorSecret32: Uint8Array;
    expiresAtMs: number;
    nowMs: number;
  }): EmailOtpEd25519YaoRootHandle {
    const factorSecret32 = input.ownedFactorSecret32;
    try {
      if (
        !(factorSecret32 instanceof Uint8Array) ||
        factorSecret32.length !== EMAIL_OTP_ED25519_YAO_ROOT_BYTES
      ) {
        throw new Error('Email OTP Ed25519 Yao factor secret must contain 32 bytes');
      }
      if (!Number.isSafeInteger(input.nowMs) || input.nowMs < 0) {
        throw new Error('nowMs must be a non-negative safe integer');
      }
      if (!Number.isSafeInteger(input.expiresAtMs) || input.expiresAtMs <= input.nowMs) {
        throw new Error('expiresAtMs must be a future safe integer');
      }
      this.removeExpired(input.nowMs);
      if (this.entries.size + this.pendingEntries.size >= MAX_EMAIL_OTP_ED25519_YAO_ROOT_HANDLES) {
        throw new Error('Email OTP Ed25519 Yao root handle capacity is exhausted');
      }
      const scope = copyScope(input.scope);
      const handle: EmailOtpEd25519YaoRootHandle = {
        kind: 'email_otp_ed25519_yao_root_handle_v1',
        handleId: secureRandomId(
          'email-otp-ed25519-yao-root',
          32,
          'Email OTP Ed25519 Yao root handles',
        ),
        purpose: scope.purpose,
        expiresAtMs: input.expiresAtMs,
      };
      this.entries.set(handle.handleId, {
        kind: 'available',
        handle,
        scope,
        factorSecret32: factorSecret32.slice(),
      });
      return handle;
    } finally {
      factorSecret32.fill(0);
    }
  }

  async consume<T>(input: {
    handle: EmailOtpEd25519YaoRootHandle;
    binding: EmailOtpEd25519YaoRootBinding;
    consumer: EmailOtpEd25519YaoRootConsumer<T>;
    nowMs: number;
  }): Promise<EmailOtpEd25519YaoRootConsumeResult<T>> {
    const entry = this.entries.get(input.handle.handleId);
    if (!entry) return missingHandleResult();
    if (
      entry.handle.kind !== input.handle.kind ||
      entry.handle.purpose !== input.handle.purpose ||
      entry.handle.expiresAtMs !== input.handle.expiresAtMs
    ) {
      return {
        ok: false,
        code: 'root_handle_scope_mismatch',
        message: 'Email OTP Ed25519 Yao root handle metadata changed',
      };
    }
    if (input.nowMs >= entry.handle.expiresAtMs) {
      this.entries.delete(entry.handle.handleId);
      zeroizeEntry(entry);
      return {
        ok: false,
        code: 'root_handle_expired',
        message: 'Email OTP Ed25519 Yao root handle expired',
      };
    }
    const binding: EmailOtpEd25519YaoRootBinding = {
      kind: 'email_otp_ed25519_yao_root_binding_v1',
      lifecycleId: requireNonEmpty(input.binding.lifecycleId, 'lifecycleId'),
      scope: copyScope(input.binding.scope),
    };
    if (!scopesMatch(entry.scope, binding.scope)) {
      return {
        ok: false,
        code: 'root_handle_scope_mismatch',
        message: 'Email OTP Ed25519 Yao root handle scope changed',
      };
    }

    this.entries.delete(entry.handle.handleId);
    const ownedFactorSecret32 = entry.factorSecret32.slice();
    zeroizeEntry(entry);
    try {
      return await input.consumer.consumeOwnedFactorSecret({
        kind: 'email_otp_ed25519_yao_owned_factor_secret_v1',
        binding,
        factorSecret32: ownedFactorSecret32,
      });
    } finally {
      ownedFactorSecret32.fill(0);
    }
  }

  remove(handle: EmailOtpEd25519YaoRootHandle): boolean {
    const entry = this.entries.get(handle.handleId);
    if (!entry) return false;
    if (
      entry.handle.kind !== handle.kind ||
      entry.handle.purpose !== handle.purpose ||
      entry.handle.expiresAtMs !== handle.expiresAtMs
    ) {
      throw new Error('Email OTP Ed25519 Yao root handle metadata changed');
    }
    this.entries.delete(handle.handleId);
    zeroizeEntry(entry);
    return true;
  }

  removePending(handle: EmailOtpEd25519YaoPendingFactorHandle): boolean {
    const entry = this.pendingEntries.get(handle.handleId);
    if (!entry) return false;
    if (
      entry.handle.kind !== handle.kind ||
      entry.handle.purpose !== handle.purpose ||
      entry.handle.expiresAtMs !== handle.expiresAtMs
    ) {
      throw new Error('Email OTP Ed25519 Yao pending factor handle metadata changed');
    }
    this.pendingEntries.delete(handle.handleId);
    zeroizePendingEntry(entry);
    return true;
  }

  clear(): void {
    for (const entry of this.entries.values()) zeroizeEntry(entry);
    for (const entry of this.pendingEntries.values()) zeroizePendingEntry(entry);
    this.entries.clear();
    this.pendingEntries.clear();
  }

  private removeExpired(nowMs: number): void {
    for (const entry of this.entries.values()) {
      if (nowMs < entry.handle.expiresAtMs) continue;
      this.entries.delete(entry.handle.handleId);
      zeroizeEntry(entry);
    }
    for (const entry of this.pendingEntries.values()) {
      if (nowMs < entry.handle.expiresAtMs) continue;
      this.pendingEntries.delete(entry.handle.handleId);
      zeroizePendingEntry(entry);
    }
  }
}
