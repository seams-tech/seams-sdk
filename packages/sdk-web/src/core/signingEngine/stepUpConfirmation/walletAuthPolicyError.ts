import type { WalletAuthIntent } from '@/core/types/seams';

export type WalletAuthPolicyErrorCode =
  | 'passkey_step_up_required'
  | 'fresh_email_otp_required'
  | 'operation_blocked_by_policy';

export type WalletAuthPolicy =
  | 'export_requires_passkey'
  | 'sensitive_operation_requires_passkey'
  | 'sensitive_operation_requires_fresh_email_otp'
  | 'email_otp_denied_by_policy';

export class WalletAuthPolicyError extends Error {
  readonly code: WalletAuthPolicyErrorCode;
  readonly policy: WalletAuthPolicy;
  readonly intent?: WalletAuthIntent;
  readonly operationLabel?: string;

  constructor(args: {
    code: WalletAuthPolicyErrorCode;
    policy: WalletAuthPolicy;
    message: string;
    intent?: WalletAuthIntent;
    operationLabel?: string;
  }) {
    super(args.message);
    this.name = 'WalletAuthPolicyError';
    this.code = args.code;
    this.policy = args.policy;
    this.intent = args.intent;
    this.operationLabel = args.operationLabel;
  }
}
