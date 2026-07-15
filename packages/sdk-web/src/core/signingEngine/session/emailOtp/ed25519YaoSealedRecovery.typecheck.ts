import type { EmailOtpEd25519YaoSilentRecoveryResultV1 } from './ed25519YaoSealedRecovery';

declare const recovery: Extract<
  EmailOtpEd25519YaoSilentRecoveryResultV1,
  { kind: 'recovered' }
>['recovery'];

const recovered: EmailOtpEd25519YaoSilentRecoveryResultV1 = {
  kind: 'recovered',
  recovery,
};
void recovered;

const recoveredWithReason = {
  kind: 'recovered',
  recovery,
  // @ts-expect-error Recovered state cannot also require reauthorization.
  reason: 'sealed_session_exhausted',
} satisfies EmailOtpEd25519YaoSilentRecoveryResultV1;
void recoveredWithReason;

const reauthRequired: EmailOtpEd25519YaoSilentRecoveryResultV1 = {
  kind: 'reauth_required',
  reason: 'wallet_session_expired',
};
void reauthRequired;

const reauthWithRecovery = {
  kind: 'reauth_required',
  reason: 'sealed_session_expired',
  // @ts-expect-error Reauthorization state cannot expose an activated recovery.
  recovery,
} satisfies EmailOtpEd25519YaoSilentRecoveryResultV1;
void reauthWithRecovery;
