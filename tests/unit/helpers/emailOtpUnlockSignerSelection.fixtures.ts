import type {
  EmailOtpUnlockEd25519Identity,
  EmailOtpUnlockSignerSelection,
} from '@/core/signingEngine/session/emailOtp/publicTypes';
import { buildMpcMaterialActivationRefFixture } from './ecdsaMaterialRef.fixtures';

const RUNTIME_POLICY_SCOPE = {
  orgId: 'org-test',
  projectId: 'project-test',
  envId: 'env-test',
  signingRootVersion: 'v1',
} as const;

function ed25519Identity(): EmailOtpUnlockEd25519Identity {
  return {
    materialActivation: buildMpcMaterialActivationRefFixture(
      'email-otp-unlock',
      'alice.testnet',
      'signing-worker-email-otp-1',
      'ed25519ks_email_otp_1',
    ),
    nearAccountId: 'alice.testnet',
    signerSlot: 1,
    operationalPublicKey: `ed25519:${'1'.repeat(44)}`,
    thresholdSessionId: 'threshold-session-email-otp-1',
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
  };
}

export function emailOtpEcdsaUnlockSignerSelectionFixture(): Extract<
  EmailOtpUnlockSignerSelection,
  { readonly kind: 'ecdsa' }
> {
  return {
    kind: 'ecdsa',
    keyHandle: 'ecdsa-key-handle-1',
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    ed25519: { kind: 'absent' },
  };
}

export function emailOtpEd25519OnlyUnlockSignerSelectionFixture(): Extract<
  EmailOtpUnlockSignerSelection,
  { readonly kind: 'ed25519_only' }
> {
  return {
    kind: 'ed25519_only',
    ...ed25519Identity(),
  };
}
