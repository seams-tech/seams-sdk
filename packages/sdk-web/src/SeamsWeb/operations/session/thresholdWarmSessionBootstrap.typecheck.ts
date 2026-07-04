import type { ThresholdWarmSessionContext } from './thresholdWarmSessionBootstrap';
import type {
  EmailOtpWalletAuthAuthority,
  PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  buildThresholdWarmSessionRequestEnvelope,
  createThresholdWarmSessionPolicyDraft,
} from './thresholdWarmSessionBootstrap';

declare const context: ThresholdWarmSessionContext;
declare const passkeyAuthority: PasskeyWalletAuthAuthority;
declare const emailOtpAuthority: EmailOtpWalletAuthAuthority;

createThresholdWarmSessionPolicyDraft(context, {
  kind: 'generated_signing_grant',
});

createThresholdWarmSessionPolicyDraft(context, {
  kind: 'shared_signing_grant',
  signingGrantId: 'wallet-session-1',
  ttlMs: 600_000,
  remainingUses: 3,
});

// @ts-expect-error generated-grant intent must be explicit.
createThresholdWarmSessionPolicyDraft(context);

// @ts-expect-error generated-grant input cannot carry a server-issued signing grant.
createThresholdWarmSessionPolicyDraft(context, {
  kind: 'generated_signing_grant',
  signingGrantId: 'wallet-session-1',
});

// @ts-expect-error shared-grant input must carry the server-issued budget limits.
createThresholdWarmSessionPolicyDraft(context, {
  kind: 'shared_signing_grant',
  signingGrantId: 'wallet-session-1',
});

buildThresholdWarmSessionRequestEnvelope({
  authority: passkeyAuthority,
  // @ts-expect-error warm-session request drafts must always carry a signing grant.
  requestedPolicy: {
    sessionId: 'threshold-session-1',
    ttlMs: 600_000,
    remainingUses: 3,
    routerAbNormalSigning: {
      kind: 'router_ab_ed25519_normal_signing_v1',
      signingWorkerId: 'signing-worker-1',
    },
  },
});

const warmSessionEnvelope = buildThresholdWarmSessionRequestEnvelope({
  authority: passkeyAuthority,
  requestedPolicy: {
    sessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
    ttlMs: 600_000,
    remainingUses: 3,
    routerAbNormalSigning: {
      kind: 'router_ab_ed25519_normal_signing_v1',
      signingWorkerId: 'signing-worker-1',
    },
  },
});

warmSessionEnvelope.session_policy.authority.walletId;

// @ts-expect-error Ed25519 warm-session route policies carry bound authority, never root rpId.
warmSessionEnvelope.session_policy.rpId;

// @ts-expect-error Ed25519 warm-session route policies carry bound authority, never authorityScope.
warmSessionEnvelope.session_policy.authorityScope;

buildThresholdWarmSessionRequestEnvelope({
  authority: emailOtpAuthority,
  requestedPolicy: {
    sessionId: 'threshold-session-2',
    signingGrantId: 'signing-grant-2',
    ttlMs: 600_000,
    remainingUses: 3,
    routerAbNormalSigning: {
      kind: 'router_ab_ed25519_normal_signing_v1',
      signingWorkerId: 'signing-worker-1',
    },
  },
});
