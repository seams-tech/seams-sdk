import type { ThresholdWarmSessionContext } from './thresholdWarmSessionBootstrap';
import {
  buildThresholdWarmSessionRequestEnvelope,
  createThresholdWarmSessionPolicyDraft,
} from './thresholdWarmSessionBootstrap';

declare const context: ThresholdWarmSessionContext;

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
  authority: { kind: 'passkey_rp', rpId: 'example.localhost' },
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
  authority: { kind: 'passkey_rp', rpId: 'example.localhost' },
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

warmSessionEnvelope.session_policy.authorityScope.rpId;

// @ts-expect-error Ed25519 warm-session route policies carry authorityScope, never root rpId.
warmSessionEnvelope.session_policy.rpId;

buildThresholdWarmSessionRequestEnvelope({
  authority: {
    kind: 'exact_authority_scope',
    authorityScope: {
      kind: 'email_otp',
      proofKind: 'google_sso_registration',
      email: 'alice@example.test',
      googleEmailOtpRegistrationAttemptId: 'attempt-1',
      googleEmailOtpRegistrationOfferId: 'offer-1',
      googleEmailOtpRegistrationCandidateId: 'candidate-1',
    },
  },
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
