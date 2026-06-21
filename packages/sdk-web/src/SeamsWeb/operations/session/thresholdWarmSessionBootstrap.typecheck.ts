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
  rpId: 'example.localhost',
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
