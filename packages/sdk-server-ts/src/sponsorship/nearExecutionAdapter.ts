import type { CloudflareRelayAuthService } from '../router/authServicePort';
import {
  buildDelegateActionPolicyFromResolvedRule,
  type ResolvedSponsoredNearDelegatePolicy,
} from './near';
import type { SponsorshipExecutionAdapter } from './executionAdapter';

export type SponsoredNearDelegateExecutionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['executeSignedDelegate']>
>;

export type SponsoredNearDelegateExecutionAdapter = SponsorshipExecutionAdapter<
  SponsoredNearDelegateExecutionResult,
  'near_delegate',
  Record<string, never>
>;

export function createSponsoredNearDelegateExecutionAdapter(input: {
  authService: CloudflareRelayAuthService;
  hash: string;
  signedDelegate: unknown;
  allowedDelegateAction: ResolvedSponsoredNearDelegatePolicy['allowedDelegateActions'][number];
}): SponsoredNearDelegateExecutionAdapter {
  return {
    executorKind: 'near_delegate',
    meta: {},
    execute: async () =>
      await input.authService.executeSignedDelegate({
        hash: input.hash,
        signedDelegate: input.signedDelegate as any,
        policy: buildDelegateActionPolicyFromResolvedRule({
          allowedDelegateAction: input.allowedDelegateAction,
        }),
      }),
  };
}
