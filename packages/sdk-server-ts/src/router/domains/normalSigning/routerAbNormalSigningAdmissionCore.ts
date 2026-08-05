import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { ThresholdEd25519AuthorityScope } from '../../../core/types';
import type {
  RouterAbNormalSigningAdmissionAdapter,
  RouterAbNormalSigningAdmissionInput,
  RouterAbNormalSigningAdmissionResult,
} from './routerAbPrivateSigningWorker';

export type RouterAbNormalSigningProjectPolicyDecision =
  | { kind: 'allowed' }
  | { kind: 'rejected'; retryAfterMs: number };

export type RouterAbNormalSigningAbuseDecision =
  | { kind: 'allowed' }
  | { kind: 'rate_limited'; retryAfterMs: number }
  | { kind: 'rejected'; retryAfterMs: number };

export interface RouterAbNormalSigningProjectPolicyProvider {
  evaluateProjectPolicy(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningProjectPolicyDecision>;
}

export interface RouterAbNormalSigningAbuseProvider {
  evaluateAbuse(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningAbuseDecision>;
}

export interface RouterAbNormalSigningAdmissionStore
  extends
    RouterAbNormalSigningProjectPolicyProvider,
    RouterAbNormalSigningAbuseProvider {}

export class InMemoryRouterAbNormalSigningAdmissionStore implements RouterAbNormalSigningAdmissionStore {
  private readonly projectPolicies = new Map<string, RouterAbNormalSigningProjectPolicyDecision>();
  private readonly abuseDecisions = new Map<string, RouterAbNormalSigningAbuseDecision>();

  setProjectPolicy(
    scope: RuntimePolicyScope,
    decision: RouterAbNormalSigningProjectPolicyDecision,
  ): void {
    this.projectPolicies.set(runtimePolicyScopeKey(scope), decision);
  }

  clearProjectPolicy(scope: RuntimePolicyScope): void {
    this.projectPolicies.delete(runtimePolicyScopeKey(scope));
  }

  setAbuseDecision(
    input: RouterAbNormalSigningAdmissionInput,
    decision: RouterAbNormalSigningAbuseDecision,
  ): void {
    this.abuseDecisions.set(abusePrincipalKey(input), decision);
  }

  clearAbuseDecision(input: RouterAbNormalSigningAdmissionInput): void {
    this.abuseDecisions.delete(abusePrincipalKey(input));
  }

  async evaluateProjectPolicy(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningProjectPolicyDecision> {
    return (
      this.projectPolicies.get(runtimePolicyScopeKey(input.runtimePolicyScope)) || {
        kind: 'allowed',
      }
    );
  }

  async evaluateAbuse(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningAbuseDecision> {
    return this.abuseDecisions.get(abusePrincipalKey(input)) || { kind: 'allowed' };
  }

}

class DefaultRouterAbNormalSigningAdmissionAdapter
  implements RouterAbNormalSigningAdmissionAdapter
{
  constructor(
    private readonly store: RouterAbNormalSigningAdmissionStore,
    private readonly now: () => number,
  ) {}

  async evaluatePolicy(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningAdmissionResult> {
    if (input.expiresAtMs <= this.now()) {
      return admissionFailure(
        408,
        'invalid_body',
        'Router A/B normal-signing request is expired',
      );
    }

    const projectPolicy = await this.store.evaluateProjectPolicy(input);
    switch (projectPolicy.kind) {
      case 'allowed':
        break;
      case 'rejected':
        return admissionFailure(
          403,
          'project_policy_rejected',
          'Router A/B normal-signing project policy rejected the request',
        );
      default:
        return assertNever(projectPolicy);
    }

    const abuse = await this.store.evaluateAbuse(input);
    switch (abuse.kind) {
      case 'allowed':
        return { ok: true };
      case 'rate_limited':
        return admissionFailure(
          429,
          'rate_limited',
          'Router A/B normal-signing request is rate limited',
        );
      case 'rejected':
        return admissionFailure(
          403,
          'abuse_rejected',
          'Router A/B normal-signing abuse policy rejected the request',
        );
      default:
        return assertNever(abuse);
    }
  }

}

export function createRouterAbNormalSigningAdmissionAdapter(
  store: RouterAbNormalSigningAdmissionStore,
  options: { readonly now?: () => number } = {},
): RouterAbNormalSigningAdmissionAdapter {
  return new DefaultRouterAbNormalSigningAdmissionAdapter(store, options.now || Date.now);
}

export function createInMemoryRouterAbNormalSigningAdmissionStore(): InMemoryRouterAbNormalSigningAdmissionStore {
  return new InMemoryRouterAbNormalSigningAdmissionStore();
}

export function createInMemoryRouterAbNormalSigningAdmissionAdapter(
  options: { readonly now?: () => number } = {},
): {
  readonly adapter: RouterAbNormalSigningAdmissionAdapter;
  readonly store: InMemoryRouterAbNormalSigningAdmissionStore;
} {
  const store = createInMemoryRouterAbNormalSigningAdmissionStore();
  return {
    store,
    adapter: createRouterAbNormalSigningAdmissionAdapter(store, options),
  };
}

function admissionFailure(
  status: 400 | 401 | 403 | 408 | 409 | 429 | 500 | 503,
  code:
    | 'project_policy_rejected'
    | 'abuse_rejected'
    | 'rate_limited'
    | 'invalid_body',
  message: string,
): RouterAbNormalSigningAdmissionResult {
  return { ok: false, status, code, message };
}

export function runtimePolicyScopeKey(scope: RuntimePolicyScope): string {
  return [scope.orgId, scope.projectId, scope.envId, scope.signingRootVersion].join('\x1f');
}

function ed25519AdmissionAuthorityScopeKey(scope: ThresholdEd25519AuthorityScope): string {
  switch (scope.kind) {
    case 'passkey_rp':
      return `passkey_rp:${scope.rpId}`;
    case 'email_otp':
      return `email_otp:${scope.provider}:${scope.providerUserId}`;
  }
}

function admissionAuthorityScope(input: RouterAbNormalSigningAdmissionInput): string {
  switch (input.curve) {
    case 'ed25519':
      return ed25519AdmissionAuthorityScopeKey(input.authorityScope);
    case 'ecdsa':
      return `material_activation:${input.materialActivationId}`;
  }
  input satisfies never;
  throw new Error('Unsupported Router A/B normal-signing curve');
}

export function abusePrincipalKey(input: RouterAbNormalSigningAdmissionInput): string {
  return [
    runtimePolicyScopeKey(input.runtimePolicyScope),
    input.walletId,
    admissionAuthorityScope(input),
    input.curve,
  ].join('\x1f');
}

function assertNever(value: never): never {
  throw new Error(`Unexpected Router A/B normal-signing admission branch: ${String(value)}`);
}
