import type { WalletId } from '@shared/utils/domainIds';
import {
  parseWalletSessionOperationCredentialV1,
  type ActiveWalletSessionV1,
  type WalletSessionOperationCredentialV1,
} from '@shared/device-linking';
import { activeWalletSessionV1RecordsEqual } from '@shared/device-linking/activeWalletSession';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import type { ResolveSelectedWalletAuthorityResultV1 } from '@/core/indexedDB/seamsWalletDB/repositories';
import type { WalletSessionAuthorizationExactActiveReadResult } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type {
  WalletIframeExactSessionReadDependencies,
  WalletIframeExactSessionStatus,
} from './exactSessionState';

type ResolvedWalletAuthority = Extract<
  ResolveSelectedWalletAuthorityResultV1,
  { readonly kind: 'resolved' }
>;

export type WalletIframeExactSessionReconciliationDependencies = Pick<
  WalletIframeExactSessionReadDependencies,
  'resolveSelectedWalletAuthority' | 'readExactActiveForWallet' | 'readStatus'
> & {
  readonly listWalletAuthMethodsV2ForWallet: (
    walletId: string,
  ) => Promise<readonly WalletAuthMethodRecordV2[]>;
  readonly resolveWalletAuthorityForMethod: (
    walletId: string,
    walletAuthMethodId: string,
  ) => Promise<ResolveSelectedWalletAuthorityResultV1>;
  readonly writeExactWithOperationCredential: (input: {
    readonly record: ActiveWalletSessionV1;
    readonly operationCredential: WalletSessionOperationCredentialV1;
  }) => Promise<ActiveWalletSessionV1>;
};

export type WalletIframeExactSessionReconciliationResult =
  | { readonly kind: 'reconciled'; readonly updatedSessionCount: number }
  | { readonly kind: 'skipped' }
  | { readonly kind: 'failed'; readonly reason: 'invalid' | 'unavailable' };

type ReconciliationContext = {
  readonly kind: 'context';
  readonly walletId: WalletId;
  readonly selected: ResolvedWalletAuthority;
};

type SessionReconciliationResult =
  | { readonly kind: 'reconciled'; readonly updated: boolean }
  | { readonly kind: 'skipped' }
  | { readonly kind: 'failed'; readonly reason: 'invalid' | 'unavailable' };

/**
 * Reconciles every locally stored exact session for the selected authority.
 * Each row is authenticated with its own operation credential before the
 * authoritative projection can replace its stale local material.
 */
export async function reconcileWalletIframeExactSessions(
  input: { readonly walletId: WalletId },
  dependencies: WalletIframeExactSessionReconciliationDependencies,
): Promise<WalletIframeExactSessionReconciliationResult> {
  let selected: ResolveSelectedWalletAuthorityResultV1;
  try {
    selected = await dependencies.resolveSelectedWalletAuthority(String(input.walletId));
  } catch {
    return { kind: 'failed', reason: 'unavailable' };
  }
  const context = reconciliationContext(input.walletId, selected);
  if (context.kind !== 'context') return context;

  let methods: readonly WalletAuthMethodRecordV2[];
  try {
    methods = await dependencies.listWalletAuthMethodsV2ForWallet(String(input.walletId));
  } catch {
    return { kind: 'failed', reason: 'unavailable' };
  }

  const seenMethodIds = new Set<string>();
  let updatedSessionCount = 0;
  for (const method of methods) {
    const methodResult = await reconcileMethod({ context, method, seenMethodIds }, dependencies);
    if (methodResult.kind === 'failed') return methodResult;
    if (methodResult.kind === 'reconciled' && methodResult.updated) {
      updatedSessionCount += 1;
    }
  }
  return { kind: 'reconciled', updatedSessionCount };
}

function reconciliationContext(
  walletId: WalletId,
  selected: ResolveSelectedWalletAuthorityResultV1,
): WalletIframeExactSessionReconciliationResult | ReconciliationContext {
  switch (selected.kind) {
    case 'missing_selection':
      return { kind: 'skipped' };
    case 'missing_auth_method':
    case 'missing_authority':
    case 'integrity_error':
      return { kind: 'failed', reason: 'invalid' };
    case 'resolved':
      break;
  }
  if (
    selected.selection.walletId !== walletId ||
    selected.authMethod.walletId !== walletId ||
    selected.authority.walletId !== walletId ||
    selected.selection.walletAuthMethodId !== selected.authMethod.walletAuthMethodId ||
    selected.authMethod.walletAuthorityId !== selected.authority.authorityId
  ) {
    return { kind: 'failed', reason: 'invalid' };
  }
  if (selected.selection.lockState === 'locked') return { kind: 'skipped' };
  if (selected.authMethod.status !== 'active' || selected.authority.state !== 'active') {
    return { kind: 'failed', reason: 'invalid' };
  }
  return { kind: 'context', walletId, selected };
}

async function reconcileMethod(
  input: {
    readonly context: ReconciliationContext;
    readonly method: WalletAuthMethodRecordV2;
    readonly seenMethodIds: Set<string>;
  },
  dependencies: WalletIframeExactSessionReconciliationDependencies,
): Promise<SessionReconciliationResult> {
  const { context, method, seenMethodIds } = input;
  const methodId = String(method.walletAuthMethodId);
  if (seenMethodIds.has(methodId)) return { kind: 'failed', reason: 'invalid' };
  seenMethodIds.add(methodId);
  if (method.walletId !== context.walletId) return { kind: 'failed', reason: 'invalid' };
  if (method.walletAuthorityId !== context.selected.authority.authorityId) {
    return { kind: 'skipped' };
  }
  if (method.status !== 'active') return { kind: 'skipped' };

  let resolved: ResolveSelectedWalletAuthorityResultV1;
  try {
    resolved = await dependencies.resolveWalletAuthorityForMethod(
      String(context.walletId),
      methodId,
    );
  } catch {
    return { kind: 'failed', reason: 'unavailable' };
  }
  if (resolved.kind !== 'resolved') return { kind: 'failed', reason: 'invalid' };
  if (!resolvedMethodMatchesContext(resolved, context, method)) {
    return { kind: 'failed', reason: 'invalid' };
  }

  let authorizationRead: WalletSessionAuthorizationExactActiveReadResult;
  try {
    authorizationRead = await dependencies.readExactActiveForWallet({
      walletId: context.walletId,
      authorityId: resolved.authority.authorityId,
      authMethodId: resolved.authMethod.walletAuthMethodId,
    });
  } catch {
    return { kind: 'failed', reason: 'unavailable' };
  }
  switch (authorizationRead.kind) {
    case 'missing':
      return { kind: 'skipped' };
    case 'upgrade_required':
    case 'corrupt':
      return { kind: 'failed', reason: 'invalid' };
    case 'persistence_unavailable':
      return { kind: 'failed', reason: 'unavailable' };
    case 'found':
      break;
  }
  if (
    !localSessionMatchesMethod(
      authorizationRead.record,
      authorizationRead.operationCredential,
      resolved,
    )
  ) {
    return { kind: 'failed', reason: 'invalid' };
  }

  let status: WalletIframeExactSessionStatus;
  try {
    status = await dependencies.readStatus({
      authorization: authorizationRead.record,
      operationCredential: authorizationRead.operationCredential,
    });
  } catch {
    return { kind: 'failed', reason: 'unavailable' };
  }
  const observedAuthorization = observedStatusAuthorization(
    status,
    authorizationRead.record,
    authorizationRead.operationCredential,
  );
  if (observedAuthorization.kind === 'failed') return observedAuthorization;
  if (observedAuthorization.kind === 'skipped') return observedAuthorization;
  if (
    !activeWalletSessionV1RecordsEqual(
      observedAuthorization.authorization,
      authorizationRead.record,
    )
  ) {
    try {
      await dependencies.writeExactWithOperationCredential({
        record: observedAuthorization.authorization,
        operationCredential: authorizationRead.operationCredential,
      });
    } catch {
      return { kind: 'failed', reason: 'unavailable' };
    }
    return { kind: 'reconciled', updated: true };
  }
  return { kind: 'reconciled', updated: false };
}

function resolvedMethodMatchesContext(
  resolved: ResolvedWalletAuthority,
  context: ReconciliationContext,
  method: WalletAuthMethodRecordV2,
): boolean {
  return (
    resolved.selection.walletId === context.walletId &&
    resolved.authMethod.walletAuthMethodId === method.walletAuthMethodId &&
    resolved.authMethod.walletId === context.walletId &&
    resolved.authMethod.walletAuthorityId === context.selected.authority.authorityId &&
    resolved.authMethod.status === 'active' &&
    resolved.authority.authorityId === context.selected.authority.authorityId &&
    resolved.authority.walletId === context.walletId &&
    resolved.authority.state === 'active' &&
    resolved.authority.authorityDigestB64u === context.selected.authority.authorityDigestB64u &&
    resolved.authority.revocationEpoch === context.selected.authority.revocationEpoch
  );
}

function localSessionMatchesMethod(
  authorization: ActiveWalletSessionV1,
  operationCredential: WalletSessionOperationCredentialV1,
  resolved: ResolvedWalletAuthority,
): boolean {
  try {
    parseWalletSessionOperationCredentialV1(operationCredential);
    return (
      authorization.walletId === resolved.authority.walletId &&
      authorization.authorityId === resolved.authority.authorityId &&
      authorization.authMethodId === resolved.authMethod.walletAuthMethodId
    );
  } catch {
    return false;
  }
}

type ObservedStatusAuthorizationResult =
  | { readonly kind: 'reconciled'; readonly authorization: ActiveWalletSessionV1 }
  | { readonly kind: 'skipped' }
  | { readonly kind: 'failed'; readonly reason: 'invalid' };

function observedStatusAuthorization(
  status: WalletIframeExactSessionStatus,
  localAuthorization: ActiveWalletSessionV1,
  operationCredential: WalletSessionOperationCredentialV1,
): ObservedStatusAuthorizationResult {
  if (
    status.walletSessionId !== operationCredential.walletSessionId ||
    status.quotaId !== localAuthorization.quotaId
  ) {
    return { kind: 'failed', reason: 'invalid' };
  }
  switch (status.status) {
    case 'missing':
      return { kind: 'skipped' };
    case 'invalid':
      return { kind: 'failed', reason: 'invalid' };
    case 'active':
      if (status.remainingUses <= 0 || status.quotaLifecycle !== 'active') {
        return { kind: 'failed', reason: 'invalid' };
      }
      break;
    case 'exhausted':
      if (status.remainingUses !== 0 || status.quotaLifecycle !== 'exhausted') {
        return { kind: 'failed', reason: 'invalid' };
      }
      break;
    case 'expired':
    case 'superseded':
    case 'authority_unavailable':
    case 'method_unavailable':
    case 'capability_unavailable':
      break;
  }
  if (
    status.authorization.walletId !== localAuthorization.walletId ||
    status.authorization.authorityId !== localAuthorization.authorityId ||
    status.authorization.authMethodId !== localAuthorization.authMethodId ||
    status.authorization.authorizationId !== localAuthorization.authorizationId ||
    status.authorization.quotaId !== localAuthorization.quotaId ||
    status.authorization.issuedAtMs !== localAuthorization.issuedAtMs ||
    status.authorization.expiresAtMs !== localAuthorization.expiresAtMs ||
    status.expiresAtMs !== status.authorization.expiresAtMs
  ) {
    return { kind: 'failed', reason: 'invalid' };
  }
  return { kind: 'reconciled', authorization: status.authorization };
}
