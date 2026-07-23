import { useCallback, useEffect, useState } from 'react';

import { MinimalNearClient } from '@seams/sdk/advanced';

import { FRONTEND_CONFIG } from '@/config';
import {
  canSignDemoNearDelegate,
  initialDemoNearFundingStatus,
  resolveDemoNearFundingCheck,
  type DemoNearAccountFundingStatus,
  type DemoNearFundingIdentity,
} from '../demoNearAccountFundingState';

type CheckNearAccessKeyArgs = {
  nearRpcUrl: string;
  nearAccountId: string;
  nearPublicKey: string;
};

type UseDemoNearAccountFundingStatusArgs = DemoNearFundingIdentity;

function normalizeDemoString(value: unknown): string {
  return String(value ?? '').trim();
}

function demoErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : normalizeDemoString(error) || 'Unknown error';
}

/* NEAR RPC rejects view_account / view_access_key when the account or key does
   not exist yet — for the demo that means the account still awaits funding
   rather than a genuine failure. MinimalNearClient surfaces the node's phrasing
   on the thrown error, so classify against its message. */
function isMissingNearAccountOrKeyError(error: unknown): boolean {
  const message = demoErrorMessage(error).toLowerCase();
  return (
    message.includes('unknown_account') ||
    message.includes('unknown account') ||
    message.includes('does not exist while viewing') ||
    message.includes('unknown_access_key') ||
    message.includes('unknown access key') ||
    message.includes('access key does not exist') ||
    message.includes("access key doesn't exist") ||
    message.includes('access key not found') ||
    message.includes('no such access key')
  );
}

function isZeroNearAccountBalance(amount: unknown): boolean {
  const normalized = normalizeDemoString(amount);
  if (!normalized) return false;
  try {
    return BigInt(normalized) === 0n;
  } catch {
    return false;
  }
}

async function checkNearAccountBalance(
  nearClient: MinimalNearClient,
  nearAccountId: string,
): Promise<DemoNearAccountFundingStatus> {
  try {
    const account = await nearClient.viewAccount(nearAccountId);
    return isZeroNearAccountBalance(account.amount)
      ? { kind: 'needs_funding', nearAccountId }
      : { kind: 'ready', nearAccountId };
  } catch (error: unknown) {
    if (isMissingNearAccountOrKeyError(error)) {
      return { kind: 'needs_funding', nearAccountId };
    }
    return { kind: 'unknown', nearAccountId, message: demoErrorMessage(error) };
  }
}

async function checkNearAccessKey(
  args: CheckNearAccessKeyArgs,
): Promise<DemoNearAccountFundingStatus> {
  const nearAccountId = normalizeDemoString(args.nearAccountId);
  const nearPublicKey = normalizeDemoString(args.nearPublicKey);
  const nearRpcUrl = normalizeDemoString(args.nearRpcUrl);
  if (!nearRpcUrl) {
    return {
      kind: 'unknown',
      nearAccountId,
      message: 'NEAR RPC URL is unavailable',
    };
  }

  const nearClient = new MinimalNearClient(nearRpcUrl);
  try {
    await nearClient.viewAccessKey(nearAccountId, nearPublicKey);
  } catch (error: unknown) {
    if (isMissingNearAccountOrKeyError(error)) {
      return { kind: 'needs_funding', nearAccountId };
    }
    return { kind: 'unknown', nearAccountId, message: demoErrorMessage(error) };
  }
  return await checkNearAccountBalance(nearClient, nearAccountId);
}

export function useDemoNearAccountFundingStatus(args: UseDemoNearAccountFundingStatusArgs) {
  const { isLoggedIn, nearAccountId, nearPublicKey } = args;
  const [status, setStatus] = useState<DemoNearAccountFundingStatus>(
    initialDemoNearFundingStatus(args),
  );

  const refresh = useCallback(async () => {
    const resolution = resolveDemoNearFundingCheck({
      isLoggedIn,
      nearAccountId,
      nearPublicKey,
    });
    if (resolution.kind === 'skip') {
      setStatus(resolution.status);
      return;
    }
    /* Re-checks keep the current definitive status (ready / needs_funding /
       unknown) for the same account instead of downgrading to 'checking':
       flipping to 'checking' mid-poll flashes the status line away and
       momentarily disables the signing buttons — visible jank every 5s while
       an account awaits funding. A fresh account still resets to 'checking'. */
    setStatus((prev) => {
      const prevIsSameAccount =
        'nearAccountId' in prev && prev.nearAccountId === resolution.nearAccountId;
      const prevIsDefinitive =
        prev.kind === 'ready' || prev.kind === 'needs_funding' || prev.kind === 'unknown';
      return prevIsSameAccount && prevIsDefinitive
        ? prev
        : { kind: 'checking', nearAccountId: resolution.nearAccountId };
    });
    try {
      const next = await checkNearAccessKey({
        nearRpcUrl: FRONTEND_CONFIG.nearRpcUrl,
        nearAccountId: resolution.nearAccountId,
        nearPublicKey: resolution.nearPublicKey,
      });
      setStatus(next);
    } catch (error: unknown) {
      setStatus({
        kind: 'unknown',
        nearAccountId: resolution.nearAccountId,
        message: demoErrorMessage(error),
      });
    }
  }, [isLoggedIn, nearAccountId, nearPublicKey]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (status.kind !== 'needs_funding') return undefined;
    const id = window.setInterval(() => {
      if (document.visibilityState === 'hidden') return;
      void refresh();
    }, 5000);
    return () => window.clearInterval(id);
  }, [refresh, status.kind]);

  return {
    status,
    refresh,
    canSignNear: canSignDemoNearDelegate(status),
  };
}
