import { useCallback, useEffect, useState } from 'react';

import { FRONTEND_CONFIG } from '@/config';
import {
  canSignDemoNearDelegate,
  initialDemoNearFundingStatus,
  resolveDemoNearFundingCheck,
  type DemoNearAccountFundingStatus,
  type DemoNearFundingIdentity,
} from '../demoNearAccountFundingState';

type NearRpcErrorBody = {
  message?: unknown;
  cause?: {
    name?: unknown;
    info?: {
      error_message?: unknown;
    };
  };
};

type NearRpcResponse = {
  error?: NearRpcErrorBody;
  result?: unknown;
};

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

function nearRpcErrorMessage(error: NearRpcErrorBody | undefined): string {
  const message = normalizeDemoString(error?.message);
  const causeName = normalizeDemoString(error?.cause?.name);
  const causeMessage = normalizeDemoString(error?.cause?.info?.error_message);
  return [message, causeName, causeMessage].filter(Boolean).join(' ');
}

function isMissingNearAccessKey(error: NearRpcErrorBody | undefined): boolean {
  const message = nearRpcErrorMessage(error).toLowerCase();
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

async function readNearRpcJson(response: Response): Promise<NearRpcResponse> {
  const text = await response.text();
  if (!text.trim()) return {};
  const parsed = JSON.parse(text) as unknown;
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
    ? (parsed as NearRpcResponse)
    : {};
}

function isZeroNearAccountBalance(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const amount = normalizeDemoString((value as { amount?: unknown }).amount);
  if (!amount) return false;
  try {
    return BigInt(amount) === 0n;
  } catch {
    return false;
  }
}

async function checkNearAccountBalance(args: {
  nearRpcUrl: string;
  nearAccountId: string;
}): Promise<DemoNearAccountFundingStatus> {
  const nearAccountId = normalizeDemoString(args.nearAccountId);
  const response = await fetch(args.nearRpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'seams-demo-near-account',
      method: 'query',
      params: {
        request_type: 'view_account',
        finality: 'final',
        account_id: nearAccountId,
      },
    }),
  });
  const json = await readNearRpcJson(response);
  if (json.error) {
    if (isMissingNearAccessKey(json.error)) {
      return { kind: 'needs_funding', nearAccountId };
    }
    return {
      kind: 'unknown',
      nearAccountId,
      message: nearRpcErrorMessage(json.error) || `NEAR RPC returned HTTP ${response.status}`,
    };
  }
  if (!response.ok) {
    return {
      kind: 'unknown',
      nearAccountId,
      message: `NEAR RPC returned HTTP ${response.status}`,
    };
  }
  return isZeroNearAccountBalance(json.result)
    ? { kind: 'needs_funding', nearAccountId }
    : { kind: 'ready', nearAccountId };
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

  const response = await fetch(nearRpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'seams-demo-near-access-key',
      method: 'query',
      params: {
        request_type: 'view_access_key',
        finality: 'final',
        account_id: nearAccountId,
        public_key: nearPublicKey,
      },
    }),
  });
  const json = await readNearRpcJson(response);
  if (json.error) {
    if (isMissingNearAccessKey(json.error)) {
      return { kind: 'needs_funding', nearAccountId };
    }
    return {
      kind: 'unknown',
      nearAccountId,
      message: nearRpcErrorMessage(json.error) || `NEAR RPC returned HTTP ${response.status}`,
    };
  }
  if (!response.ok) {
    return {
      kind: 'unknown',
      nearAccountId,
      message: `NEAR RPC returned HTTP ${response.status}`,
    };
  }
  return await checkNearAccountBalance({
    nearRpcUrl,
    nearAccountId,
  });
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
