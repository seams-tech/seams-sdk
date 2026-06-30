import { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG } from '@/config';
import { NEAR_EXPLORER_BASE_URL } from '@/shared/types';

export type DemoNearAccountFundingStatus =
  | {
      kind: 'not_available';
    }
  | {
      kind: 'checking';
      nearAccountId: string;
    }
  | {
      kind: 'ready';
      nearAccountId: string;
    }
  | {
      kind: 'needs_funding';
      nearAccountId: string;
    }
  | {
      kind: 'unknown';
      nearAccountId: string;
      message: string;
    };

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

type UseDemoNearAccountFundingStatusArgs = {
  isLoggedIn: boolean;
  nearAccountId?: string | null;
  nearPublicKey?: string | null;
};

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

async function checkNearAccessKey(args: CheckNearAccessKeyArgs): Promise<DemoNearAccountFundingStatus> {
  const nearAccountId = normalizeDemoString(args.nearAccountId);
  const nearPublicKey = normalizeDemoString(args.nearPublicKey);
  const nearRpcUrl = normalizeDemoString(args.nearRpcUrl);
  if (!nearAccountId || !nearPublicKey || !nearRpcUrl) return { kind: 'not_available' };

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
  return { kind: 'ready', nearAccountId };
}

async function copyTextToClipboard(text: string): Promise<void> {
  const value = normalizeDemoString(text);
  if (!value) return;
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const textarea = document.createElement('textarea');
  textarea.value = value;
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand('copy');
  document.body.removeChild(textarea);
}

function openNearAccountFundingPage(nearAccountId: string): void {
  const accountUrl = `${NEAR_EXPLORER_BASE_URL.replace(/\/$/, '')}/address/${encodeURIComponent(
    nearAccountId,
  )}`;
  window.open(accountUrl, '_blank', 'noopener,noreferrer');
}

export function useDemoNearAccountFundingStatus(args: UseDemoNearAccountFundingStatusArgs) {
  const { isLoggedIn, nearAccountId, nearPublicKey } = args;
  const [status, setStatus] = useState<DemoNearAccountFundingStatus>({ kind: 'not_available' });

  const refresh = useCallback(async () => {
    const accountId = normalizeDemoString(nearAccountId);
    const publicKey = normalizeDemoString(nearPublicKey);
    if (!isLoggedIn || !accountId || !publicKey) {
      setStatus({ kind: 'not_available' });
      return;
    }
    setStatus({ kind: 'checking', nearAccountId: accountId });
    try {
      const next = await checkNearAccessKey({
        nearRpcUrl: FRONTEND_CONFIG.nearRpcUrl,
        nearAccountId: accountId,
        nearPublicKey: publicKey,
      });
      setStatus(next);
    } catch (error: unknown) {
      setStatus({
        kind: 'unknown',
        nearAccountId: accountId,
        message: demoErrorMessage(error),
      });
    }
  }, [isLoggedIn, nearAccountId, nearPublicKey]);

  const openFunding = useCallback(async () => {
    const accountId = normalizeDemoString(nearAccountId);
    if (!accountId) return;
    await copyTextToClipboard(accountId)
      .then(() => toast.success('NEAR account copied'))
      .catch(() => toast.info('Open the account page to fund this NEAR account'));
    openNearAccountFundingPage(accountId);
  }, [nearAccountId]);

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
    openFunding,
    canSignNear: status.kind === 'ready',
  };
}
