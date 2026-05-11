export type SigningBudgetStatusActive = {
  kind: 'active';
  ok: true;
  walletSigningSessionId: string;
  thresholdSessionId: string;
  status: 'active';
  remainingUses: number;
  expiresAtMs: number;
};

export type SigningBudgetStatusRejected = {
  kind: 'rejected';
  ok: false;
  code: string;
  message: string;
};

export type SigningBudgetStatusResult =
  | SigningBudgetStatusActive
  | SigningBudgetStatusRejected;

export function installBrowserSigningBudgetStatusReader(): () => void {
  return () => {
    const normalizeText = (value: unknown): string => String(value || '').trim();
    const normalizeNonNegativeInt = (value: unknown): number | null => {
      const parsed = Number(value);
      if (!Number.isFinite(parsed) || parsed < 0) return null;
      return Math.floor(parsed);
    };

    (globalThis as any).__w3aReadSigningBudgetStatus = async (input: {
      relayerUrl: string;
      session: {
        jwt: string;
        thresholdSessionId: string;
        walletSigningSessionId: string;
      };
    }): Promise<SigningBudgetStatusResult> => {
      const relayerUrl = normalizeText(input.relayerUrl);
      const jwt = normalizeText(input.session.jwt);
      const thresholdSessionId = normalizeText(input.session.thresholdSessionId);
      const walletSigningSessionId = normalizeText(input.session.walletSigningSessionId);
      if (!relayerUrl || !jwt || !thresholdSessionId || !walletSigningSessionId) {
        return {
          kind: 'rejected',
          ok: false,
          code: 'missing_budget_status_identity',
          message: 'Budget status requires relayer URL, JWT, wallet session, and threshold session',
        };
      }

      const response = await fetch(`${relayerUrl}/session/signing-budget/status`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({
          walletSigningSessionId,
          thresholdSessionId,
        }),
      });
      const json = await response.json().catch(() => null);
      const code = normalizeText(json?.code) || (response.ok ? 'invalid_response' : 'http_error');
      const message =
        normalizeText(json?.message) ||
        (response.ok ? 'Budget status response was malformed' : `HTTP ${response.status}`);
      if (!response.ok || json?.ok !== true || json?.status !== 'active') {
        return {
          kind: 'rejected',
          ok: false,
          code,
          message,
        };
      }

      const remainingUses = normalizeNonNegativeInt(json.remainingUses);
      const expiresAtMs = normalizeNonNegativeInt(json.expiresAtMs);
      const responseWalletSigningSessionId = normalizeText(json.walletSigningSessionId);
      const responseThresholdSessionId = normalizeText(json.thresholdSessionId);
      if (
        remainingUses === null ||
        expiresAtMs === null ||
        responseWalletSigningSessionId !== walletSigningSessionId ||
        responseThresholdSessionId !== thresholdSessionId
      ) {
        return {
          kind: 'rejected',
          ok: false,
          code: 'malformed_budget_status',
          message: 'Budget status response did not match the requested wallet session',
        };
      }

      return {
        kind: 'active',
        ok: true,
        walletSigningSessionId,
        thresholdSessionId,
        status: 'active',
        remainingUses,
        expiresAtMs,
      };
    };
  };
}
