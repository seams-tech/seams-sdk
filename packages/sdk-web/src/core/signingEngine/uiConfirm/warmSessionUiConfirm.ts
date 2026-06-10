import type { WarmSessionStatusBatchResult } from '../../types/secure-confirm-worker';
import type {
  UiConfirmRuntimeBridgePort,
  ClearVolatileWarmSessionMaterialCommand,
  WarmSessionClaimResult,
  WarmSessionStatusResult,
} from './types';

type WarmSessionStatusOnlyUiConfirmPort = UiConfirmRuntimeBridgePort & {
  readWarmSessionStatusOnly?: (args: { sessionId: string }) => Promise<WarmSessionStatusResult>;
  readWarmSessionStatusesOnly?: (args: {
    sessionIds: string[];
  }) => Promise<WarmSessionStatusBatchResult>;
};

export type WarmSessionStatusOnlyReaderPort = {
  getWarmSessionStatus: (args: { sessionId: string }) => Promise<WarmSessionStatusResult>;
  getWarmSessionStatuses?: (args: {
    sessionIds: string[];
  }) => Promise<WarmSessionStatusBatchResult>;
  claimWarmSessionMaterial?: never;
  clearVolatileWarmSessionMaterial?: never;
  requestUserConfirmation?: never;
  prompt?: never;
  webauthnPrompt?: never;
  touchIdPrompt?: never;
  passkeyCredentialCollector?: never;
  freshBootstrap?: never;
  bootstrapEcdsaSession?: never;
};

type WarmSessionClaimArgs = Parameters<
  UiConfirmRuntimeBridgePort['claimWarmSessionMaterial']
>[0];

type SecondaryWarmSessionPort = {
  readWarmSessionStatusOnly: (sessionId: string) => Promise<WarmSessionStatusResult>;
  claimWarmSessionMaterial: (args: WarmSessionClaimArgs) => Promise<WarmSessionClaimResult>;
  clearVolatileWarmSessionMaterial: (
    command: ClearVolatileWarmSessionMaterialCommand,
  ) => Promise<void>;
};

type SecondaryWarmSessionStatusOnlyPort = {
  readWarmSessionStatusOnly: (sessionId: string) => Promise<WarmSessionStatusResult>;
};

function shouldReadPrimaryWarmSessionStatus(result: WarmSessionStatusResult): boolean {
  return !result.ok && (result.code === 'not_found' || result.code === 'worker_error');
}

function shouldClaimPrimaryWarmSession(result: WarmSessionClaimResult): boolean {
  return !result.ok && (result.code === 'not_found' || result.code === 'worker_error');
}

export function createWarmSessionAwareUiConfirm(args: {
  base: UiConfirmRuntimeBridgePort;
  secondary: SecondaryWarmSessionPort;
}): UiConfirmRuntimeBridgePort {
  const { base, secondary } = args;

  const getWarmSessionStatus = async (statusArgs: {
    sessionId: string;
  }): Promise<WarmSessionStatusResult> => {
    const secondaryStatus = await secondary.readWarmSessionStatusOnly(statusArgs.sessionId);
    if (!shouldReadPrimaryWarmSessionStatus(secondaryStatus)) return secondaryStatus;
    return await base.getWarmSessionStatus(statusArgs);
  };

  const getWarmSessionStatuses = async (statusArgs: {
    sessionIds: string[];
  }): Promise<WarmSessionStatusBatchResult> => {
    const secondaryResults = await Promise.all(
      statusArgs.sessionIds.map(async (sessionId) => ({
        sessionId,
        result: await secondary.readWarmSessionStatusOnly(sessionId),
      })),
    );
    const unresolvedSessionIds = secondaryResults
      .filter((entry) => shouldReadPrimaryWarmSessionStatus(entry.result))
      .map((entry) => entry.sessionId);
    const primary =
      unresolvedSessionIds.length === 0
        ? { results: [] }
        : typeof base.getWarmSessionStatuses === 'function'
          ? await base.getWarmSessionStatuses({ sessionIds: unresolvedSessionIds })
          : {
              results: await Promise.all(
                unresolvedSessionIds.map(async (sessionId) => ({
                  sessionId,
                  result: await base.getWarmSessionStatus({ sessionId }),
                })),
              ),
            };
    const primaryBySessionId = new Map(primary.results.map((entry) => [entry.sessionId, entry]));
    return {
      results: secondaryResults.map((entry) =>
        shouldReadPrimaryWarmSessionStatus(entry.result)
          ? primaryBySessionId.get(entry.sessionId) || entry
          : entry,
      ),
    };
  };

  const claimWarmSessionMaterial = async (
    claimArgs: WarmSessionClaimArgs,
  ): Promise<WarmSessionClaimResult> => {
    const secondaryClaim = await secondary.claimWarmSessionMaterial(claimArgs);
    if (!shouldClaimPrimaryWarmSession(secondaryClaim)) return secondaryClaim;
    return await base.claimWarmSessionMaterial(claimArgs);
  };

  const clearVolatileWarmSessionMaterial = async (
    command: ClearVolatileWarmSessionMaterialCommand,
  ): Promise<void> => {
    await Promise.all([
      base.clearVolatileWarmSessionMaterial(command).catch(() => undefined),
      secondary.clearVolatileWarmSessionMaterial(command).catch(() => undefined),
    ]);
  };

  return new Proxy(base, {
    get: (target, prop, receiver) => {
      if (prop === 'getWarmSessionStatus') return getWarmSessionStatus;
      if (prop === 'getWarmSessionStatuses') return getWarmSessionStatuses;
      if (prop === 'claimWarmSessionMaterial') return claimWarmSessionMaterial;
      if (prop === 'clearVolatileWarmSessionMaterial') return clearVolatileWarmSessionMaterial;
      const value = Reflect.get(target, prop, receiver);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  }) as UiConfirmRuntimeBridgePort;
}

export function createWarmSessionStatusOnlyUiConfirm(args: {
  base: UiConfirmRuntimeBridgePort;
  secondary: SecondaryWarmSessionStatusOnlyPort;
}): WarmSessionStatusOnlyReaderPort {
  const { base, secondary } = args;
  const primary = base as WarmSessionStatusOnlyUiConfirmPort;
  const readPrimaryWarmSessionStatusOnly = async (statusArgs: {
    sessionId: string;
  }): Promise<WarmSessionStatusResult> => {
    if (typeof primary.readWarmSessionStatusOnly !== 'function') {
      return {
        ok: false,
        code: 'status_reader_unavailable',
        message: 'Warm-session status-only reader is unavailable',
      };
    }
    return await primary.readWarmSessionStatusOnly({ sessionId: statusArgs.sessionId });
  };
  const readCombinedWarmSessionStatusOnly = async (statusArgs: {
    sessionId: string;
  }): Promise<WarmSessionStatusResult> => {
    const secondaryStatus = await secondary.readWarmSessionStatusOnly(statusArgs.sessionId);
    if (!shouldReadPrimaryWarmSessionStatus(secondaryStatus)) return secondaryStatus;
    return await readPrimaryWarmSessionStatusOnly(statusArgs);
  };
  const readCombinedWarmSessionStatusesOnly = async (statusArgs: {
    sessionIds: string[];
  }): Promise<WarmSessionStatusBatchResult> => {
    const normalizedSessionIds = Array.from(
      new Set(
        (Array.isArray(statusArgs.sessionIds) ? statusArgs.sessionIds : [])
          .map((sessionId) => String(sessionId || '').trim())
          .filter(Boolean),
      ),
    );
    const secondaryResults = await Promise.all(
      normalizedSessionIds.map(async (sessionId) => ({
        sessionId,
        result: await secondary.readWarmSessionStatusOnly(sessionId),
      })),
    );
    const unresolvedSessionIds = secondaryResults
      .filter((entry) => shouldReadPrimaryWarmSessionStatus(entry.result))
      .map((entry) => entry.sessionId);
    const primaryResults =
      unresolvedSessionIds.length === 0
        ? { results: [] }
        : typeof primary.readWarmSessionStatusesOnly === 'function'
          ? await primary.readWarmSessionStatusesOnly({ sessionIds: unresolvedSessionIds })
          : {
              results: await Promise.all(
                unresolvedSessionIds.map(async (sessionId) => ({
                  sessionId,
                  result: await readPrimaryWarmSessionStatusOnly({ sessionId }),
                })),
              ),
            };
    const primaryBySessionId = new Map(
      primaryResults.results.map((entry) => [entry.sessionId, entry.result]),
    );
    return {
      results: secondaryResults.map((entry) =>
        shouldReadPrimaryWarmSessionStatus(entry.result)
          ? {
              sessionId: entry.sessionId,
              result: primaryBySessionId.get(entry.sessionId) || entry.result,
            }
          : entry,
      ),
    };
  };

  return new Proxy(base, {
    get: (target, prop, receiver) => {
      if (prop === 'getWarmSessionStatus') return readCombinedWarmSessionStatusOnly;
      if (prop === 'getWarmSessionStatuses') return readCombinedWarmSessionStatusesOnly;
      const value = Reflect.get(target, prop, receiver);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  }) as unknown as WarmSessionStatusOnlyReaderPort;
}
