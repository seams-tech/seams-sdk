import type { WarmSessionStatusBatchResult } from '../../types/secure-confirm-worker';
import type {
  ClearVolatileWarmSessionMaterialCommand,
  PasskeyMpcSessionPort,
  WarmSessionStatusBatchReader,
  WarmSessionStatusReader,
  WarmSessionStatusResult,
} from './uiConfirm.types';

export type WarmSessionStatusOnlyReaderPort = WarmSessionStatusReader & {
  getWarmSessionStatuses?: WarmSessionStatusBatchReader['getWarmSessionStatuses'];
};

type SecondaryWarmSessionPort = {
  readWarmSessionStatusOnly: (thresholdSessionId: string) => Promise<WarmSessionStatusResult>;
  clearVolatileWarmSessionMaterial: (
    command: ClearVolatileWarmSessionMaterialCommand,
  ) => Promise<void>;
};

type SecondaryWarmSessionStatusOnlyPort = {
  readWarmSessionStatusOnly: (thresholdSessionId: string) => Promise<WarmSessionStatusResult>;
};

function shouldReadPrimaryWarmSessionStatus(result: WarmSessionStatusResult): boolean {
  return !result.ok && (result.code === 'not_found' || result.code === 'worker_error');
}

export function createWarmSessionAwarePasskeyMpcSession(args: {
  base: PasskeyMpcSessionPort;
  secondary: SecondaryWarmSessionPort;
}): PasskeyMpcSessionPort {
  const { base, secondary } = args;

  const getWarmSessionStatus = async (statusArgs: {
    thresholdSessionId: string;
  }): Promise<WarmSessionStatusResult> => {
    const secondaryStatus = await secondary.readWarmSessionStatusOnly(statusArgs.thresholdSessionId);
    if (!shouldReadPrimaryWarmSessionStatus(secondaryStatus)) return secondaryStatus;
    return await base.getWarmSessionStatus(statusArgs);
  };

  const getWarmSessionStatuses = async (statusArgs: {
    thresholdSessionIds: string[];
  }): Promise<WarmSessionStatusBatchResult> => {
    const secondaryResults = await Promise.all(
      statusArgs.thresholdSessionIds.map(async (thresholdSessionId) => ({
        thresholdSessionId,
        result: await secondary.readWarmSessionStatusOnly(thresholdSessionId),
      })),
    );
    const unresolvedSessionIds = secondaryResults
      .filter((entry) => shouldReadPrimaryWarmSessionStatus(entry.result))
      .map((entry) => entry.thresholdSessionId);
    const primary =
      unresolvedSessionIds.length === 0
        ? { results: [] }
        : typeof base.getWarmSessionStatuses === 'function'
          ? await base.getWarmSessionStatuses({ thresholdSessionIds: unresolvedSessionIds })
          : {
              results: await Promise.all(
                unresolvedSessionIds.map(async (thresholdSessionId) => ({
                  thresholdSessionId,
                  result: await base.getWarmSessionStatus({ thresholdSessionId }),
                })),
              ),
            };
    const primaryByThresholdSessionId = new Map(
      primary.results.map((entry) => [entry.thresholdSessionId, entry]),
    );
    return {
      results: secondaryResults.map((entry) =>
        shouldReadPrimaryWarmSessionStatus(entry.result)
          ? primaryByThresholdSessionId.get(entry.thresholdSessionId) || entry
          : entry,
      ),
    };
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
      if (prop === 'clearVolatileWarmSessionMaterial') return clearVolatileWarmSessionMaterial;
      const value = Reflect.get(target, prop, receiver);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  }) as PasskeyMpcSessionPort;
}

export function createWarmSessionStatusOnlyUiConfirm(args: {
  base: WarmSessionStatusReader & WarmSessionStatusBatchReader;
  secondary: SecondaryWarmSessionStatusOnlyPort;
}): WarmSessionStatusOnlyReaderPort {
  const { base, secondary } = args;
  const readCombinedWarmSessionStatusOnly = async (statusArgs: {
    thresholdSessionId: string;
  }): Promise<WarmSessionStatusResult> => {
    const secondaryStatus = await secondary.readWarmSessionStatusOnly(statusArgs.thresholdSessionId);
    if (!shouldReadPrimaryWarmSessionStatus(secondaryStatus)) return secondaryStatus;
    return await base.getWarmSessionStatus(statusArgs);
  };
  const readCombinedWarmSessionStatusesOnly = async (statusArgs: {
    thresholdSessionIds: string[];
  }): Promise<WarmSessionStatusBatchResult> => {
    const normalizedThresholdSessionIds = Array.from(
      new Set(
        (Array.isArray(statusArgs.thresholdSessionIds) ? statusArgs.thresholdSessionIds : [])
          .map((thresholdSessionId) => String(thresholdSessionId || '').trim())
          .filter(Boolean),
      ),
    );
    const secondaryResults = await Promise.all(
      normalizedThresholdSessionIds.map(async (thresholdSessionId) => ({
        thresholdSessionId,
        result: await secondary.readWarmSessionStatusOnly(thresholdSessionId),
      })),
    );
    const unresolvedSessionIds = secondaryResults
      .filter((entry) => shouldReadPrimaryWarmSessionStatus(entry.result))
      .map((entry) => entry.thresholdSessionId);
    const primaryResults =
      unresolvedSessionIds.length === 0
        ? { results: [] }
        : await base.getWarmSessionStatuses({ thresholdSessionIds: unresolvedSessionIds });
    const primaryByThresholdSessionId = new Map(
      primaryResults.results.map((entry) => [entry.thresholdSessionId, entry.result]),
    );
    return {
      results: secondaryResults.map((entry) =>
        shouldReadPrimaryWarmSessionStatus(entry.result)
          ? {
              thresholdSessionId: entry.thresholdSessionId,
              result: primaryByThresholdSessionId.get(entry.thresholdSessionId) || entry.result,
            }
          : entry,
      ),
    };
  };

  return {
    getWarmSessionStatus: readCombinedWarmSessionStatusOnly,
    getWarmSessionStatuses: readCombinedWarmSessionStatusesOnly,
  };
}
