import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ActiveSDKFlowKind, SDKFlowRuntime, SDKFlowState } from '../types';

type FlowKind = ActiveSDKFlowKind;
type SDKFlowCompletionStatus = 'success' | 'error';

const MAX_EVENT_LINES = 6;

type Deferred<T> = {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (error: Error) => void;
  settled: boolean;
};

type StartWaiter = {
  kind: FlowKind;
  seqAfter: number;
  resolve: (seq: number) => void;
  timeoutId: ReturnType<typeof setTimeout>;
};

function buildIdleSdkFlowState(): SDKFlowState {
  return {
    seq: 0,
    kind: null,
    status: 'idle',
    eventsText: '',
  };
}

function buildStartedSdkFlowState(input: {
  seq: number;
  kind: FlowKind;
  accountId?: string;
}): SDKFlowState {
  return {
    seq: input.seq,
    kind: input.kind,
    status: 'in-progress',
    eventsText: '',
    ...(input.accountId ? { accountId: input.accountId } : {}),
  };
}

function buildCompletedSdkFlowState(input: {
  current: SDKFlowState;
  seq: number;
  kind: FlowKind;
  status: SDKFlowCompletionStatus;
  error?: string;
}): SDKFlowState {
  const currentAccountId = 'accountId' in input.current ? input.current.accountId : undefined;
  const base =
    input.current.seq === input.seq && input.current.kind === input.kind
      ? {
          seq: input.current.seq,
          kind: input.current.kind,
          eventsText: input.current.eventsText,
          ...(currentAccountId ? { accountId: currentAccountId } : {}),
        }
      : {
          seq: input.seq,
          kind: input.kind,
          eventsText: '',
        };

  switch (input.status) {
    case 'success':
      return {
        ...base,
        status: 'success',
      };
    case 'error':
      return {
        ...base,
        status: 'error',
        error: input.error || 'Operation failed',
      };
    default:
      return assertNeverSdkFlowCompletionStatus(input.status);
  }
}

function assertNeverSdkFlowCompletionStatus(value: never): never {
  throw new Error(`Unhandled SDK flow completion status: ${String(value)}`);
}

const createDeferred = <T>(): Deferred<T> => {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject, settled: false };
};

const withTimeout = async <T>(promise: Promise<T>, timeoutMs: number): Promise<T> => {
  if (timeoutMs <= 0) return await promise;
  return await new Promise<T>((resolve, reject) => {
    const timeoutId = setTimeout(() => reject(new Error('Operation timed out')), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timeoutId);
        resolve(value);
      },
      (error) => {
        clearTimeout(timeoutId);
        reject(error);
      },
    );
  });
};

export function useSDKFlowRuntime(): {
  sdkFlow: SDKFlowRuntime;
  beginSdkFlow: (kind: FlowKind, accountId?: string) => number;
  appendSdkEventMessage: (seq: number, message: string) => void;
  endSdkFlow: (kind: FlowKind, seq: number, status: SDKFlowCompletionStatus, error?: string) => void;
} {
  const sdkFlowSeqRef = useRef(0);
  const sdkFlowStartWaitersRef = useRef<Set<StartWaiter>>(new Set());
  const sdkFlowCompletionDeferredsRef = useRef<Map<number, Deferred<SDKFlowState>>>(new Map());

  const [sdkFlowState, setSdkFlowState] = useState<SDKFlowState>(buildIdleSdkFlowState);

  const sdkFlowRef = useRef<SDKFlowState>(sdkFlowState);
  useEffect(() => {
    sdkFlowRef.current = sdkFlowState;
    sdkFlowSeqRef.current = sdkFlowState.seq;
  }, [sdkFlowState]);

  const beginSdkFlow = useCallback((kind: FlowKind, accountId?: string): number => {
    const prev = sdkFlowRef.current;
    const prevDeferred = sdkFlowCompletionDeferredsRef.current.get(prev.seq);
    if (prevDeferred && !prevDeferred.settled && prev.status === 'in-progress') {
      prevDeferred.settled = true;
      prevDeferred.reject(new Error('SDK flow superseded'));
      sdkFlowCompletionDeferredsRef.current.delete(prev.seq);
    }

    const seq = (sdkFlowSeqRef.current += 1);
    const next = buildStartedSdkFlowState({
      seq,
      kind,
      ...(accountId ? { accountId } : {}),
    });

    sdkFlowRef.current = next;
    setSdkFlowState(next);

    sdkFlowCompletionDeferredsRef.current.set(seq, createDeferred<SDKFlowState>());

    const waiters = sdkFlowStartWaitersRef.current;
    for (const waiter of Array.from(waiters)) {
      if (waiter.kind !== kind) continue;
      if (seq <= waiter.seqAfter) continue;
      clearTimeout(waiter.timeoutId);
      waiters.delete(waiter);
      waiter.resolve(seq);
    }

    return seq;
  }, []);

  const appendSdkEventMessage = useCallback((seq: number, message: string) => {
    const trimmed = message.trim();
    if (!trimmed) return;

    setSdkFlowState((prev) => {
      if (prev.seq !== seq || prev.status !== 'in-progress') return prev;
      const lines = prev.eventsText ? prev.eventsText.split('\n') : [];
      const last = lines[lines.length - 1];
      if (last === trimmed) return prev;
      const nextLines = [...lines, trimmed].slice(-MAX_EVENT_LINES);
      const next = { ...prev, eventsText: nextLines.join('\n') };
      sdkFlowRef.current = next;
      return next;
    });
  }, []);

  const endSdkFlow = useCallback(
    (kind: FlowKind, seq: number, status: 'success' | 'error', error?: string) => {
      const current = sdkFlowRef.current;
      const snapshot = buildCompletedSdkFlowState({
        current,
        seq,
        kind,
        status,
        ...(error ? { error } : {}),
      });

      if (current.seq === seq && current.kind === kind) {
        sdkFlowRef.current = snapshot;
        setSdkFlowState(snapshot);
      }

      const deferred = sdkFlowCompletionDeferredsRef.current.get(seq);
      if (deferred && !deferred.settled) {
        deferred.settled = true;
        sdkFlowCompletionDeferredsRef.current.delete(seq);
        if (status === 'error') {
          deferred.reject(new Error(error || 'Operation failed'));
        } else {
          deferred.resolve(snapshot);
        }
      }
    },
    [],
  );

  const awaitNextStart: SDKFlowRuntime['awaitNextStart'] = useCallback(
    async (kind, seqAfter, timeoutMs) => {
      const current = sdkFlowRef.current;
      if (current.kind === kind && current.seq > seqAfter) return current.seq;

      return await new Promise<number | null>((resolve) => {
        const waiter: StartWaiter = {
          kind,
          seqAfter,
          resolve: (seq) => resolve(seq),
          timeoutId: setTimeout(() => {
            sdkFlowStartWaitersRef.current.delete(waiter);
            resolve(null);
          }, timeoutMs),
        };
        sdkFlowStartWaitersRef.current.add(waiter);
      });
    },
    [],
  );

  const awaitCompletion: SDKFlowRuntime['awaitCompletion'] = useCallback(async (seq, timeoutMs) => {
    const current = sdkFlowRef.current;
    if (current.seq === seq && current.status !== 'in-progress') {
      if (current.status === 'error') throw new Error(current.error || 'Operation failed');
      return current;
    }

    const deferred = sdkFlowCompletionDeferredsRef.current.get(seq);
    if (!deferred) throw new Error('Unknown SDK flow sequence');
    return await withTimeout(deferred.promise, timeoutMs);
  }, []);

  const awaitNextCompletion: SDKFlowRuntime['awaitNextCompletion'] = useCallback(
    async (kind, seqAfter, startTimeoutMs, completionTimeoutMs) => {
      const seq = await awaitNextStart(kind, seqAfter, startTimeoutMs);
      if (seq == null) return;
      await awaitCompletion(seq, completionTimeoutMs);
    },
    [awaitCompletion, awaitNextStart],
  );

  const sdkFlow: SDKFlowRuntime = useMemo(
    () => ({
      ...sdkFlowState,
      awaitCompletion,
      awaitNextStart,
      awaitNextCompletion,
    }),
    [awaitCompletion, awaitNextCompletion, awaitNextStart, sdkFlowState],
  );

  useEffect(() => {
    return () => {
      for (const waiter of sdkFlowStartWaitersRef.current) {
        clearTimeout(waiter.timeoutId);
      }
      sdkFlowStartWaitersRef.current.clear();
      for (const deferred of sdkFlowCompletionDeferredsRef.current.values()) {
        if (!deferred.settled) {
          deferred.settled = true;
          deferred.reject(new Error('SDK flow canceled'));
        }
      }
      sdkFlowCompletionDeferredsRef.current.clear();
    };
  }, []);

  return {
    sdkFlow,
    beginSdkFlow,
    appendSdkEventMessage,
    endSdkFlow,
  };
}

export default useSDKFlowRuntime;
