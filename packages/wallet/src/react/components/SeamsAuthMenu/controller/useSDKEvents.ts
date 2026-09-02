import React from 'react';
import type { SDKFlowRuntime } from '@/react/types';

/*
 * Feeds SDK events to the SeamsAuthMenu so that we can display SDK events
 * for registration, recovery, login, and related flows.
 */

type FlowKind = Exclude<SDKFlowRuntime['kind'], null>;
type Handler = ((...args: any[]) => void | Promise<unknown>) | undefined;

export function useSDKEvents(args: { sdkFlow: SDKFlowRuntime }): {
  withSdkEventsHandler: (
    kind: FlowKind,
    handler: Handler,
    timeoutMs: number,
  ) => ((...args: any[]) => Promise<void>) | undefined;
} {
  const { sdkFlow } = args;

  const withSdkEventsHandler = React.useCallback(
    (kind: FlowKind, handler: Handler, timeoutMs: number) => {
      if (!handler) return undefined;
      return async (...handlerArgs: any[]) => {
        const seqBefore = sdkFlow.seq;
        const res = handler(...handlerArgs);
        if (res && typeof res.then === 'function') {
          await res;
        }
        await sdkFlow.awaitNextCompletion(kind, seqBefore, 500, timeoutMs);
      };
    },
    [sdkFlow],
  );

  return { withSdkEventsHandler };
}

export default useSDKEvents;
