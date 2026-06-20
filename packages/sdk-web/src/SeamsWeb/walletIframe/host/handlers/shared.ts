import type { ProgressPayload } from '../../shared/messages';
import type { HandlerDeps } from './walletIframeHandler.types';

export function respondOk(deps: Pick<HandlerDeps, 'post'>, requestId: string | undefined): void {
  deps.post({ type: 'PM_RESULT', requestId, payload: { ok: true } });
}

export function respondOkResult(
  deps: Pick<HandlerDeps, 'post'>,
  requestId: string | undefined,
  result: unknown,
): void {
  deps.post({ type: 'PM_RESULT', requestId, payload: { ok: true, result } });
}

export function withProgress<T extends object>(
  deps: Pick<HandlerDeps, 'postProgress'>,
  requestId: string | undefined,
  options?: T,
): T & { onEvent: (payload: ProgressPayload) => void } {
  return {
    ...(options || {}),
    onEvent: (ev: ProgressPayload) => deps.postProgress(requestId, ev),
  } as T & { onEvent: (payload: ProgressPayload) => void };
}

