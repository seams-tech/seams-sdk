import type { UserConfirmWorkerResponse } from '@/core/types/secure-confirm-worker';
import { UserConfirmMessageType } from '../../stepUpConfirmation/channel/confirmTypes';
import { awaitUserConfirmationV2 } from '../../uiConfirm/awaitUserConfirmation';
import {
  parsePasskeyMpcExportRequestPayload,
  runPasskeyMpcExportWithUi,
} from './passkeyMpcExportRuntime';

type PasskeyMpcExportWorkerGlobal = typeof globalThis & {
  awaitUserConfirmationV2?: typeof awaitUserConfirmationV2;
};

(globalThis as PasskeyMpcExportWorkerGlobal).awaitUserConfirmationV2 = awaitUserConfirmationV2;

function postResponse(id: unknown, response: Omit<UserConfirmWorkerResponse, 'id'>): void {
  self.postMessage({
    ...(typeof id === 'string' ? { id } : {}),
    ...response,
  } satisfies UserConfirmWorkerResponse);
}

self.onmessage = (event: MessageEvent): void => {
  const incoming = event.data as { id?: unknown; type?: unknown; payload?: unknown };
  if (incoming?.type === UserConfirmMessageType.USER_PASSKEY_CONFIRM_RESPONSE) return;
  if (incoming?.type === UserConfirmMessageType.USER_PASSKEY_CONFIRM_PROGRESS) {
    self.postMessage(event.data);
    return;
  }
  if (incoming?.type !== 'EXPORT_PRIVATE_KEYS_WITH_UI') {
    postResponse(incoming?.id, {
      success: false,
      error: `Unsupported Passkey MPC export worker message type: ${String(incoming?.type)}`,
    });
    return;
  }
  void (async () => {
    try {
      const payload = parsePasskeyMpcExportRequestPayload(incoming.payload);
      if (!payload) {
        postResponse(incoming.id, {
          success: false,
          error: 'Invalid EXPORT_PRIVATE_KEYS_WITH_UI payload',
        });
        return;
      }
      const result = await runPasskeyMpcExportWithUi(payload);
      postResponse(incoming.id, { success: true, data: result });
    } catch (error: unknown) {
      postResponse(incoming.id, {
        success: false,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  })();
};
