/**
 * UserConfirm worker types
 *
 * The UserConfirm worker now hosts:
 * - the UserConfirm bridge (`awaitUserConfirmationV2`) used by confirmTxFlow, and
 * - a small PRF.first cache for threshold warm sessions.
 */

export interface TouchConfirmManagerConfig {
  workerUrl?: string;
  workerTimeout?: number;
  debug?: boolean;
}

export type UserConfirmWorkerMessageType =
  | 'PING'
  | 'SECURE_CONFIRM_REQUEST'
  | 'THRESHOLD_PRF_FIRST_CACHE_PUT'
  | 'THRESHOLD_PRF_FIRST_CACHE_PEEK'
  | 'THRESHOLD_PRF_FIRST_CACHE_DISPENSE'
  | 'THRESHOLD_PRF_FIRST_CACHE_CLEAR';

export interface UserConfirmWorkerMessage<TPayload = unknown> {
  type: UserConfirmWorkerMessageType;
  id?: string;
  payload?: TPayload;
}

export interface UserConfirmWorkerResponse<TData = unknown> {
  id?: string;
  success: boolean;
  data?: TData;
  error?: string;
}
