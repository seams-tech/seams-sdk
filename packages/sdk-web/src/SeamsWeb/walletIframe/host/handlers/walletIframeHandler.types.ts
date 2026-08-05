import type {
  ChildToParentEnvelope,
  ParentToChildEnvelope,
  ParentToChildType,
  ProgressPayload,
} from '../../shared/messages';
import type { SeamsWeb } from '@/SeamsWeb';
import type { WalletIframeRequestId } from '@/core/types/walletIframeIdentity';

export type Req<T extends ParentToChildType> = Extract<ParentToChildEnvelope, { type: T }>;

export type HostedAuthMenuRequestType =
  | 'PM_OPEN_AUTH_MENU'
  | 'PM_CANCEL_AUTH_MENU'
  | 'PM_RESOLVE_AUTH_MENU_EXTERNAL_AUTH';

export type HostedAuthMenuReq<T extends HostedAuthMenuRequestType> = Omit<Req<T>, 'requestId'> & {
  requestId: WalletIframeRequestId;
};

/**
 * Auth-menu handlers are deliberately typed as ordinary wallet handlers. The
 * Phase 1 route is fail-closed until the wallet-host controller owns the
 * session lifecycle in Phase 2.
 */
export type HostedAuthMenuHandlerMap = {
  [K in HostedAuthMenuRequestType]?: (
    req: HostedAuthMenuReq<K>,
  ) => Promise<void>;
};

export type HandlerMap = Partial<{
  [K in ParentToChildType]: (req: Extract<ParentToChildEnvelope, { type: K }>) => Promise<void>;
}>;

export interface HandlerDeps {
  getSeamsWeb(): SeamsWeb;
  post(msg: ChildToParentEnvelope): void;
  postProgress(requestId: string | undefined, payload: ProgressPayload): void;
  postToParent?(msg: unknown): void;
  isCancelled(requestId: string | undefined): boolean;
  respondIfCancelled(requestId: string | undefined): boolean;
}
