import type {
  ChildToParentEnvelope,
  ParentToChildEnvelope,
  ParentToChildType,
  ProgressPayload,
} from '../../shared/messages';
import type { SeamsWeb } from '@/SeamsWeb';

export type Req<T extends ParentToChildType> = Extract<ParentToChildEnvelope, { type: T }>;

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
