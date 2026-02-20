// Shared helpers for Lit component custom events (local to WebAuthn components)

export const LitComponentEvents = {
  CONFIRM: 'lit-confirm',
  CANCEL: 'lit-cancel',
  COPY: 'lit-copy',
  TREE_TOGGLED: 'lit-tree-toggled',
  TX_REVIEW_TOGGLE_NODE: 'tx-review:toggle-node',
  TX_REVIEW_COPY: 'tx-review:copy',
  TX_REVIEW_OPEN_LINK: 'tx-review:open-link',
} as const;

export type LitComponentEvent = (typeof LitComponentEvents)[keyof typeof LitComponentEvents];

export interface LitComponentEventDetailMap {
  [LitComponentEvents.CONFIRM]: void;
  [LitComponentEvents.CANCEL]: { reason?: string } | undefined;
  [LitComponentEvents.COPY]: { type: string; value: string };
  [LitComponentEvents.TREE_TOGGLED]: void;
  [LitComponentEvents.TX_REVIEW_TOGGLE_NODE]: { nodeId?: string; open?: boolean } | undefined;
  [LitComponentEvents.TX_REVIEW_COPY]: { value: string };
  [LitComponentEvents.TX_REVIEW_OPEN_LINK]: { href: string };
}

export type LitConfirmDetail = LitComponentEventDetailMap[(typeof LitComponentEvents)['CONFIRM']];
export type LitCancelDetail = LitComponentEventDetailMap[(typeof LitComponentEvents)['CANCEL']];
export type LitCopyDetail = LitComponentEventDetailMap[(typeof LitComponentEvents)['COPY']];
export type LitTreeToggledDetail = LitComponentEventDetailMap[(typeof LitComponentEvents)['TREE_TOGGLED']];
export type TxReviewToggleNodeDetail =
  LitComponentEventDetailMap[(typeof LitComponentEvents)['TX_REVIEW_TOGGLE_NODE']];
export type TxReviewCopyDetail =
  LitComponentEventDetailMap[(typeof LitComponentEvents)['TX_REVIEW_COPY']];
export type TxReviewOpenLinkDetail =
  LitComponentEventDetailMap[(typeof LitComponentEvents)['TX_REVIEW_OPEN_LINK']];

export type LitComponentEventDetail<T extends LitComponentEvent> = LitComponentEventDetailMap[T];

export type LitComponentEventListener<T extends LitComponentEvent> = (event: CustomEvent<LitComponentEventDetail<T>>) => void;

export function dispatchLitEvent<T extends LitComponentEvent>(
  target: EventTarget,
  type: T,
  detail?: LitComponentEventDetail<T>
): boolean {
  const event = new CustomEvent(type, {
    bubbles: true,
    composed: true,
    detail: detail as LitComponentEventDetail<T>,
  });
  return target.dispatchEvent(event);
}

export function addLitEventListener<T extends LitComponentEvent>(
  target: EventTarget,
  type: T,
  listener: LitComponentEventListener<T>,
  options?: boolean | AddEventListenerOptions
): () => void {
  const handler = listener as EventListener;
  target.addEventListener(type, handler, options);
  return () => target.removeEventListener(type, handler, options);
}

export const dispatchLitConfirm = (target: EventTarget) =>
  dispatchLitEvent(target, LitComponentEvents.CONFIRM);

export const dispatchLitCancel = (target: EventTarget, detail?: LitCancelDetail) =>
  dispatchLitEvent(target, LitComponentEvents.CANCEL, detail);

export const dispatchLitCopy = (target: EventTarget, detail: LitCopyDetail) =>
  dispatchLitEvent(target, LitComponentEvents.COPY, detail);

export const dispatchLitTreeToggled = (target: EventTarget) =>
  dispatchLitEvent(target, LitComponentEvents.TREE_TOGGLED);

export const dispatchTxReviewToggleNode = (
  target: EventTarget,
  detail?: TxReviewToggleNodeDetail,
) => dispatchLitEvent(target, LitComponentEvents.TX_REVIEW_TOGGLE_NODE, detail);

export const dispatchTxReviewCopy = (target: EventTarget, detail: TxReviewCopyDetail) =>
  dispatchLitEvent(target, LitComponentEvents.TX_REVIEW_COPY, detail);

export const dispatchTxReviewOpenLink = (target: EventTarget, detail: TxReviewOpenLinkDetail) =>
  dispatchLitEvent(target, LitComponentEvents.TX_REVIEW_OPEN_LINK, detail);

export const addLitCancelListener = (
  target: EventTarget,
  listener: LitComponentEventListener<(typeof LitComponentEvents)['CANCEL']>,
  options?: boolean | AddEventListenerOptions
) => addLitEventListener(target, LitComponentEvents.CANCEL, listener, options);
