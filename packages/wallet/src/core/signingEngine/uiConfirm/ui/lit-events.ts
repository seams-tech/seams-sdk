// Shared helpers for Lit component custom events (local to WebAuthn components)

export const LitComponentEvents = {
  CONFIRM: 'lit-confirm',
  CANCEL: 'lit-cancel',
  COPY: 'lit-copy',
  TREE_TOGGLED: 'lit-tree-toggled',
  SURFACE_RESIZE_BEGIN: 'lit-surface-resize-begin',
  TX_REVIEW_TOGGLE_NODE: 'tx-review:toggle-node',
  TX_REVIEW_COPY: 'tx-review:copy',
  TX_REVIEW_OPEN_LINK: 'tx-review:open-link',
} as const;

export type LitComponentEvent = (typeof LitComponentEvents)[keyof typeof LitComponentEvents];

/**
 * Handed to whoever takes over a height change (see
 * {@link LitSurfaceResizeBeginDetail}). The announcing component keeps
 * ownership of its DOM and only lends out the one number it was about to
 * animate, as a ratio so the driver never needs to know the layout.
 */
export type LitSurfaceResizeDriver = {
  /** 0 renders the pre-change height, 1 the post-change height. */
  setProgress(progress: number): void;
  /** The change is fully applied: release the clamp and commit the DOM. */
  finish(): void;
};

/**
 * Fired before a component inside a confirmation changes its own height, with
 * that component already clamped at its PRE-change height. A host whose box is
 * sized from outside (the wallet-iframe confirmer, whose iframe the parent
 * window resizes to hug it) claims the motion so the box moves first and the
 * content fills it, instead of the content moving first and being clipped by a
 * box still catching up. Left unclaimed, the component animates itself.
 *
 * Components do not build this detail by hand: `announceSurfaceResize()` in
 * `ui/confirm-surface-resize.ts` owns the claim, clamp, and safety rules.
 */
export type LitSurfaceResizeBeginDetail = {
  /** Diagnostics label: a tree node id, `file-content-mode`, `confirm-body`. */
  reason?: string;
  /** Signed change in the announcing element's height, in CSS px. */
  deltaCssPx: number;
  /** Take over the motion. Returns null once someone else already has. */
  claim(): LitSurfaceResizeDriver | null;
};

export interface LitComponentEventDetailMap {
  [LitComponentEvents.CONFIRM]: void;
  [LitComponentEvents.CANCEL]: { reason?: string } | undefined;
  [LitComponentEvents.COPY]: { type: string; value: string };
  [LitComponentEvents.TREE_TOGGLED]: void;
  [LitComponentEvents.SURFACE_RESIZE_BEGIN]: LitSurfaceResizeBeginDetail;
  [LitComponentEvents.TX_REVIEW_TOGGLE_NODE]: { nodeId?: string; open?: boolean } | undefined;
  [LitComponentEvents.TX_REVIEW_COPY]: { value: string };
  [LitComponentEvents.TX_REVIEW_OPEN_LINK]: { href: string };
}

export type LitConfirmDetail = LitComponentEventDetailMap[(typeof LitComponentEvents)['CONFIRM']];
export type LitCancelDetail = LitComponentEventDetailMap[(typeof LitComponentEvents)['CANCEL']];
export type LitCopyDetail = LitComponentEventDetailMap[(typeof LitComponentEvents)['COPY']];
export type LitTreeToggledDetail =
  LitComponentEventDetailMap[(typeof LitComponentEvents)['TREE_TOGGLED']];
export type TxReviewToggleNodeDetail =
  LitComponentEventDetailMap[(typeof LitComponentEvents)['TX_REVIEW_TOGGLE_NODE']];
export type TxReviewCopyDetail =
  LitComponentEventDetailMap[(typeof LitComponentEvents)['TX_REVIEW_COPY']];
export type TxReviewOpenLinkDetail =
  LitComponentEventDetailMap[(typeof LitComponentEvents)['TX_REVIEW_OPEN_LINK']];

export type LitComponentEventDetail<T extends LitComponentEvent> = LitComponentEventDetailMap[T];

export type LitComponentEventListener<T extends LitComponentEvent> = (
  event: CustomEvent<LitComponentEventDetail<T>>,
) => void;

export function dispatchLitEvent<T extends LitComponentEvent>(
  target: EventTarget,
  type: T,
  detail?: LitComponentEventDetail<T>,
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
  options?: boolean | AddEventListenerOptions,
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

export const dispatchLitSurfaceResizeBegin = (
  target: EventTarget,
  detail: LitSurfaceResizeBeginDetail,
) => dispatchLitEvent(target, LitComponentEvents.SURFACE_RESIZE_BEGIN, detail);

export const dispatchTxReviewToggleNode = (
  target: EventTarget,
  detail?: TxReviewToggleNodeDetail,
) => dispatchLitEvent(target, LitComponentEvents.TX_REVIEW_TOGGLE_NODE, detail);

export const dispatchTxReviewCopy = (target: EventTarget, detail: TxReviewCopyDetail) =>
  dispatchLitEvent(target, LitComponentEvents.TX_REVIEW_COPY, detail);

export const dispatchTxReviewOpenLink = (target: EventTarget, detail: TxReviewOpenLinkDetail) =>
  dispatchLitEvent(target, LitComponentEvents.TX_REVIEW_OPEN_LINK, detail);

export const addLitSurfaceResizeBeginListener = (
  target: EventTarget,
  listener: LitComponentEventListener<(typeof LitComponentEvents)['SURFACE_RESIZE_BEGIN']>,
  options?: boolean | AddEventListenerOptions,
) => addLitEventListener(target, LitComponentEvents.SURFACE_RESIZE_BEGIN, listener, options);

export const addLitCancelListener = (
  target: EventTarget,
  listener: LitComponentEventListener<(typeof LitComponentEvents)['CANCEL']>,
  options?: boolean | AddEventListenerOptions,
) => addLitEventListener(target, LitComponentEvents.CANCEL, listener, options);
