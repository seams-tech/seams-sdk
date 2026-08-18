/**
 * Preload the client-only implementation chunk for `SeamsAuthMenu`.
 * Useful for hover/viewport/idle prefetch to reduce interaction latency.
 */
export function preloadSeamsAuthMenu(): Promise<void> {
  // Best-effort: preloading should never crash callers or surface unhandled rejections.
  return import('./client').then(() => undefined).catch(() => undefined);
}

export default preloadSeamsAuthMenu;
