import type { WalletIframeSurfacePresentation } from './domain';

export const WALLET_IFRAME_SURFACE_INSET_CSS_PX = 16;
export const WALLET_IFRAME_SURFACE_MIN_COMPACT_WIDTH_CSS_PX = 280;
export const WALLET_IFRAME_SURFACE_MIN_COMPACT_HEIGHT_CSS_PX = 280;
export const WALLET_IFRAME_SURFACE_MAX_MODAL_WIDTH_CSS_PX = 560;
export const WALLET_IFRAME_SURFACE_PROVISIONAL_HEIGHT_CSS_PX = 320;

export type WalletIframeSurfaceGeometry =
  | { kind: 'hidden' }
  | {
      kind: 'provisional_centered_modal' | 'centered_modal';
      widthCssPx: number;
      heightCssPx: number;
      topCssPx: number;
      leftCssPx: number;
    }
  | {
      kind: 'provisional_bottom_drawer' | 'bottom_drawer';
      edge: 'bottom';
      widthCssPx: number;
      heightCssPx: number;
      topCssPx: number;
      leftCssPx: number;
    }
  | {
      kind: 'viewport_fallback';
      reason: 'small_visual_viewport' | 'measurement_unavailable';
      widthCssPx: number;
      heightCssPx: number;
      topCssPx: number;
      leftCssPx: number;
    };

export type WalletIframeModalGeometry = Extract<
  WalletIframeSurfaceGeometry,
  {
    kind: 'provisional_centered_modal' | 'centered_modal' | 'viewport_fallback';
  }
>;

export type WalletIframeDrawerGeometry = Extract<
  WalletIframeSurfaceGeometry,
  {
    kind: 'provisional_bottom_drawer' | 'bottom_drawer' | 'viewport_fallback';
  }
>;

export function isWalletIframeModalGeometry(
  geometry: WalletIframeSurfaceGeometry,
): geometry is WalletIframeModalGeometry {
  return (
    geometry.kind === 'provisional_centered_modal' ||
    geometry.kind === 'centered_modal' ||
    geometry.kind === 'viewport_fallback'
  );
}

export type WalletIframeSurfaceViewport = {
  widthCssPx: number;
  heightCssPx: number;
  offsetLeftCssPx: number;
  offsetTopCssPx: number;
};

export type WalletIframeSurfaceMeasurementSize = {
  widthCssPx: number;
  heightCssPx: number;
};

export type WalletIframeSurfaceAnchorRect = {
  topCssPx: number;
  leftCssPx: number;
  widthCssPx: number;
  heightCssPx: number;
};

export type WalletIframeSurfaceMeasurementState =
  | { kind: 'pending' }
  | ({ kind: 'measured' } & WalletIframeSurfaceMeasurementSize)
  | { kind: 'unavailable' };

function isFinitePositive(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const allowed = new Set(keys);
  return Object.keys(record).every((key) => allowed.has(key));
}

function roundCssPx(value: number): number {
  return Math.max(0, Math.round(value));
}

function roundSignedCssPx(value: number): number {
  return Math.round(value);
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

function normalizedViewport(viewport: WalletIframeSurfaceViewport): WalletIframeSurfaceViewport {
  if (
    !isFinitePositive(viewport.widthCssPx) ||
    !isFinitePositive(viewport.heightCssPx) ||
    !isFiniteNumber(viewport.offsetLeftCssPx) ||
    !isFiniteNumber(viewport.offsetTopCssPx)
  ) {
    throw new Error('Wallet iframe surface viewport is invalid');
  }
  return {
    widthCssPx: viewport.widthCssPx,
    heightCssPx: viewport.heightCssPx,
    offsetLeftCssPx: viewport.offsetLeftCssPx,
    offsetTopCssPx: viewport.offsetTopCssPx,
  };
}

export function parseWalletIframeSurfaceViewport(
  value: unknown,
): WalletIframeSurfaceViewport | null {
  if (!isPlainRecord(value)) return null;
  if (
    !hasOnlyKeys(value, ['widthCssPx', 'heightCssPx', 'offsetLeftCssPx', 'offsetTopCssPx']) ||
    !isFinitePositive(value.widthCssPx) ||
    !isFinitePositive(value.heightCssPx) ||
    !isFiniteNumber(value.offsetLeftCssPx) ||
    !isFiniteNumber(value.offsetTopCssPx)
  ) {
    return null;
  }
  return {
    widthCssPx: value.widthCssPx,
    heightCssPx: value.heightCssPx,
    offsetLeftCssPx: value.offsetLeftCssPx,
    offsetTopCssPx: value.offsetTopCssPx,
  };
}

function parseGeometryNumbers(record: Record<string, unknown>): {
  widthCssPx: number;
  heightCssPx: number;
  topCssPx: number;
  leftCssPx: number;
} | null {
  if (
    !isFinitePositive(record.widthCssPx) ||
    !isFinitePositive(record.heightCssPx) ||
    !isFiniteNumber(record.topCssPx) ||
    !isFiniteNumber(record.leftCssPx) ||
    record.topCssPx < 0 ||
    record.leftCssPx < 0
  ) {
    return null;
  }
  return {
    widthCssPx: record.widthCssPx,
    heightCssPx: record.heightCssPx,
    topCssPx: record.topCssPx,
    leftCssPx: record.leftCssPx,
  };
}

export function parseWalletIframeSurfaceGeometry(
  value: unknown,
): WalletIframeSurfaceGeometry | null {
  if (!isPlainRecord(value) || typeof value.kind !== 'string') return null;
  if (value.kind === 'hidden') {
    return hasOnlyKeys(value, ['kind']) ? { kind: 'hidden' } : null;
  }

  if (value.kind === 'provisional_centered_modal' || value.kind === 'centered_modal') {
    if (!hasOnlyKeys(value, ['kind', 'widthCssPx', 'heightCssPx', 'topCssPx', 'leftCssPx'])) {
      return null;
    }
    const geometry = parseGeometryNumbers(value);
    return geometry ? { kind: value.kind, ...geometry } : null;
  }

  if (value.kind === 'provisional_bottom_drawer' || value.kind === 'bottom_drawer') {
    if (
      !hasOnlyKeys(value, ['kind', 'edge', 'widthCssPx', 'heightCssPx', 'topCssPx', 'leftCssPx']) ||
      value.edge !== 'bottom'
    ) {
      return null;
    }
    const geometry = parseGeometryNumbers(value);
    return geometry ? { kind: value.kind, edge: 'bottom', ...geometry } : null;
  }

  if (value.kind === 'viewport_fallback') {
    if (
      !hasOnlyKeys(value, [
        'kind',
        'reason',
        'widthCssPx',
        'heightCssPx',
        'topCssPx',
        'leftCssPx',
      ]) ||
      (value.reason !== 'small_visual_viewport' && value.reason !== 'measurement_unavailable')
    ) {
      return null;
    }
    const geometry = parseGeometryNumbers(value);
    return geometry ? { kind: value.kind, reason: value.reason, ...geometry } : null;
  }

  return null;
}

function fallbackGeometry(
  viewport: WalletIframeSurfaceViewport,
  reason: 'small_visual_viewport' | 'measurement_unavailable',
): WalletIframeSurfaceGeometry {
  const widthCssPx = Math.max(1, viewport.widthCssPx - WALLET_IFRAME_SURFACE_INSET_CSS_PX * 2);
  const heightCssPx = Math.max(1, viewport.heightCssPx - WALLET_IFRAME_SURFACE_INSET_CSS_PX * 2);
  return {
    kind: 'viewport_fallback',
    reason,
    widthCssPx: roundCssPx(widthCssPx),
    heightCssPx: roundCssPx(heightCssPx),
    topCssPx: roundCssPx(viewport.offsetTopCssPx + WALLET_IFRAME_SURFACE_INSET_CSS_PX),
    leftCssPx: roundCssPx(viewport.offsetLeftCssPx + WALLET_IFRAME_SURFACE_INSET_CSS_PX),
  };
}

function viewportCannotFitCompactSurface(viewport: WalletIframeSurfaceViewport): boolean {
  return (
    viewport.widthCssPx - WALLET_IFRAME_SURFACE_INSET_CSS_PX * 2 <
      WALLET_IFRAME_SURFACE_MIN_COMPACT_WIDTH_CSS_PX ||
    viewport.heightCssPx - WALLET_IFRAME_SURFACE_INSET_CSS_PX * 2 <
      WALLET_IFRAME_SURFACE_MIN_COMPACT_HEIGHT_CSS_PX
  );
}

function centeredGeometry(
  viewport: WalletIframeSurfaceViewport,
  widthCssPx: number,
  heightCssPx: number,
  kind: 'provisional_centered_modal' | 'centered_modal',
): WalletIframeModalGeometry {
  return {
    kind,
    widthCssPx: roundCssPx(widthCssPx),
    heightCssPx: roundCssPx(heightCssPx),
    topCssPx: roundCssPx(viewport.offsetTopCssPx + (viewport.heightCssPx - heightCssPx) / 2),
    leftCssPx: roundCssPx(viewport.offsetLeftCssPx + (viewport.widthCssPx - widthCssPx) / 2),
  };
}

export function anchorWalletIframeModalGeometry(
  geometry: WalletIframeModalGeometry,
  anchor: WalletIframeSurfaceAnchorRect,
): WalletIframeModalGeometry {
  if (geometry.kind === 'viewport_fallback') return geometry;
  if (
    !isFiniteNumber(anchor.topCssPx) ||
    !isFiniteNumber(anchor.leftCssPx) ||
    !isFinitePositive(anchor.widthCssPx) ||
    !isFinitePositive(anchor.heightCssPx)
  ) {
    return geometry;
  }

  // Mirror the anchor exactly, with no visual-viewport clamp. The anchor is
  // in-flow host content: browser zoom shrinks the viewport's CSS px while the
  // anchor keeps its CSS size, so clamping width against the viewport made the
  // menu reflow under zoom instead of scaling with the page. If the anchor
  // overflows the viewport, the page scrolls — like any inline content.
  return {
    kind: geometry.kind,
    widthCssPx: roundCssPx(anchor.widthCssPx),
    heightCssPx: roundCssPx(geometry.heightCssPx),
    leftCssPx: roundSignedCssPx(anchor.leftCssPx),
    topCssPx: roundSignedCssPx(anchor.topCssPx),
  };
}

function fullViewportDrawerGeometry(
  viewport: WalletIframeSurfaceViewport,
  kind: 'provisional_bottom_drawer' | 'bottom_drawer',
): WalletIframeDrawerGeometry {
  // The inner drawer owns its width, safe-area padding, drag, and elevation.
  // Keep the host iframe aligned with the complete visual viewport.
  return {
    kind,
    edge: 'bottom',
    widthCssPx: roundCssPx(viewport.widthCssPx),
    heightCssPx: roundCssPx(viewport.heightCssPx),
    topCssPx: roundSignedCssPx(viewport.offsetTopCssPx),
    leftCssPx: roundSignedCssPx(viewport.offsetLeftCssPx),
  };
}

function isDrawerPresentation(
  presentation: WalletIframeSurfacePresentation,
): presentation is Extract<WalletIframeSurfacePresentation, { kind: 'drawer' }> {
  return presentation.kind === 'drawer';
}

export function provisionalWalletIframeSurfaceGeometry(
  presentation: WalletIframeSurfacePresentation,
  viewportInput: WalletIframeSurfaceViewport,
): WalletIframeSurfaceGeometry {
  const viewport = normalizedViewport(viewportInput);
  if (isDrawerPresentation(presentation)) {
    return fullViewportDrawerGeometry(viewport, 'provisional_bottom_drawer');
  }
  if (viewportCannotFitCompactSurface(viewport)) {
    return fallbackGeometry(viewport, 'small_visual_viewport');
  }
  const availableWidth = viewport.widthCssPx - WALLET_IFRAME_SURFACE_INSET_CSS_PX * 2;
  const availableHeight = viewport.heightCssPx - WALLET_IFRAME_SURFACE_INSET_CSS_PX * 2;
  return centeredGeometry(
    viewport,
    clamp(
      WALLET_IFRAME_SURFACE_MAX_MODAL_WIDTH_CSS_PX,
      WALLET_IFRAME_SURFACE_MIN_COMPACT_WIDTH_CSS_PX,
      Math.min(WALLET_IFRAME_SURFACE_MAX_MODAL_WIDTH_CSS_PX, availableWidth),
    ),
    Math.min(WALLET_IFRAME_SURFACE_PROVISIONAL_HEIGHT_CSS_PX, availableHeight),
    'provisional_centered_modal',
  );
}

export function measuredWalletIframeSurfaceGeometry(
  presentation: WalletIframeSurfacePresentation,
  viewportInput: WalletIframeSurfaceViewport,
  measurement: WalletIframeSurfaceMeasurementSize,
): WalletIframeSurfaceGeometry {
  const viewport = normalizedViewport(viewportInput);
  if (isDrawerPresentation(presentation)) {
    return fullViewportDrawerGeometry(viewport, 'bottom_drawer');
  }
  if (!isFinitePositive(measurement.widthCssPx) || !isFinitePositive(measurement.heightCssPx)) {
    throw new Error('Wallet iframe surface measurement is invalid');
  }
  if (viewportCannotFitCompactSurface(viewport)) {
    return fallbackGeometry(viewport, 'small_visual_viewport');
  }
  const availableWidth = viewport.widthCssPx - WALLET_IFRAME_SURFACE_INSET_CSS_PX * 2;
  const availableHeight = viewport.heightCssPx - WALLET_IFRAME_SURFACE_INSET_CSS_PX * 2;
  return centeredGeometry(
    viewport,
    clamp(
      measurement.widthCssPx,
      WALLET_IFRAME_SURFACE_MIN_COMPACT_WIDTH_CSS_PX,
      Math.min(WALLET_IFRAME_SURFACE_MAX_MODAL_WIDTH_CSS_PX, availableWidth),
    ),
    clamp(measurement.heightCssPx, 1, availableHeight),
    'centered_modal',
  );
}

export function resolveWalletIframeSurfaceGeometry(args: {
  presentation: WalletIframeSurfacePresentation;
  viewport: WalletIframeSurfaceViewport;
  measurement?: WalletIframeSurfaceMeasurementState;
}): WalletIframeSurfaceGeometry {
  const measurement = args.measurement;
  if (!measurement) {
    return provisionalWalletIframeSurfaceGeometry(args.presentation, args.viewport);
  }
  switch (measurement.kind) {
    case 'pending':
      return provisionalWalletIframeSurfaceGeometry(args.presentation, args.viewport);
    case 'measured':
      return measuredWalletIframeSurfaceGeometry(args.presentation, args.viewport, measurement);
    case 'unavailable': {
      const viewport = normalizedViewport(args.viewport);
      if (isDrawerPresentation(args.presentation)) {
        return fullViewportDrawerGeometry(viewport, 'bottom_drawer');
      }
      return viewportCannotFitCompactSurface(viewport)
        ? fallbackGeometry(viewport, 'small_visual_viewport')
        : fallbackGeometry(viewport, 'measurement_unavailable');
    }
    default: {
      const exhaustive: never = measurement;
      throw new Error(`Unhandled wallet iframe surface measurement state: ${String(exhaustive)}`);
    }
  }
}

export function walletIframeSurfaceGeometryEqual(
  left: WalletIframeSurfaceGeometry,
  right: WalletIframeSurfaceGeometry,
  epsilonCssPx = 1,
): boolean {
  if (left.kind !== right.kind) return false;
  if (left.kind === 'hidden' && right.kind === 'hidden') return true;
  if (left.kind === 'hidden' || right.kind === 'hidden') return false;
  if ('reason' in left || 'reason' in right) {
    if (!('reason' in left) || !('reason' in right) || left.reason !== right.reason) return false;
  }
  if ('edge' in left || 'edge' in right) {
    if (!('edge' in left) || !('edge' in right) || left.edge !== right.edge) return false;
  }
  return (
    Math.abs(left.widthCssPx - right.widthCssPx) < epsilonCssPx &&
    Math.abs(left.heightCssPx - right.heightCssPx) < epsilonCssPx &&
    Math.abs(left.topCssPx - right.topCssPx) < epsilonCssPx &&
    Math.abs(left.leftCssPx - right.leftCssPx) < epsilonCssPx
  );
}
