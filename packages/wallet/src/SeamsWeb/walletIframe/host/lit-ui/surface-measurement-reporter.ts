import type { WalletIframeRequestId } from '@/core/types/walletIframeIdentity';
import type {
  HostedAuthMenuSessionId,
  WalletIframeSurfaceMeasurement,
} from '../../shared/messages';

type SurfaceMeasurementReporterOptions =
  | {
      readonly kind: 'request_surface';
      readonly element: HTMLElement;
      readonly requestId: WalletIframeRequestId;
      readonly postMeasurement: (measurement: WalletIframeSurfaceMeasurement) => void;
    }
  | {
      readonly kind: 'request_scroll_surface';
      readonly element: HTMLElement;
      readonly requestId: WalletIframeRequestId;
      readonly postMeasurement: (measurement: WalletIframeSurfaceMeasurement) => void;
    }
  | {
      readonly kind: 'auth_menu_surface';
      readonly element: HTMLElement;
      readonly requestId: WalletIframeRequestId;
      readonly authMenuSessionId: HostedAuthMenuSessionId;
      readonly postMeasurement: (measurement: WalletIframeSurfaceMeasurement) => void;
    };

type SurfaceSize = {
  readonly widthCssPx: number;
  readonly heightCssPx: number;
};

function roundedPositiveCssPx(value: number): number | null {
  if (!Number.isFinite(value) || value <= 0) return null;
  const rounded = Math.round(value);
  return rounded > 0 && Number.isSafeInteger(rounded) ? rounded : null;
}

function sizeFromRect(rect: Pick<DOMRectReadOnly, 'width' | 'height'>): SurfaceSize | null {
  const widthCssPx = roundedPositiveCssPx(rect.width);
  const heightCssPx = roundedPositiveCssPx(rect.height);
  if (widthCssPx === null || heightCssPx === null) return null;
  return { widthCssPx, heightCssPx };
}

function sizeFromEntryOrElement(
  element: HTMLElement,
  entry: ResizeObserverEntry | null,
): SurfaceSize | null {
  return sizeFromRect(entry?.contentRect ?? element.getBoundingClientRect());
}

function sizeForReporter(
  options: SurfaceMeasurementReporterOptions,
  entry: ResizeObserverEntry | null,
): SurfaceSize | null {
  if (options.kind === 'request_scroll_surface') {
    const rect = options.element.getBoundingClientRect();
    return sizeFromRect({
      width: Math.max(options.element.scrollWidth, rect.width),
      height: Math.max(options.element.scrollHeight, rect.height),
    });
  }
  return sizeFromEntryOrElement(options.element, entry);
}

function measurementForSize(
  options: SurfaceMeasurementReporterOptions,
  sequence: number,
  size: SurfaceSize,
): WalletIframeSurfaceMeasurement {
  switch (options.kind) {
    case 'request_surface':
    case 'request_scroll_surface':
      return {
        kind: 'measured_v1',
        requestId: options.requestId,
        sequence,
        widthCssPx: size.widthCssPx,
        heightCssPx: size.heightCssPx,
      };
    case 'auth_menu_surface':
      return {
        kind: 'measured_auth_menu_v1',
        requestId: options.requestId,
        authMenuSessionId: options.authMenuSessionId,
        sequence,
        widthCssPx: size.widthCssPx,
        heightCssPx: size.heightCssPx,
      };
  }
}

/**
 * A surface posts one measurement per change: it announces where its content
 * is going and the parent eases there once (refactor 116). A burst of them is
 * the signature of content animating its own height inside a box that is
 * sized from that height — the parent then chases a moving target and the card
 * is clipped by a box that never catches up. It is worth one console line,
 * because no test can enumerate every component that might start doing it.
 */
const STREAMING_POSTS_THRESHOLD = 4;
const STREAMING_WINDOW_MS = 150;

// Parent-side surface generations can outlive a remounted child root.
let nextSurfaceMeasurementSequence = 1;

function allocateSurfaceMeasurementSequence(): number | null {
  const sequence = nextSurfaceMeasurementSequence;
  if (!Number.isSafeInteger(sequence) || sequence <= 0) return null;

  nextSurfaceMeasurementSequence =
    sequence === Number.MAX_SAFE_INTEGER ? Number.POSITIVE_INFINITY : sequence + 1;
  return sequence;
}

export type WalletIframeSurfaceMeasurementReporter = {
  disconnect(): void;
};

class SurfaceMeasurementReporter implements WalletIframeSurfaceMeasurementReporter {
  private readonly observer: ResizeObserver | null;
  private latestEntry: ResizeObserverEntry | null = null;
  private recentPostTimes: number[] = [];
  private warnedAboutStreaming = false;
  private animationFrame: number | null = null;
  private lastSize: SurfaceSize | null = null;
  private disconnected = false;

  constructor(private readonly options: SurfaceMeasurementReporterOptions) {
    if (typeof ResizeObserver === 'function') {
      this.observer = new ResizeObserver(this.onResize);
      this.observer.observe(options.element);
      this.reportLatestSize();
      return;
    }
    this.observer = null;
    this.reportLatestSize();
  }

  disconnect(): void {
    if (this.disconnected) return;
    this.disconnected = true;
    this.observer?.disconnect();
    if (this.animationFrame !== null && typeof cancelAnimationFrame === 'function') {
      cancelAnimationFrame(this.animationFrame);
    }
    this.animationFrame = null;
    this.latestEntry = null;
  }

  private onResize = (entries: ResizeObserverEntry[]): void => {
    if (this.disconnected) return;
    this.latestEntry = entries.at(-1) ?? null;
    this.scheduleReport();
  };

  private scheduleReport(): void {
    if (this.disconnected) return;
    // Report synchronously from the ResizeObserver callback. RO already
    // delivers at most once per frame, after layout and before paint, so
    // deferring to requestAnimationFrame only added a whole frame of latency
    // between this surface resizing and the host geometry that follows it —
    // visible as the host box lagging the card during a resize.
    if (this.animationFrame !== null && typeof cancelAnimationFrame === 'function') {
      cancelAnimationFrame(this.animationFrame);
      this.animationFrame = null;
    }
    this.reportLatestSize();
  }

  private reportLatestSize(): void {
    if (this.disconnected) return;
    const size = sizeForReporter(this.options, this.latestEntry);
    this.latestEntry = null;
    if (!size || this.sameSize(size)) return;
    this.lastSize = size;
    const sequence = allocateSurfaceMeasurementSequence();
    if (sequence === null) {
      this.disconnect();
      return;
    }
    this.noteStreaming();
    this.options.postMeasurement(measurementForSize(this.options, sequence, size));
  }

  private noteStreaming(): void {
    if (this.warnedAboutStreaming) return;
    const now = typeof performance === 'object' ? performance.now() : Date.now();
    this.recentPostTimes.push(now);
    while (this.recentPostTimes.length && now - this.recentPostTimes[0] > STREAMING_WINDOW_MS) {
      this.recentPostTimes.shift();
    }
    if (this.recentPostTimes.length < STREAMING_POSTS_THRESHOLD) return;
    this.warnedAboutStreaming = true;
    console.warn(
      `[W3A] ${this.options.kind} posted ${this.recentPostTimes.length} surface measurements in ` +
        `${STREAMING_WINDOW_MS}ms. Content inside a measured surface must announce a height ` +
        'change once (announceSurfaceResize) instead of animating its own height; the host box ' +
        'cannot follow a moving target. See docs/refactor-116-lit-component-consolidation.md.',
    );
  }

  private sameSize(size: SurfaceSize): boolean {
    return (
      this.lastSize?.widthCssPx === size.widthCssPx &&
      this.lastSize?.heightCssPx === size.heightCssPx
    );
  }
}

export function createWalletIframeSurfaceMeasurementReporter(
  options: SurfaceMeasurementReporterOptions,
): WalletIframeSurfaceMeasurementReporter {
  return new SurfaceMeasurementReporter(options);
}
