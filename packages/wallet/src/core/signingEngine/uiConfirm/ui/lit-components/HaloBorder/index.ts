import { html, type PropertyValues } from 'lit';
import { LitElementWithProps } from '../LitElementWithProps';
import { ensureExternalStyles } from '../css/css-loader';
import type { AppearanceConfig } from '@/core/types/seams';

export type HaloTheme = 'dark' | 'light';

export class HaloBorderElement extends LitElementWithProps {
  static properties = {
    animated: { type: Boolean },
    theme: { type: String },
    appearance: { attribute: false },
    durationMs: { type: Number, attribute: 'duration-ms' },
    ringGap: { type: Number, attribute: 'ring-gap' },
    ringWidth: { type: Number, attribute: 'ring-width' },
    ringBorderRadius: { type: String, attribute: 'ring-border-radius' },
    ringBorderShadow: { type: String, attribute: 'ring-border-shadow' },
    ringBackground: { type: String, attribute: 'ring-background' },
    padding: { type: String },
    innerPadding: { type: String, attribute: 'inner-padding' },
    innerBackground: { type: String, attribute: 'inner-background' },
  } as const;

  declare animated?: boolean;
  declare theme?: HaloTheme;
  declare appearance?: AppearanceConfig;
  declare durationMs?: number;
  declare ringGap?: number;
  declare ringWidth?: number;
  declare ringBorderRadius?: string;
  declare ringBorderShadow?: string;
  declare ringBackground?: string;
  declare padding?: string;
  declare innerPadding?: string;
  declare innerBackground?: string;

  private _stylesReady = false;
  private _stylePromises: Promise<void>[] = [];
  private _stylesAwaiting: Promise<void> | null = null;
  private static readonly _STYLE_MARKER = 'data-w3a-halo-border-css';

  protected createRenderRoot(): HTMLElement | DocumentFragment {
    const root = super.createRenderRoot();
    const p = ensureExternalStyles(
      root as ShadowRoot | DocumentFragment | HTMLElement,
      'halo-border.css',
      HaloBorderElement._STYLE_MARKER,
    );
    this._stylePromises.push(p);
    p.catch(() => {});
    return root;
  }

  // Defer first render until external styles are adopted to avoid FOUC
  protected shouldUpdate(_changed: Map<string | number | symbol, unknown>): boolean {
    if (this._stylesReady) return true;
    if (this._hasPreloadedDocumentStyles()) {
      this._stylesReady = true;
      return true;
    }
    if (!this._stylesAwaiting) {
      const settle = Promise.all(this._stylePromises).then(
        () =>
          new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r()))),
      );
      this._stylesAwaiting = settle.then(() => {
        this._stylesReady = true;
        this.requestUpdate();
      });
    }
    return false;
  }

  /**
   * Returns true when a document-level stylesheet link for this component is
   * already present and loaded, allowing first render without extra gating.
   */
  private _hasPreloadedDocumentStyles(): boolean {
    const doc = this.ownerDocument ?? (typeof document !== 'undefined' ? document : null);
    if (!doc?.head) return false;
    const link = doc.head.querySelector(
      `link[${HaloBorderElement._STYLE_MARKER}]`,
    ) as HTMLLinkElement | null;
    if (!link) return false;
    const statefulLink = link as HTMLLinkElement & { _w3aLoaded?: boolean };
    return !!(statefulLink._w3aLoaded || link.sheet);
  }

  private _rafId: number | null = null;
  private _startTs: number = 0;
  private _running: boolean = false;

  connectedCallback(): void {
    super.connectedCallback();
    this.applyCssVars();
  }

  protected updated(changed?: PropertyValues): void {
    this.applyCssVars();

    // Start/stop animation based on "animated" or duration changes
    if (!changed) return;
    if (changed.has('animated') || changed.has('durationMs')) {
      if (this.animated) this.start();
      else this.stop();
    }
  }

  private applyCssVars(): void {
    this.setAppearanceCssVars(this.appearance);
    const vars: Record<string, string> = {};
    if (typeof this.ringGap === 'number') vars['--ring-gap'] = `${this.ringGap}px`;
    if (typeof this.ringWidth === 'number') vars['--ring-width'] = `${this.ringWidth}px`;
    if (this.ringBorderRadius) vars['--ring-border-radius'] = this.ringBorderRadius;
    if (this.innerPadding) vars['--inner-padding'] = this.innerPadding;
    if (this.innerBackground) vars['--inner-background'] = this.innerBackground;
    if (this.ringBackground) vars['--ring-stops'] = this.ringBackground;
    if (this.ringBorderShadow) vars['--halo-box-shadow'] = this.ringBorderShadow;
    // Ensure an initial angle is present
    vars['--halo-angle'] = vars['--halo-angle'] || '0deg';
    this.setCssVars(vars);
  }

  disconnectedCallback(): void {
    this.stop();
    super.disconnectedCallback();
  }

  private tick = (ts: number) => {
    if (!this._running) return;
    if (!this._startTs) this._startTs = ts;
    const dur = typeof this.durationMs === 'number' && this.durationMs > 0 ? this.durationMs : 1150;
    const delta = (ts - this._startTs) % dur;
    const angle = (delta / dur) * 360;
    // Update only the angle var via adoptedStyleSheet (no style attribute writes)
    this.setCssVars({ '--halo-angle': `${angle}deg` });
    this._rafId = requestAnimationFrame(this.tick);
  };

  private start() {
    if (this._running) return;
    this._running = true;
    this._startTs = 0;
    this._rafId = requestAnimationFrame(this.tick);
  }

  private stop() {
    this._running = false;
    if (this._rafId) {
      cancelAnimationFrame(this._rafId);
      this._rafId = null;
    }
    // Reset angle
    this.setCssVars({ '--halo-angle': `0deg` });
  }

  render() {
    return html`
      <div class="halo-root ${this.theme ?? 'light'} ${this.animated ? 'animated' : ''}">
        <div class="halo-inner">
          <div class="halo-outer">
            ${this.animated ? html`<div class="halo-ring"></div>` : ''}
            <div class="halo-content"><slot></slot></div>
          </div>
        </div>
      </div>
    `;
  }
}

import { W3A_HALO_BORDER_ID } from '../../registry';

if (!customElements.get(W3A_HALO_BORDER_ID)) {
  customElements.define(W3A_HALO_BORDER_ID, HaloBorderElement);
}

export default HaloBorderElement;
