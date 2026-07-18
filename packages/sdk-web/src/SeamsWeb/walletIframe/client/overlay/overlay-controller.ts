import { setFullscreen, setHidden } from './overlay-styles';

type Mode = 'hidden' | 'fullscreen';

export class OverlayController {
  private ensureIframe: () => HTMLIFrameElement;
  private mode: Mode = 'hidden';
  private visible = false;

  constructor(opts: { ensureIframe: () => HTMLIFrameElement }) {
    this.ensureIframe = opts.ensureIframe;
  }

  applyViewportModal(accessibility: { title?: string }): void {
    const iframe = this.ensureIframe();
    this.visible = true;
    this.mode = 'fullscreen';
    setFullscreen(iframe);
    iframe.setAttribute('aria-hidden', 'false');
    iframe.removeAttribute('tabindex');
    this.applyTitle(iframe, accessibility.title);
  }

  applyHidden(): void {
    this.visible = false;
    this.mode = 'hidden';
    const iframe = this.ensureIframe();
    setHidden(iframe);
    iframe.setAttribute('aria-hidden', 'true');
    iframe.setAttribute('tabindex', '-1');
    iframe.removeAttribute('title');
  }

  private applyTitle(iframe: HTMLIFrameElement, title: string | undefined): void {
    if (title) {
      iframe.setAttribute('title', title);
      return;
    }
    iframe.removeAttribute('title');
  }

  getState(): {
    visible: boolean;
    mode: Mode;
  } {
    return {
      visible: this.visible,
      mode: this.mode,
    };
  }
}

export default OverlayController;
