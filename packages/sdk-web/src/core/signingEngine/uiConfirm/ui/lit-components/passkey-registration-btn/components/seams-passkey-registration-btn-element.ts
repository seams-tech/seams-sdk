import { html, type PropertyValues } from 'lit';
import { LitElementWithProps } from '../../LitElementWithProps';
import { ensureExternalStyles } from '../../css/css-loader';
import { SEAMS_PASSKEY_REGISTRATION_BTN_ID } from '../../../registry';
import type { RegistrationActivationButtonCss } from '@/SeamsWeb/publicApi/types';
import { buildPasskeyRegistrationButtonInteractionState } from '../state/passkey-registration-button-builders';
import type {
  PasskeyRegistrationButtonInteractionState,
  PasskeyRegistrationButtonLifecycle,
} from '../state/passkey-registration-button-state';

export const SEAMS_PASSKEY_REGISTRATION_ACTIVATION_START_EVENT =
  'seams-registration-activation-start';
export const SEAMS_PASSKEY_REGISTRATION_ACTIVATION_STATE_EVENT =
  'seams-registration-activation-state';

type PasskeyRegistrationButtonMode = 'outline_overlay' | 'iframe_button';

function cssPropertyName(property: string): string {
  return property.replace(/[A-Z]/g, (match) => `-${match.toLowerCase()}`);
}

export class SeamsPasskeyRegistrationButtonElement extends LitElementWithProps {
  static properties = {
    activationId: { type: String, attribute: 'activation-id' },
    label: { type: String },
    busyLabel: { type: String, attribute: 'busy-label' },
    accessibleLabel: { type: String, attribute: 'accessible-label' },
    mode: { type: String },
    buttonStyle: { attribute: false },
    shadowPaddingPx: { type: Number, attribute: 'shadow-padding-px' },
    lifecycle: { attribute: false },
  } as const;

  declare activationId: string;
  declare label: string;
  declare busyLabel: string;
  declare accessibleLabel: string;
  declare mode: PasskeyRegistrationButtonMode;
  declare buttonStyle?: RegistrationActivationButtonCss;
  declare shadowPaddingPx: number;
  declare lifecycle: PasskeyRegistrationButtonLifecycle;

  private hovered = false;
  private focused = false;
  private pressed = false;

  constructor() {
    super();
    this.activationId = '';
    this.label = 'Create passkey';
    this.busyLabel = 'Creating passkey...';
    this.accessibleLabel = 'Create passkey';
    this.mode = 'outline_overlay';
    this.shadowPaddingPx = 0;
    this.lifecycle = { kind: 'ready', busy: false, disabled: false };
  }

  protected createRenderRoot(): HTMLElement | DocumentFragment {
    return this;
  }

  connectedCallback(): void {
    super.connectedCallback();
    void ensureExternalStyles(
      this,
      'seams-passkey-registration-btn.css',
      'data-seams-passkey-registration-btn-css',
    );
  }

  protected updated(changedProperties: PropertyValues<this>): void {
    super.updated(changedProperties);
    if (
      changedProperties.has('buttonStyle') ||
      changedProperties.has('mode') ||
      changedProperties.has('shadowPaddingPx')
    ) {
      this.applyButtonStyle();
    }
  }

  focusButton(): void {
    this.findButton()?.focus({ preventScroll: true });
  }

  render() {
    const disabled = this.lifecycle.disabled;
    const buttonText = this.lifecycle.kind === 'starting' ? this.busyLabel : this.label;
    return html`
      <button
        type="button"
        data-seams-registration-activation-start="true"
        aria-label=${this.accessibleLabel || this.label}
        ?disabled=${disabled}
        @click=${this.handleClick}
        @pointerenter=${this.handlePointerEnter}
        @pointerleave=${this.handlePointerLeave}
        @pointerdown=${this.handlePointerDown}
        @pointerup=${this.handlePointerUp}
        @pointercancel=${this.handlePointerCancel}
        @dragstart=${this.handleDragStart}
        @dragend=${this.handleDragEnd}
        @focus=${this.handleFocus}
        @blur=${this.handleBlur}
        @keydown=${this.handleKeyDown}
        @keyup=${this.handleKeyUp}
      >
        ${buttonText}
      </button>
    `;
  }

  private findButton(): HTMLButtonElement | null {
    return this.querySelector('button');
  }

  private applyButtonStyle(): void {
    const button = this.findButton();
    if (!button) return;
    if (this.buttonStyle) {
      for (const [property, value] of Object.entries(this.buttonStyle)) {
        if (typeof value !== 'string') continue;
        button.style.setProperty(cssPropertyName(property), value);
      }
    }
    this.applyButtonInset(button);
  }

  private applyButtonInset(button: HTMLButtonElement): void {
    const shadowPaddingPx =
      this.mode === 'iframe_button' && Number.isFinite(this.shadowPaddingPx)
        ? Math.max(0, this.shadowPaddingPx)
        : 0;
    button.style.margin = `${shadowPaddingPx}px`;
    button.style.inlineSize =
      shadowPaddingPx > 0 ? `calc(100% - ${shadowPaddingPx * 2}px)` : '100%';
    button.style.blockSize =
      shadowPaddingPx > 0 ? `calc(100% - ${shadowPaddingPx * 2}px)` : '100%';
  }

  private isPointerInsideButton(event: PointerEvent | DragEvent): boolean {
    const button = this.findButton();
    if (!button) return false;
    const x = Number(event.clientX);
    const y = Number(event.clientY);
    if (!Number.isFinite(x) || !Number.isFinite(y)) return false;
    const rect = button.getBoundingClientRect();
    return x >= rect.left && x <= rect.right && y >= rect.top && y <= rect.bottom;
  }

  private releaseCapturedPointer(event: PointerEvent): void {
    const target = event.currentTarget as HTMLButtonElement | null;
    if (!target?.hasPointerCapture?.(event.pointerId)) return;
    try {
      target.releasePointerCapture(event.pointerId);
    } catch {
      // Pointer capture can already be released by the browser.
    }
  }

  private setLifecycle(lifecycle: PasskeyRegistrationButtonLifecycle): void {
    this.lifecycle = lifecycle;
    this.requestUpdate();
    this.emitInteractionState();
  }

  private setInteractionState(next: {
    hovered?: boolean;
    focused?: boolean;
    pressed?: boolean;
  }): void {
    if (next.hovered !== undefined) this.hovered = next.hovered;
    if (next.focused !== undefined) this.focused = next.focused;
    if (next.pressed !== undefined) this.pressed = next.pressed;
    this.emitInteractionState();
  }

  private currentInteractionState(): PasskeyRegistrationButtonInteractionState {
    return buildPasskeyRegistrationButtonInteractionState({
      hovered: this.hovered,
      focused: this.focused,
      pressed: this.pressed,
      lifecycle: this.lifecycle,
    });
  }

  private emitInteractionState(): void {
    this.dispatchEvent(
      new CustomEvent<PasskeyRegistrationButtonInteractionState>(
        SEAMS_PASSKEY_REGISTRATION_ACTIVATION_STATE_EVENT,
        {
          detail: this.currentInteractionState(),
          bubbles: true,
          composed: true,
        },
      ),
    );
  }

  private handleClick = (): void => {
    if (this.lifecycle.disabled) return;
    this.setLifecycle({ kind: 'starting', busy: true, disabled: true });
    this.dispatchEvent(
      new CustomEvent(SEAMS_PASSKEY_REGISTRATION_ACTIVATION_START_EVENT, {
        bubbles: true,
        composed: true,
        detail: { activationId: this.activationId },
      }),
    );
  };

  private handlePointerEnter = (): void => {
    this.setInteractionState({ hovered: true });
  };

  private handlePointerLeave = (): void => {
    this.setInteractionState({ hovered: false, pressed: false });
  };

  private handlePointerDown = (event: PointerEvent): void => {
    this.setInteractionState({ pressed: true });
    const target = event.currentTarget as HTMLButtonElement | null;
    target?.setPointerCapture?.(event.pointerId);
  };

  private handlePointerUp = (event: PointerEvent): void => {
    this.releaseCapturedPointer(event);
    this.setInteractionState({ pressed: false, hovered: this.isPointerInsideButton(event) });
  };

  private handlePointerCancel = (event: PointerEvent): void => {
    this.releaseCapturedPointer(event);
    this.setInteractionState({ pressed: false });
  };

  private handleDragStart = (): void => {
    this.setInteractionState({ pressed: true });
  };

  private handleDragEnd = (event: DragEvent): void => {
    this.setInteractionState({ hovered: this.isPointerInsideButton(event), pressed: false });
  };

  private handleFocus = (): void => {
    this.setInteractionState({ focused: true });
  };

  private handleBlur = (): void => {
    this.setInteractionState({ focused: false, pressed: false });
  };

  private handleKeyDown = (event: KeyboardEvent): void => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    this.setInteractionState({ pressed: true });
  };

  private handleKeyUp = (event: KeyboardEvent): void => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    this.setInteractionState({ pressed: false });
  };
}

if (
  typeof customElements !== 'undefined' &&
  !customElements.get(SEAMS_PASSKEY_REGISTRATION_BTN_ID)
) {
  customElements.define(SEAMS_PASSKEY_REGISTRATION_BTN_ID, SeamsPasskeyRegistrationButtonElement);
}

export default SeamsPasskeyRegistrationButtonElement;
