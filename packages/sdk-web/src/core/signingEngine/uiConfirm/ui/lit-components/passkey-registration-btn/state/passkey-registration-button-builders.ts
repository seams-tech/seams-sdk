import type {
  PasskeyRegistrationButtonInteractionState,
  PasskeyRegistrationButtonLifecycle,
} from './passkey-registration-button-state';
import { assertNever } from './assert-never';

export function buildPasskeyRegistrationButtonInteractionState(args: {
  hovered: boolean;
  focused: boolean;
  pressed: boolean;
  lifecycle: PasskeyRegistrationButtonLifecycle;
}): PasskeyRegistrationButtonInteractionState {
  switch (args.lifecycle.kind) {
    case 'ready':
      return {
        kind: 'registration_activation_button_interaction_state_v1',
        hovered: args.hovered,
        focused: args.focused,
        pressed: args.pressed,
        busy: false,
        disabled: false,
      };
    case 'starting':
      return {
        kind: 'registration_activation_button_interaction_state_v1',
        hovered: args.hovered,
        focused: args.focused,
        pressed: false,
        busy: true,
        disabled: true,
      };
    default:
      return assertNever(args.lifecycle);
  }
}
