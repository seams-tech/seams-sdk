export type PasskeyRegistrationButtonInteractionState = {
  kind: 'registration_activation_button_interaction_state_v1';
  hovered: boolean;
  focused: boolean;
  pressed: boolean;
  busy: boolean;
  disabled: boolean;
};

export type PasskeyRegistrationButtonLifecycle =
  | {
      kind: 'ready';
      busy: false;
      disabled: false;
    }
  | {
      kind: 'starting';
      busy: true;
      disabled: true;
    };
