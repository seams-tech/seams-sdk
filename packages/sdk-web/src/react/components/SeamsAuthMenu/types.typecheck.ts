import type {
  HostedAuthMenuExternalAuthEvidence,
  HostedAuthMenuExternalAuthRequest,
  SeamsAuthMenuProps,
} from './types';

const onOutcome: SeamsAuthMenuProps['onOutcome'] = (outcome) => {
  switch (outcome.kind) {
    case 'authenticated':
    case 'registered':
    case 'account_synced':
    case 'cancelled':
    case 'failed':
      return outcome.authMenuSessionId;
  }
};

const externalAuthBroker = async (
  request: HostedAuthMenuExternalAuthRequest,
): Promise<HostedAuthMenuExternalAuthEvidence> => {
  if (request.provider !== 'google') {
    return {
      kind: 'failed',
      code: 'provider_unavailable',
      message: 'Unsupported provider',
    };
  }
  return { kind: 'cancelled', reason: 'user_cancelled' };
};

const validProps: SeamsAuthMenuProps = {
  initialMode: 'register',
  registrationAccountInput: 'sponsored_named_near_account',
  showRegistrationInput: true,
  showProgress: true,
  copy: {
    register: { passkeyNameLabel: 'Passkey name' },
  },
  externalAuthBroker,
  onOutcome,
};
void validProps;

const callbackProps: SeamsAuthMenuProps = {
  onOutcome,
  // @ts-expect-error React-era operation callbacks are removed from the public boundary.
  onLogin: async () => undefined,
};
void callbackProps;

const domProps: SeamsAuthMenuProps = {
  onOutcome,
  // @ts-expect-error React elements, style objects, and class names cannot cross the iframe boundary.
  className: 'legacy-menu',
  style: {},
};
void domProps;
