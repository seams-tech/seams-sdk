import { expect, test } from '@playwright/test';

import {
  getUserFriendlyErrorMessage,
  isTouchIdCancellationError,
  isUserCancellationError,
  isWebAuthnRpIdOriginConfigurationError,
} from '../../packages/shared-ts/src/utils/errors';

function webAuthnRpIdError(): Error {
  const error = new Error(
    'The relying party ID is not a registrable domain suffix of, nor equal to the current domain, and the /.well-known/webauthn resource of the claimed RP ID failed.',
  );
  error.name = 'NotAllowedError';
  return error;
}

test('WebAuthn RP ID origin failures are configuration errors, not cancellations', () => {
  const error = webAuthnRpIdError();
  expect(isWebAuthnRpIdOriginConfigurationError(error)).toBe(true);
  expect(isUserCancellationError(error)).toBe(false);
  expect(isTouchIdCancellationError(error)).toBe(false);
  expect(getUserFriendlyErrorMessage(error, 'registration')).toBe(
    'Registration failed because the configured WebAuthn RP ID is not valid for this app origin. Check VITE_RP_ID_BASE and the /.well-known/webauthn related-origin configuration for this environment.',
  );
});
