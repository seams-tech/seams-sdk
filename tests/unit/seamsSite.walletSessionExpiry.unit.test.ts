import { expect, test } from '@playwright/test';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  createSigningSessionExpiredEvent,
  parseSdkLifecycleEvent,
  SIGNING_SESSION_EXPIRY_DETECTION_SOURCES,
} from '../../packages/wallet/src/core/types/sdkSentEvents';
import { toWalletId } from '../../packages/wallet/src/core/signingEngine/interfaces/ecdsaChainTarget';
import { SigningSessionIds } from '../../packages/wallet/src/core/signingEngine/session/operationState/types';

test('the public expiry parser preserves the event and strips secret fields', () => {
  const event = createSigningSessionExpiredEvent({
    walletId: toWalletId('refactor-92-demo-wallet'),
    walletSessionId: SigningSessionIds.walletSession('refactor-92-demo-session'),
    authMethod: SIGNER_AUTH_METHODS.passkey,
    expiresAtMs: 1_000,
    detectedAtMs: 1_001,
    source: SIGNING_SESSION_EXPIRY_DETECTION_SOURCES.operationPreflight,
  });
  const parsed = parseSdkLifecycleEvent({
    ...event,
    jwt: 'secret-jwt',
    otp: '123456',
    prfOutput: 'secret-prf',
    privateKey: 'secret-private-key',
  });
  expect(parsed).toEqual(event);
  expect(parsed).not.toHaveProperty('jwt');
  expect(parsed).not.toHaveProperty('otp');
  expect(parsed).not.toHaveProperty('prfOutput');
  expect(parsed).not.toHaveProperty('privateKey');
});
