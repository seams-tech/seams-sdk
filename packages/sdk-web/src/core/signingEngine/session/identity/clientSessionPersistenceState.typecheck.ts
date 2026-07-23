import { ClientWalletSessionExpiryInvalidator } from '../availability/clientSessionExpiryInvalidator';
import {
  parseWalletSessionAuthorizationBoundary,
  requireActiveWalletSessionAuthorization,
  type ActiveWalletSessionAuthorizationState,
  type ExpiredWalletSessionAuthorizationState,
  type InvalidWalletSessionAuthorizationState,
  type MissingWalletSessionAuthorizationState,
  type UnavailableWalletSessionAuthorizationState,
  type WalletSessionAuthorizationObservation,
} from './clientSessionPersistenceState';

declare const active: ActiveWalletSessionAuthorizationState;
declare const expired: ExpiredWalletSessionAuthorizationState;
declare const invalid: InvalidWalletSessionAuthorizationState;
declare const missing: MissingWalletSessionAuthorizationState;
declare const unavailable: UnavailableWalletSessionAuthorizationState;
declare const invalidator: ClientWalletSessionExpiryInvalidator;
declare const observation: WalletSessionAuthorizationObservation;

parseWalletSessionAuthorizationBoundary({ observation, nowMs: Date.now() });

// @ts-expect-error Boundary parsing requires an explicit observation time.
parseWalletSessionAuthorizationBoundary({ observation });

requireActiveWalletSessionAuthorization(active);

// @ts-expect-error Expired authorization cannot satisfy an active consumer.
requireActiveWalletSessionAuthorization(expired);
// @ts-expect-error Missing authorization cannot satisfy an active consumer.
requireActiveWalletSessionAuthorization(missing);
// @ts-expect-error Unavailable authorization cannot satisfy an active consumer.
requireActiveWalletSessionAuthorization(unavailable);
// @ts-expect-error Invalid authorization cannot satisfy an active consumer.
requireActiveWalletSessionAuthorization(invalid);

void invalidator.invalidate(expired);

// @ts-expect-error The canonical invalidator accepts expired authorization only.
void invalidator.invalidate(active);
