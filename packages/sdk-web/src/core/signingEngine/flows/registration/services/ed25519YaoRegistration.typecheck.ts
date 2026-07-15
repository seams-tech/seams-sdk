import type {
  NearEd25519YaoSigningCapability,
  NearResolvedEd25519SigningSessionState,
} from '@/core/signingEngine/interfaces/near';
import type { WasmRouterAbEd25519YaoActiveClientV1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';
import {
  PendingProductEd25519YaoRegistrationV1,
  buildProductEd25519YaoRegistrationRequestV1,
  type ProductEd25519YaoCapabilityActivationPortV1,
} from './ed25519YaoRegistration';

declare const pendingRegistration: PendingProductEd25519YaoRegistrationV1;
void pendingRegistration.dispose();
declare const activation: ProductEd25519YaoCapabilityActivationPortV1;
declare const walletSessionState: NearResolvedEd25519SigningSessionState;
declare const capability: NearEd25519YaoSigningCapability;
declare const activeClient: WasmRouterAbEd25519YaoActiveClientV1;

pendingRegistration.commit({ activation, walletSessionState });
activation.activateVerifiedNearEd25519YaoSigningCapability(capability);
// @ts-expect-error activation accepts a verified capability, not a raw active Client.
activation.activateVerifiedNearEd25519YaoSigningCapability(activeClient);

buildProductEd25519YaoRegistrationRequestV1({
  scope: {
    lifecycle_id: 'registration-1',
    root_share_epoch: 'epoch-1',
    account_id: 'wallet-1',
    wallet_session_id: 'wallet-session-1',
    signer_set_id: 'signer-set-1',
    signing_worker_id: 'signing-worker-1',
  },
  applicationBinding: {
    wallet_id: 'wallet-1',
    near_ed25519_signing_key_id: 'ed25519-key-1',
    signing_root_id: 'root-1',
    key_creation_signer_slot: 1,
  },
  participantIds: [1, 2],
});

// @ts-expect-error product registrations can only be created from verified active Client state.
new PendingProductEd25519YaoRegistrationV1({} as WasmRouterAbEd25519YaoActiveClientV1);

buildProductEd25519YaoRegistrationRequestV1({
  scope: {
    lifecycle_id: 'registration-1',
    root_share_epoch: 'epoch-1',
    account_id: 'wallet-1',
    wallet_session_id: 'wallet-session-1',
    signer_set_id: 'signer-set-1',
    signing_worker_id: 'signing-worker-1',
  },
  applicationBinding: {
    wallet_id: 'wallet-1',
    near_ed25519_signing_key_id: 'ed25519-key-1',
    signing_root_id: 'root-1',
    key_creation_signer_slot: 1,
  },
  // @ts-expect-error the fixed protocol requires exactly two participant ids.
  participantIds: [1],
});
