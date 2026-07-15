import type { SigningEngineExportKeypairWithUIInput } from '@/core/signingEngine/flows/recovery/keyExportFlow';
import type { ExactEcdsaSigningLaneIdentity } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  PMExportKeypairUiPayload,
  PMRegistrationActivationPreparePayload,
  ParentToChildType,
} from '../shared/messages';
import {
  walletIdFromString,
  type RegistrationSignerSetSelection,
} from '@shared/utils/registrationIntent';
import type {
  RegistrationActivationId,
  WalletIframeRequestId,
  WalletIframeSurfaceId,
} from '@/SeamsWeb/publicApi/types';

declare const walletSession: WalletSessionRef;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const ecdsaLane: ExactEcdsaSigningLaneIdentity;
declare const activationId: RegistrationActivationId;
declare const activationRequestId: WalletIframeRequestId;
declare const activationSurfaceId: WalletIframeSurfaceId;

const activationSignerSelection: RegistrationSignerSetSelection = {
  kind: 'signer_set',
  signers: [
    {
      kind: 'near_ed25519',
      accountProvisioning: {
        kind: 'implicit_account',
        accountIdSource: 'ed25519_public_key',
      },
      signerSlot: 1,
      participantIds: [1, 2],
      derivationVersion: 1,
    },
  ],
};

const iframeExportPayload: PMExportKeypairUiPayload = {
  kind: 'ecdsa',
  walletSession,
  chainTarget,
  laneIdentity: { raw: 'untrusted-boundary-payload' },
  options: {},
};
void iframeExportPayload;

const coreExportInput: SigningEngineExportKeypairWithUIInput = {
  kind: 'ecdsa',
  walletSession,
  chainTarget,
  laneIdentity: ecdsaLane,
  options: {},
};
void coreExportInput;

const coreExportInputWithRawLane: SigningEngineExportKeypairWithUIInput = {
  kind: 'ecdsa',
  walletSession,
  chainTarget,
  // @ts-expect-error Core export requires parsed exact lane identity.
  laneIdentity: { raw: 'untrusted-boundary-payload' },
  options: {},
};
void coreExportInputWithRawLane;

// @ts-expect-error Stale named-account registration iframe route was removed.
const staleRegisterRoute: ParentToChildType = 'PM_REGISTER';
void staleRegisterRoute;

const activationPreparePayload: PMRegistrationActivationPreparePayload = {
  activationId,
  requestId: activationRequestId,
  surfaceId: activationSurfaceId,
  expiresAtMs: 1_900_000_000_000,
  wallet: { kind: 'provided', walletId: walletIdFromString('frost-fjord-rgcmpa') },
  signerSelection: activationSignerSelection,
  presentation: {
    kind: 'outline_overlay',
    label: 'Register',
    busyLabel: 'Registering...',
    accessibleLabel: 'Register wallet',
  },
};
void activationPreparePayload;

// @ts-expect-error activation prepare requires complete surface correlation identity.
const activationPrepareWithoutIdentity: PMRegistrationActivationPreparePayload = {
  expiresAtMs: 1_900_000_000_000,
  wallet: { kind: 'provided', walletId: walletIdFromString('frost-fjord-rgcmpa') },
  signerSelection: activationSignerSelection,
  presentation: {
    kind: 'outline_overlay',
    label: 'Register',
    busyLabel: 'Registering...',
    accessibleLabel: 'Register wallet',
  },
};
void activationPrepareWithoutIdentity;

// @ts-expect-error Activation prepare must carry the displayed provided wallet ID.
const activationPrepareWithoutWallet: PMRegistrationActivationPreparePayload = {
  activationId,
  requestId: activationRequestId,
  surfaceId: activationSurfaceId,
  expiresAtMs: 1_900_000_000_000,
  signerSelection: activationSignerSelection,
  presentation: {
    kind: 'outline_overlay',
    label: 'Register',
    busyLabel: 'Registering...',
    accessibleLabel: 'Register wallet',
  },
};
void activationPrepareWithoutWallet;

const activationPrepareWithServerAllocatedWallet: PMRegistrationActivationPreparePayload = {
  activationId,
  requestId: activationRequestId,
  surfaceId: activationSurfaceId,
  expiresAtMs: 1_900_000_000_000,
  signerSelection: activationSignerSelection,
  presentation: {
    kind: 'outline_overlay',
    label: 'Register',
    busyLabel: 'Registering...',
    accessibleLabel: 'Register wallet',
  },
  // @ts-expect-error Activation prepare must carry the displayed provided wallet ID.
  wallet: { kind: 'server_allocated' },
};
void activationPrepareWithServerAllocatedWallet;

const activationPrepareWithNearAccount: PMRegistrationActivationPreparePayload = {
  activationId,
  requestId: activationRequestId,
  surfaceId: activationSurfaceId,
  expiresAtMs: 1_900_000_000_000,
  wallet: { kind: 'provided', walletId: walletIdFromString('frost-fjord-rgcmpa') },
  signerSelection: activationSignerSelection,
  presentation: {
    kind: 'outline_overlay',
    label: 'Register',
    busyLabel: 'Registering...',
    accessibleLabel: 'Register wallet',
  },
  // @ts-expect-error Activation prepare is wallet-scoped and carries no NEAR account.
  nearAccountId: 'alice.testnet',
};
void activationPrepareWithNearAccount;

const activationPrepareWithConfirmationPolicy: PMRegistrationActivationPreparePayload = {
  ...activationPreparePayload,
  // @ts-expect-error activation preparation derives wallet-owned confirmation policy.
  confirmationConfig: { uiMode: 'none' },
};
void activationPrepareWithConfirmationPolicy;

const activationPrepareWithGenericOptions: PMRegistrationActivationPreparePayload = {
  ...activationPreparePayload,
  // @ts-expect-error activation preparation carries no generic options bag.
  options: {},
};
void activationPrepareWithGenericOptions;

export {};
