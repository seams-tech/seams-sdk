import type { SigningEngineExportKeypairWithUIInput } from '@/core/signingEngine/flows/recovery/keyExportFlow';
import type { ExactEd25519SigningLaneIdentity } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type {
  NearAccountRef,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  PMExportKeypairUiPayload,
  PMRegistrationActivationPreparePayload,
  ParentToChildType,
} from '../shared/messages';
import { walletIdFromString } from '@shared/utils/registrationIntent';

declare const walletSession: WalletSessionRef;
declare const nearAccount: NearAccountRef;
declare const ed25519Lane: ExactEd25519SigningLaneIdentity;

const iframeExportPayload: PMExportKeypairUiPayload = {
  kind: 'near',
  walletSession,
  nearAccount,
  laneIdentity: { raw: 'untrusted-boundary-payload' },
  options: { chain: 'near' },
};
void iframeExportPayload;

const coreExportInput: SigningEngineExportKeypairWithUIInput = {
  kind: 'near',
  walletSession,
  nearAccount,
  laneIdentity: ed25519Lane,
  options: { chain: 'near' },
};
void coreExportInput;

const coreExportInputWithRawLane: SigningEngineExportKeypairWithUIInput = {
  kind: 'near',
  walletSession,
  nearAccount,
  // @ts-expect-error Core export requires parsed exact lane identity.
  laneIdentity: { raw: 'untrusted-boundary-payload' },
  options: { chain: 'near' },
};
void coreExportInputWithRawLane;

// @ts-expect-error Stale named-account registration iframe route was removed.
const staleRegisterRoute: ParentToChildType = 'PM_REGISTER';
void staleRegisterRoute;

const activationPreparePayload: PMRegistrationActivationPreparePayload = {
  activationId: 'activation-1',
  expiresAtMs: 1_900_000_000_000,
  wallet: { kind: 'provided', walletId: walletIdFromString('frost-fjord-rgcmpa') },
  presentation: {
    kind: 'outline_overlay',
    label: 'Register',
    busyLabel: 'Registering...',
    accessibleLabel: 'Register wallet',
  },
};
void activationPreparePayload;

// @ts-expect-error Activation prepare must carry the displayed provided wallet ID.
const activationPrepareWithoutWallet: PMRegistrationActivationPreparePayload = {
  activationId: 'activation-1',
  expiresAtMs: 1_900_000_000_000,
  presentation: {
    kind: 'outline_overlay',
    label: 'Register',
    busyLabel: 'Registering...',
    accessibleLabel: 'Register wallet',
  },
};
void activationPrepareWithoutWallet;

const activationPrepareWithServerAllocatedWallet: PMRegistrationActivationPreparePayload = {
  activationId: 'activation-1',
  expiresAtMs: 1_900_000_000_000,
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
  activationId: 'activation-1',
  expiresAtMs: 1_900_000_000_000,
  wallet: { kind: 'provided', walletId: walletIdFromString('frost-fjord-rgcmpa') },
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

export {};
