import type { SigningEngineExportKeypairWithUIInput } from '@/core/signingEngine/flows/recovery/keyExportFlow';
import type { ExactEcdsaSigningLaneIdentity } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  PMEmailOtpEcdsaCapabilityPayload,
  PMEnrollEmailOtpPayload,
  PMExportKeypairUiPayload,
  ParentToChildType,
} from '../shared/messages';

declare const walletSession: WalletSessionRef;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const ecdsaLane: ExactEcdsaSigningLaneIdentity;
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

const enrollmentWithParentBearer: PMEnrollEmailOtpPayload = {
  walletId: 'wallet.testnet',
  otpCode: '123456',
  // @ts-expect-error Hosted-wallet enrollment exchanges the bearer before postMessage.
  walletSessionToken: 'parent-wallet-session-token',
};
void enrollmentWithParentBearer;

const ecdsaLoginWithParentBearer: PMEmailOtpEcdsaCapabilityPayload = {
  walletSession,
  chainTarget,
  otpCode: '123456',
  // @ts-expect-error Hosted-wallet ECDSA login exchanges the bearer before postMessage.
  walletSessionToken: 'parent-wallet-session-token',
};
void ecdsaLoginWithParentBearer;

export {};
