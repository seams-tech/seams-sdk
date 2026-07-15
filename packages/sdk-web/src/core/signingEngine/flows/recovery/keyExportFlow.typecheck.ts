import type {
  SigningEngineExportKeypairWithUIInput,
  SigningEngineResolveExactKeyExportLaneInput,
} from './keyExportFlow';
import type {
  ExactEcdsaSigningLaneIdentity,
  ExactEd25519SigningLaneIdentity,
} from '../../session/identity/exactSigningLaneIdentity';
import type {
  NearAccountRef,
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '../../interfaces/ecdsaChainTarget';

declare const walletSession: WalletSessionRef;
declare const nearAccount: NearAccountRef;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const ed25519Lane: ExactEd25519SigningLaneIdentity;
declare const ecdsaLane: ExactEcdsaSigningLaneIdentity;

const validEd25519Export: SigningEngineExportKeypairWithUIInput = {
  kind: 'ed25519',
  walletSession,
  nearAccount,
  laneIdentity: ed25519Lane,
  options: {},
};
void validEd25519Export;

const validEcdsaExport: SigningEngineExportKeypairWithUIInput = {
  kind: 'ecdsa',
  walletSession,
  chainTarget,
  laneIdentity: ecdsaLane,
  options: {},
};
void validEcdsaExport;

// @ts-expect-error Ed25519 export rejects an ECDSA lane identity.
const invalidEd25519Lane: SigningEngineExportKeypairWithUIInput = {
  kind: 'ed25519',
  walletSession,
  nearAccount,
  laneIdentity: ecdsaLane,
  options: {},
};
void invalidEd25519Lane;

// @ts-expect-error Ed25519 export rejects ECDSA chain targets.
const invalidEd25519Target: SigningEngineExportKeypairWithUIInput = {
  kind: 'ed25519',
  walletSession,
  nearAccount,
  chainTarget,
  laneIdentity: ed25519Lane,
  options: {},
};
void invalidEd25519Target;

// @ts-expect-error ECDSA lane resolution rejects NEAR account identity.
const invalidEcdsaResolve: SigningEngineResolveExactKeyExportLaneInput = {
  kind: 'ecdsa',
  walletSession,
  chainTarget,
  nearAccount,
};
void invalidEcdsaResolve;

export {};
