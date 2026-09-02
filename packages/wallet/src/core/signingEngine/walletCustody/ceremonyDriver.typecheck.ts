import type {
  WalletCustodyKeySetCeremonyInput,
  WalletCustodyCeremonyKeySetInput,
  WalletCustodyCeremonyStepRunner,
} from './ceremonyDriver';

declare const runStep: WalletCustodyCeremonyStepRunner;
declare const keySetRun: WalletCustodyCeremonyKeySetInput;

// @ts-expect-error recovery must name the registered manifest it reproduces.
const recoveryWithoutManifest: WalletCustodyKeySetCeremonyInput = {
  runStep,
  keySetRun,
  custody: {
    origin: 'recover',
    custodyJson: '{}',
    recoveryCode: new ArrayBuffer(20),
  },
};
void recoveryWithoutManifest;

const recoveryWithManifest: WalletCustodyKeySetCeremonyInput = {
  runStep,
  keySetRun,
  custody: {
    origin: 'recover_and_reseal',
    custodyJson: '{}',
    recoveryCode: new ArrayBuffer(20),
    replacementFactorJson: '{}',
    replacementFactorSecret: new ArrayBuffer(32),
  },
  recordedKeyManifestDigestB64u: 'registered-manifest-digest',
};
void recoveryWithManifest;

const recoveryWithoutReplacementFactor: WalletCustodyKeySetCeremonyInput = {
  runStep,
  keySetRun,
  // @ts-expect-error resealing requires the replacement factor and its secret.
  custody: {
    origin: 'recover_and_reseal',
    custodyJson: '{}',
    recoveryCode: new ArrayBuffer(20),
  },
  recordedKeyManifestDigestB64u: 'registered-manifest-digest',
};
void recoveryWithoutReplacementFactor;
