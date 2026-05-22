import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type {
  ReadyEcdsaSignerSession,
  ReadyEvmFamilyEcdsaMaterial,
  VerifiedEcdsaPublicFacts,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type {
  EcdsaSessionIdentity,
  EcdsaSigningKeyContext,
} from '../../session/warmCapabilities/ecdsaProvisionPlan';
import type {
  PublicIdentityAvailableEcdsaMaterial,
  ReadyEcdsaMaterial,
} from './ecdsaMaterialState';

declare const publicFacts: VerifiedEcdsaPublicFacts;
declare const record: ThresholdEcdsaSessionRecord;
declare const keyRef: ThresholdEcdsaSecp256k1KeyRef;
declare const identity: EcdsaSessionIdentity;
declare const signingKeyContext: EcdsaSigningKeyContext;
declare const readyMaterial: ReadyEvmFamilyEcdsaMaterial;
declare const signerSession: ReadyEcdsaSignerSession;

void ({
  kind: 'ready_to_sign',
  authMethod: 'passkey',
  source: 'login',
  chainTarget: record.chainTarget,
  identity,
  publicFacts,
  signingKeyContext,
  readyMaterial,
  signerSession,
  record,
  keyRef,
} satisfies ReadyEcdsaMaterial);

void ({
  kind: 'public_identity_available',
  authMethod: 'passkey',
  source: 'login',
  chainTarget: record.chainTarget,
  identity,
  publicFacts,
  record,
  keyRef,
} satisfies PublicIdentityAvailableEcdsaMaterial);

const readyWithoutSignerSession = {
  kind: 'ready_to_sign',
  authMethod: 'passkey',
  source: 'login',
  chainTarget: record.chainTarget,
  identity,
  publicFacts,
  signingKeyContext,
  readyMaterial,
  record,
  keyRef,
};

// @ts-expect-error ready-to-sign material requires hot signer-session material
void (readyWithoutSignerSession satisfies ReadyEcdsaMaterial);

const publicIdentityWithSignerSession = {
  kind: 'public_identity_available',
  authMethod: 'passkey',
  source: 'login',
  chainTarget: record.chainTarget,
  identity,
  publicFacts,
  record,
  keyRef,
  signerSession,
};

// @ts-expect-error public identity material must not carry signer-session material
void (publicIdentityWithSignerSession satisfies PublicIdentityAvailableEcdsaMaterial);

export {};
