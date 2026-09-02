import type { RouterAbNormalSigningPrepareRequestV2BuildResult } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type {
  NearEd25519YaoOperationMaterial,
  NearEd25519YaoOperationMaterialFacts,
} from '@/core/signingEngine/interfaces/near';
import type { PreparedNearOperationStepUp } from './operationStepUpPreparation';
import {
  resolveNearOperationStepUpMaterial,
  type NearOperationStepUpMaterial,
} from './ed25519YaoCapabilityResolution';

declare const prepare: RouterAbNormalSigningPrepareRequestV2BuildResult;
declare const materialActivation: MpcMaterialActivationRef;
declare const material: NearEd25519YaoOperationMaterial;
declare const credential: WebAuthnAuthenticationCredential;
declare const materialFacts: NearEd25519YaoOperationMaterialFacts;

const operationMaterial: NearEd25519YaoOperationMaterial = {
  activeClient: material.activeClient,
  facts: materialFacts,
};

const invalidAuthorizedOperationMaterial: NearEd25519YaoOperationMaterial = {
  activeClient: material.activeClient,
  facts: materialFacts,
  // @ts-expect-error Operation material cannot carry reusable Wallet Session state.
  walletSessionState: undefined,
};

const invalidSessionOperationMaterial: NearEd25519YaoOperationMaterial = {
  activeClient: material.activeClient,
  facts: materialFacts,
  // @ts-expect-error Operation material cannot carry authorization-session identity.
  walletSessionId: 'wallet-session',
};

const invalidGrantOperationMaterial: NearEd25519YaoOperationMaterial = {
  activeClient: material.activeClient,
  facts: materialFacts,
  // @ts-expect-error An issued grant belongs beside resolved material.
  issuedAuthorization: null,
};

const transactionPreparation: PreparedNearOperationStepUp = {
  kind: 'near_transaction',
  prepare,
  unsignedTransactionBorshB64u: 'transaction',
  signingDigestB64u: 'digest',
  materialActivation,
};

const signatureOnlyPreparation: PreparedNearOperationStepUp = {
  kind: 'near_signature_only',
  prepare,
  signingDigestB64u: 'digest',
  materialActivation,
};

// @ts-expect-error Signature-only preparation cannot carry transaction bytes.
const invalidSignatureOnlyPreparation: PreparedNearOperationStepUp = {
  kind: 'near_signature_only',
  prepare,
  unsignedTransactionBorshB64u: 'transaction',
  signingDigestB64u: 'digest',
  materialActivation,
};

declare const sealedPasskeyMaterial: Extract<
  NearOperationStepUpMaterial,
  { kind: 'passkey_sealed' }
>;
declare const emailOtpMaterial: Extract<
  NearOperationStepUpMaterial,
  { kind: 'email_otp_live' }
>;
declare const sealedEmailOtpMaterial: Extract<
  NearOperationStepUpMaterial,
  { kind: 'email_otp_sealed' }
>;

void resolveNearOperationStepUpMaterial({
  kind: 'passkey',
  material: sealedPasskeyMaterial,
  expectedActivation: materialActivation,
  credential,
});

void resolveNearOperationStepUpMaterial({
  kind: 'email_otp_live',
  material: emailOtpMaterial,
  expectedActivation: materialActivation,
});

// @ts-expect-error A sealed Email OTP branch requires confirmed proof and request facts.
void resolveNearOperationStepUpMaterial({
  kind: 'email_otp_sealed',
  material: sealedEmailOtpMaterial,
  expectedActivation: materialActivation,
});

// @ts-expect-error Email OTP cannot authorize sealed Passkey material.
void resolveNearOperationStepUpMaterial({
  kind: 'email_otp_live',
  material: sealedPasskeyMaterial,
  expectedActivation: materialActivation,
});

void transactionPreparation;
void signatureOnlyPreparation;
void invalidSignatureOnlyPreparation;
void operationMaterial;
void invalidAuthorizedOperationMaterial;
void invalidSessionOperationMaterial;
void invalidGrantOperationMaterial;
void material;
