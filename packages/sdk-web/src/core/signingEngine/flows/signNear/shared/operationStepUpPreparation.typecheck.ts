import type { RouterAbNormalSigningPrepareRequestV2BuildResult } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { NearEd25519YaoSigningCapability } from '@/core/signingEngine/interfaces/near';
import type { PreparedNearOperationStepUp } from './operationStepUpPreparation';
import {
  resolveNearSignatureOnlyOperationStepUpCapability,
  type NearSignatureOnlyOperationStepUpMaterial,
} from './ed25519YaoCapabilityResolution';

declare const prepare: RouterAbNormalSigningPrepareRequestV2BuildResult;
declare const materialActivation: MpcMaterialActivationRef;
declare const capability: NearEd25519YaoSigningCapability;
declare const credential: WebAuthnAuthenticationCredential;

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
  NearSignatureOnlyOperationStepUpMaterial,
  { kind: 'passkey_sealed' }
>;
declare const emailOtpMaterial: Extract<
  NearSignatureOnlyOperationStepUpMaterial,
  { kind: 'email_otp_live' }
>;

void resolveNearSignatureOnlyOperationStepUpCapability({
  kind: 'passkey',
  material: sealedPasskeyMaterial,
  expectedActivation: materialActivation,
  credential,
});

void resolveNearSignatureOnlyOperationStepUpCapability({
  kind: 'email_otp',
  material: emailOtpMaterial,
  expectedActivation: materialActivation,
});

// @ts-expect-error Email OTP cannot authorize sealed Passkey material.
void resolveNearSignatureOnlyOperationStepUpCapability({
  kind: 'email_otp',
  material: sealedPasskeyMaterial,
  expectedActivation: materialActivation,
});

void transactionPreparation;
void signatureOnlyPreparation;
void invalidSignatureOnlyPreparation;
void capability;
