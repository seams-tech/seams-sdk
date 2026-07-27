import type { OperationDigestSet } from '@shared/authorization/operationFingerprint';
import type { SelectedEcdsaLane } from '../../session/identity/laneIdentity';
import type { PreparedTransactionOperation } from '../../session/operationState/transactionState';
import type { SigningAuthPlan } from '../../stepUpConfirmation/types';
import type {
  EvmFamilyEcdsaEmailOtpStepUpAuthorization,
  EvmFamilyEcdsaPasskeyStepUpAuthorization,
} from './stepUpAuthorization';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  issueEcdsaOperationStepUpGrant,
  prepareEcdsaOperationStepUp,
  type EcdsaOperationStepUpSessionAuth,
  type PreparedEcdsaOperationStepUp,
} from '../../threshold/ecdsa/operationStepUp';
import type { EvmFamilySigningKeySlotId } from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  buildReadySecp256k1SigningMaterial,
  type ReadySecp256k1SigningMaterial,
} from './signers/secp256k1';

export type EvmFamilyThresholdEcdsaOperation =
  PreparedTransactionOperation<SelectedEcdsaLane> & {
    readonly authPlan: SigningAuthPlan;
  };

export type EvmFamilyEcdsaOperationStepUpAuthorization =
  | EvmFamilyEcdsaEmailOtpStepUpAuthorization
  | EvmFamilyEcdsaPasskeyStepUpAuthorization;

export async function prepareEvmFamilyEcdsaOperationStepUp(args: {
  readonly operation: EvmFamilyThresholdEcdsaOperation;
  readonly operationDigests: OperationDigestSet;
  readonly material: ReadySecp256k1SigningMaterial;
  readonly evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
}): Promise<PreparedEcdsaOperationStepUp> {
  const signerSession = args.material.signerSession;
  const participantIds = signerSession.publicFacts.participantIds;
  if (participantIds.length !== 2) {
    throw new Error('[chains] ECDSA operation step-up requires exactly two participants');
  }
  const operationId = String(args.operation.intent.operationId || '').trim();
  const expiresAtMs = Date.now() + 5 * 60_000;
  return await prepareEcdsaOperationStepUp({
    walletId: args.material.walletId,
    operationId,
    operationDigests: args.operationDigests,
    materialActivation: signerSession.materialActivation,
    normalSigningScope: signerSession.routerAbEcdsaDerivationNormalSigning.state.scope,
    evmFamilySigningKeySlotId: args.evmFamilySigningKeySlotId,
    keyHandle: signerSession.publicFacts.keyHandle,
    relayerKeyId: signerSession.transport.relayerKeyId,
    participantIds: [Number(participantIds[0]), Number(participantIds[1])],
    expiresAtMs,
  });
}

export async function authorizeEvmFamilyEcdsaOperationStepUp(args: {
  readonly relayerUrl: string;
  readonly sessionAuth: EcdsaOperationStepUpSessionAuth;
  readonly authority: WalletAuthAuthority;
  readonly authorization: EvmFamilyEcdsaOperationStepUpAuthorization;
  readonly prepared: PreparedEcdsaOperationStepUp;
  readonly material: ReadySecp256k1SigningMaterial;
}): Promise<ReadySecp256k1SigningMaterial> {
  const proof = operationStepUpProof({
    authority: args.authority,
    authorization: args.authorization,
  });
  const grant = await issueEcdsaOperationStepUpGrant({
    relayerUrl: args.relayerUrl,
    sessionAuth: args.sessionAuth,
    request: {
      kind: 'router_ab_ecdsa_operation_step_up_grant_v1',
      operation: args.prepared.operation,
      proof,
    },
  });
  const credential =
    args.sessionAuth.kind === 'app_session_jwt'
      ? {
          kind: 'jwt' as const,
          walletSessionJwt: args.sessionAuth.appSessionJwt,
        }
      : { kind: 'app_session_cookie' as const };
  return buildReadySecp256k1SigningMaterial({
    walletId: args.material.walletId,
    signerSession: args.material.signerSession,
    authorization: grant.authorization,
    credential,
    expiresAtMs: grant.expires_at_ms,
    singleUseEmailOtpSession: false,
    operationStepUpPreparation: args.prepared.operation,
  });
}

function operationStepUpProof(args: {
  readonly authority: WalletAuthAuthority;
  readonly authorization: EvmFamilyEcdsaOperationStepUpAuthorization;
}) {
  switch (args.authorization.kind) {
    case 'passkey': {
      if (!isPasskeyWalletAuthAuthority(args.authority)) {
        throw new Error('[chains] passkey step-up requires the exact passkey authority');
      }
      const credential = args.authorization.credential;
      return {
        kind: 'passkey' as const,
        authority: args.authority,
        webauthn_authentication: {
          id: credential.id,
          rawId: credential.rawId,
          type: credential.type,
          authenticatorAttachment: credential.authenticatorAttachment ?? null,
          response: {
            clientDataJSON: credential.response.clientDataJSON,
            authenticatorData: credential.response.authenticatorData,
            signature: credential.response.signature,
            userHandle: credential.response.userHandle ?? null,
          },
          clientExtensionResults: credential.clientExtensionResults ?? null,
        },
      };
    }
    case 'email_otp':
      if (!isEmailOtpWalletAuthAuthority(args.authority)) {
        throw new Error('[chains] Email OTP step-up requires the exact Email OTP authority');
      }
      return {
        kind: 'email_otp' as const,
        authority: args.authority,
        challenge_id: args.authorization.challengeId,
        otp_code: args.authorization.otpCode,
      };
  }
}
