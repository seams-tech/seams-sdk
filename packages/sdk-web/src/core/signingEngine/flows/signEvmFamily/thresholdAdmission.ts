import type { OperationDigestSet } from '@shared/authorization/operationFingerprint';
import type { TransactionSigningIntent } from '../../session/operationState/transactionState';
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
  issueEcdsaOperationStepUpAuthorization,
  prepareEcdsaOperationStepUp,
  type PreparedEcdsaOperationStepUp,
} from '../../threshold/ecdsa/operationStepUp';
import type { HydratedEcdsaSignerMaterial } from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  buildReadySecp256k1SigningMaterial,
  type ReadySecp256k1SigningMaterial,
} from './signers/secp256k1';

/** The operation a step-up authorizes: the intent it was prepared for, and the
 * plan that will authorize it. It carries no `SelectedEcdsaLane` — an
 * auth-neutral candidate has none, and nothing here ever read one. */
export type EvmFamilyThresholdEcdsaOperation = {
  readonly intent: TransactionSigningIntent;
  readonly authPlan: SigningAuthPlan;
};

export type EvmFamilyEcdsaOperationStepUpAuthorization =
  | EvmFamilyEcdsaEmailOtpStepUpAuthorization
  | EvmFamilyEcdsaPasskeyStepUpAuthorization;

export async function prepareEvmFamilyEcdsaOperationStepUp(args: {
  readonly operation: EvmFamilyThresholdEcdsaOperation;
  readonly operationDigests: OperationDigestSet;
  readonly material: HydratedEcdsaSignerMaterial;
}): Promise<PreparedEcdsaOperationStepUp> {
  const signerSession = args.material;
  const participantIds = signerSession.publicFacts.participantIds;
  if (participantIds.length !== 2) {
    throw new Error('[chains] ECDSA operation step-up requires exactly two participants');
  }
  const operationId = String(args.operation.intent.operationId || '').trim();
  const expiresAtMs = Date.now() + 5 * 60_000;
  return await prepareEcdsaOperationStepUp({
    walletId: signerSession.walletId,
    operationKind: 'evm.sign_transaction',
    operationId,
    operationDigests: args.operationDigests,
    materialActivation: signerSession.materialActivation,
    normalSigningScope: signerSession.routerAbEcdsaDerivationNormalSigning.state.scope,
    keyHandle: signerSession.publicFacts.keyHandle,
    relayerKeyId: signerSession.transport.relayerKeyId,
    participantIds: [Number(participantIds[0]), Number(participantIds[1])],
    expiresAtMs,
  });
}

export async function authorizeEvmFamilyEcdsaOperationStepUp(args: {
  readonly relayerUrl: string;
  readonly authority: WalletAuthAuthority;
  readonly authorization: EvmFamilyEcdsaOperationStepUpAuthorization;
  readonly prepared: PreparedEcdsaOperationStepUp;
  readonly material: HydratedEcdsaSignerMaterial;
}): Promise<ReadySecp256k1SigningMaterial> {
  const proof = operationStepUpProof({
    authority: args.authority,
    authorization: args.authorization,
  });
  const authorization = await issueEcdsaOperationStepUpAuthorization({
    relayerUrl: args.relayerUrl,
    request: {
      kind: 'router_ab_ecdsa_operation_step_up_v1',
      operation: args.prepared.operation,
      proof,
    },
  });
  const credential = { kind: 'operation_step_up' as const };
  return buildReadySecp256k1SigningMaterial({
    walletId: args.material.walletId,
    signerSession: args.material,
    authorization: { kind: 'operation_step_up' },
    credential,
    expiresAtMs: authorization.expires_at_ms,
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
