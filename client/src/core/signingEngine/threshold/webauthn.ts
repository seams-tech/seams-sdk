import type { AccountId } from '../../types/accountIds';
import type { ProfileAuthenticatorRecord } from '../../indexedDB';
import type { WebAuthnAuthenticationCredential } from '../../types/webauthn';
import {
  collectAuthenticationCredentialForChallengeB64u as collectAuthenticationCredentialForChallengeB64uShared,
  type WebAuthnAuthenticatorRecord,
  type WebAuthnIndexedDbClientPort,
  type WebAuthnIndexedDbPort,
  type WebAuthnPromptPort,
} from '../signers/webauthn/credentials/collectAuthenticationCredentialForChallengeB64u';
import {
  getPrfFirstB64uFromCredential,
  redactCredentialExtensionOutputs,
} from '../signers/webauthn/credentials/credentialExtensions';

export { getPrfFirstB64uFromCredential, redactCredentialExtensionOutputs };

export type ThresholdAuthenticatorRecord = ProfileAuthenticatorRecord & WebAuthnAuthenticatorRecord;
export type ThresholdIndexedDbClientPort =
  WebAuthnIndexedDbClientPort<ThresholdAuthenticatorRecord>;
export type ThresholdIndexedDbPort = WebAuthnIndexedDbPort<ThresholdAuthenticatorRecord>;
export type ThresholdWebAuthnPromptPort = WebAuthnPromptPort;

export type ThresholdEd25519ClientShareDeriverPort = {
  deriveThresholdEd25519ClientVerifyingShare: (args: {
    sessionId: string;
    nearAccountId: AccountId;
    prfFirstB64u: string;
    wrapKeySalt: string;
  }) => Promise<{
    success: boolean;
    nearAccountId?: string;
    clientVerifyingShareB64u: string;
    error?: string;
  }>;
};

export type WarmSessionMaterialPort = {
  putWarmSessionMaterial: (args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
  }) => Promise<void>;
  claimWarmSessionMaterial?: (args: {
    sessionId: string;
    uses?: number;
  }) => Promise<{
    ok: boolean;
    code?: string;
    message?: string;
    prfFirstB64u?: string;
    remainingUses?: number;
    expiresAtMs?: number;
  }>;
  getWarmSessionStatus?: (args: { sessionId: string }) => Promise<{
    ok: boolean;
    code?: string;
    message?: string;
    remainingUses?: number;
    expiresAtMs?: number;
  }>;
  persistPrfFirstSealForThresholdSession?: (args: {
    sessionId: string;
    transport?: {
      relayerUrl?: string;
      thresholdSessionJwt?: string;
      keyVersion?: string;
      shamirPrimeB64u?: string;
    };
  }) => Promise<{
    ok: boolean;
    code?: string;
    message?: string;
    keyVersion?: string;
    sealedPrfFirstB64u?: string;
    remainingUses?: number;
    expiresAtMs?: number;
  }>;
};
export type WarmSessionMaterialWriter = Pick<
  WarmSessionMaterialPort,
  'putWarmSessionMaterial'
>;
export type ThresholdSigningKeyOpsPort = ThresholdEd25519ClientShareDeriverPort;

export async function collectAuthenticationCredentialForChallengeB64u(args: {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: Pick<
    ThresholdWebAuthnPromptPort,
    'getAuthenticationCredentialsSerializedForChallengeB64u'
  >;
  nearAccountId: AccountId | string;
  challengeB64u: string;
  includeSecondPrfOutput?: boolean;
}): Promise<WebAuthnAuthenticationCredential> {
  return await collectAuthenticationCredentialForChallengeB64uShared({
    indexedDB: args.indexedDB,
    touchIdPrompt: args.touchIdPrompt,
    nearAccountId: args.nearAccountId,
    challengeB64u: args.challengeB64u,
    includeSecondPrfOutput: args.includeSecondPrfOutput,
  });
}
