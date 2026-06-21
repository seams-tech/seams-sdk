import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '@/core/types';
import type {
  ThresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorizationRequest,
  ThresholdEd25519PreparePasskeyPrfWorkerMaterialSealAuthorizationRequest,
  ThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult,
  ThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult,
  ThresholdEd25519WorkerMaterialBindingInputWithoutVerifier,
} from '@/core/types/signer-worker';
import { getPrfFirstB64uFromCredential } from '@/core/signingEngine/threshold/crypto/webauthn';
import { base64UrlDecode } from '@shared/utils/encoders';
import type { DurableSealedSessionPort, VolatileWarmMaterialPort } from '../../uiConfirm/uiConfirm.types';
import {
  formatMissingWarmPrfMaterialError,
  formatWarmSessionClaimUnavailableError,
  reportWarmSessionAvailabilityFailure,
} from '../warmCapabilities/readModel';

export type WarmSessionClaimPorts =
  | Partial<Pick<VolatileWarmMaterialPort, 'getWarmSessionStatus' | 'claimWarmSessionMaterial'>>
  | undefined;

export type PasskeyWarmSessionRecoveryPorts = Partial<
  Pick<
    VolatileWarmMaterialPort & DurableSealedSessionPort,
    'getWarmSessionStatus' | 'claimWarmSessionMaterial' | 'restorePersistedSessionForSigning'
  >
>;

export async function claimWarmSessionPrfFirst(args: {
  touchConfirm: WarmSessionClaimPorts;
  thresholdSessionId: string;
  errorContext: string;
  uses?: number;
  consume?: boolean;
  curve?: 'ed25519' | 'ecdsa';
  chain?: 'near';
  chainTarget?: ThresholdEcdsaChainTarget;
  restoreBeforeClaim?: () => Promise<void>;
}): Promise<string> {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const errorContext = String(args.errorContext || 'threshold session operation').trim();
  if (!thresholdSessionId) {
    throw new Error(`Missing threshold sessionId for ${errorContext}`);
  }
  if (!args.touchConfirm || typeof args.touchConfirm.claimWarmSessionMaterial !== 'function') {
    throw new Error('[WarmSessionStore] touchConfirm warm-session claim operations are required');
  }

  const readDiagnosticClaimCode = async (): Promise<string | undefined> => {
    if (typeof args.touchConfirm?.getWarmSessionStatus !== 'function') return undefined;
    const status = await args.touchConfirm
      .getWarmSessionStatus({ sessionId: thresholdSessionId })
      .catch(() => null);
    if (!status || status.ok) return undefined;
    return status.code === 'not_found' ? 'missing' : String(status.code || '').trim() || undefined;
  };

  await args.restoreBeforeClaim?.();

  const claimedMaterial = await args.touchConfirm.claimWarmSessionMaterial({
    sessionId: thresholdSessionId,
    uses: args.uses,
    ...(typeof args.consume === 'boolean' ? { consume: args.consume } : {}),
    ...(args.curve ? { curve: args.curve } : {}),
    ...(args.chain ? { chain: args.chain } : {}),
    ...(args.chainTarget ? { chainTarget: args.chainTarget } : {}),
  });
  if (!claimedMaterial.ok) {
    if (
      claimedMaterial.code !== 'not_found' &&
      claimedMaterial.code !== 'expired' &&
      claimedMaterial.code !== 'exhausted'
    ) {
      reportWarmSessionAvailabilityFailure({
        operation: 'claim',
        sessionId: thresholdSessionId,
        code: claimedMaterial.code,
      });
      throw formatWarmSessionClaimUnavailableError({
        errorContext,
        code: claimedMaterial.code,
      });
    }
    throw formatMissingWarmPrfMaterialError({
      errorContext,
      code: claimedMaterial.code === 'not_found' ? 'missing' : claimedMaterial.code,
    });
  }

  const prfFirstB64u = String(claimedMaterial.prfFirstB64u || '').trim();
  if (prfFirstB64u) {
    return prfFirstB64u;
  }

  const diagnosticCode = await readDiagnosticClaimCode();
  if (
    diagnosticCode &&
    diagnosticCode !== 'missing' &&
    diagnosticCode !== 'expired' &&
    diagnosticCode !== 'exhausted'
  ) {
    reportWarmSessionAvailabilityFailure({
      operation: 'claim',
      sessionId: thresholdSessionId,
      code: diagnosticCode,
    });
    throw formatWarmSessionClaimUnavailableError({
      errorContext,
      code: diagnosticCode,
    });
  }
  throw formatMissingWarmPrfMaterialError({
    errorContext,
    code: diagnosticCode,
  });
}

export type ThresholdEd25519PasskeyMaterialSealAuthorizationPort = {
  prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorization: (args: {
    request: ThresholdEd25519PreparePasskeyPrfWorkerMaterialSealAuthorizationRequest;
  }) => Promise<ThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult>;
};

export type ThresholdEd25519PasskeyMaterialUnsealAuthorizationPort = {
  prepareThresholdEd25519PasskeyPrfWorkerMaterialUnsealAuthorization: (args: {
    request: ThresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorizationRequest;
  }) => Promise<ThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult>;
};

const WORKER_DEFAULT_MATERIAL_AUTHORIZATION_EXPIRES_AT_MS = 0;

function zeroizeSecretBytes(bytes?: Uint8Array | null): void {
  if (bytes instanceof Uint8Array) bytes.fill(0);
}

function decodeMaterialAuthorizationSecret32B64u(value: string, fieldName: string): Uint8Array {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`${fieldName} is required for Ed25519 material authorization`);
  }
  const decoded = base64UrlDecode(normalized);
  if (decoded.length !== 32) {
    zeroizeSecretBytes(decoded);
    throw new Error(`${fieldName} must decode to 32 bytes`);
  }
  return decoded;
}

function requirePasskeyCredentialIdB64u(
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential,
): string {
  const credentialIdB64u = String(credential.rawId || credential.id || '').trim();
  if (!credentialIdB64u) {
    throw new Error('Passkey credential id is required for Ed25519 material authorization');
  }
  return credentialIdB64u;
}

function requirePasskeyCredentialPrfFirstB64u(
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential,
): string {
  const prfFirstB64u = String(getPrfFirstB64uFromCredential(credential) || '').trim();
  if (!prfFirstB64u) {
    throw new Error('Passkey PRF.first is required for Ed25519 material authorization');
  }
  return prfFirstB64u;
}

export async function prepareThresholdEd25519PasskeyMaterialSealAuthorizationFromCredential(args: {
  authorizationPort: ThresholdEd25519PasskeyMaterialSealAuthorizationPort;
  bindingInput: ThresholdEd25519WorkerMaterialBindingInputWithoutVerifier;
  rpId: string;
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
}): Promise<ThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult> {
  const prfFirstBytes = decodeMaterialAuthorizationSecret32B64u(
    requirePasskeyCredentialPrfFirstB64u(args.credential),
    'prfFirstB64u',
  );
  try {
    return await args.authorizationPort.prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorization(
      {
        request: {
          bindingInput: args.bindingInput,
          rpId: String(args.rpId || '').trim(),
          credentialIdB64u: requirePasskeyCredentialIdB64u(args.credential),
          prfFirstBytes,
          expiresAtMs: WORKER_DEFAULT_MATERIAL_AUTHORIZATION_EXPIRES_AT_MS,
        },
      },
    );
  } finally {
    zeroizeSecretBytes(prfFirstBytes);
  }
}

export async function prepareThresholdEd25519PasskeyMaterialUnsealAuthorizationFromCredential(args: {
  authorizationPort: ThresholdEd25519PasskeyMaterialUnsealAuthorizationPort;
  materialBindingDigest: string;
  rpId: string;
  credential: WebAuthnAuthenticationCredential;
  expiresAtMs: number;
}): Promise<ThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult> {
  const prfFirstBytes = decodeMaterialAuthorizationSecret32B64u(
    requirePasskeyCredentialPrfFirstB64u(args.credential),
    'prfFirstB64u',
  );
  try {
    return await args.authorizationPort.prepareThresholdEd25519PasskeyPrfWorkerMaterialUnsealAuthorization(
      {
        request: {
          materialBindingDigest: String(args.materialBindingDigest || '').trim(),
          rpId: String(args.rpId || '').trim(),
          credentialIdB64u: requirePasskeyCredentialIdB64u(args.credential),
          prfFirstBytes,
          expiresAtMs: args.expiresAtMs,
        },
      },
    );
  } finally {
    zeroizeSecretBytes(prfFirstBytes);
  }
}
