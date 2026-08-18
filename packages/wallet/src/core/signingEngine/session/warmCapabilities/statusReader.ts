import type { SigningSessionStatus } from '@/core/types/seams';
import { SIGNER_AUTH_METHODS, type SignerAuthMethod } from '@shared/utils/signerDomain';
import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import {
  normalizeWarmSessionReadPorts,
  readWarmSessionClaim,
  toWarmSessionClaimFromStatusResult,
  toSigningSessionStatus,
  type WarmSessionReadPortsInput,
} from './readModel';
import type {
  ThresholdWarmSessionStatusReader,
  WarmSessionPrfClaim,
} from './types';
import {
  ed25519AuthorizationIdentityMatchesRuntime,
  type ExactEd25519SealedSessionRuntime,
} from './ed25519SealedSessionRuntime';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { EmailOtpWarmMaterialTarget } from '../../workerManager/workerTypes';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
function ed25519SessionMetadata(runtime: ExactEd25519SealedSessionRuntime): {
  authMethod: SignerAuthMethod;
  retention?: 'session';
} {
  switch (runtime.factor.kind) {
    case SIGNER_AUTH_METHODS.passkey:
      return {
        authMethod: SIGNER_AUTH_METHODS.passkey,
      };
    case SIGNER_AUTH_METHODS.emailOtp:
      return {
        authMethod: SIGNER_AUTH_METHODS.emailOtp,
        retention: 'session',
      };
    default:
      runtime.factor satisfies never;
      throw new Error('[WarmSessionStore] unsupported Ed25519 runtime factor');
  }
}

function ed25519WalletAuthAuthority(
  runtime: ExactEd25519SealedSessionRuntime,
): WalletAuthAuthority {
  switch (runtime.factor.kind) {
    case SIGNER_AUTH_METHODS.passkey:
      return buildPasskeyWalletAuthAuthority({
        walletId: runtime.walletId,
        rpId: runtime.factor.rpId,
        credentialIdB64u: runtime.factor.credentialIdB64u,
      });
    case SIGNER_AUTH_METHODS.emailOtp:
      return buildEmailOtpWalletAuthAuthority({
        walletId: runtime.walletId,
        provider: runtime.factor.provider,
        providerUserId: runtime.factor.providerSubjectId,
        emailHashHex: runtime.factor.emailHashHex,
      });
    default:
      runtime.factor satisfies never;
      throw new Error('[WarmSessionStore] unsupported Ed25519 runtime factor');
  }
}

async function ed25519AuthorizationMatchesRuntime(args: {
  runtime: ExactEd25519SealedSessionRuntime;
  authorization: ActiveWalletSessionAuthorizationProjection;
}): Promise<boolean> {
  const runtime = args.runtime;
  const authorization = args.authorization;
  if (
    String(authorization.walletId) !== String(runtime.walletId) ||
    authorization.authMethod !== runtime.factor.kind
  ) {
    return false;
  }
  if (!ed25519AuthorizationIdentityMatchesRuntime({ runtime, authorization })) return false;
  try {
    const authority = ed25519WalletAuthAuthority(runtime);
    const expected = await walletAuthAuthorityRef({ authority });
    return expected.authorityDigest === authorization.authority.authorityDigest;
  } catch {
    return false;
  }
}

export type WarmSessionStatusReaderDeps = {
  touchConfirm?: WarmSessionReadPortsInput;
  getEmailOtpWarmSessionStatus: (
    target: EmailOtpWarmMaterialTarget,
  ) => Promise<WarmSessionStatusResult>;
};

export type WarmSigningStatusReader = ThresholdWarmSessionStatusReader & {
  readEd25519WarmSessionClaim: (
    runtime: ExactEd25519SealedSessionRuntime,
  ) => Promise<WarmSessionPrfClaim | null>;
};

export function createWarmSessionStatusReader(
  deps: WarmSessionStatusReaderDeps,
): WarmSigningStatusReader {
  const touchConfirm = normalizeWarmSessionReadPorts(deps.touchConfirm);

  async function readEd25519WarmSessionClaim(
    runtime: ExactEd25519SealedSessionRuntime,
  ): Promise<WarmSessionPrfClaim | null> {
    const thresholdSessionId = String(runtime.thresholdSessionId);
    return await readEd25519WarmSessionClaimByMethod({
      authMethod: runtime.factor.kind,
      thresholdSessionId,
      materialActivation: runtime.sealedRecord.ed25519Restore.materialActivation,
    });
  }

  async function readEd25519WarmSessionClaimByMethod(args: {
    authMethod: SignerAuthMethod;
    thresholdSessionId: string;
    materialActivation: ExactEd25519SealedSessionRuntime['sealedRecord']['ed25519Restore']['materialActivation'];
  }): Promise<WarmSessionPrfClaim | null> {
    if (args.authMethod === SIGNER_AUTH_METHODS.emailOtp) {
      const status = await deps
        .getEmailOtpWarmSessionStatus({
          kind: 'ed25519_yao',
          thresholdSessionId: args.thresholdSessionId,
          materialActivation: args.materialActivation,
        })
        .catch(() => ({
          ok: false as const,
          code: 'worker_error',
          message: 'worker_error',
        }));
      return toWarmSessionClaimFromStatusResult({
        thresholdSessionId: args.thresholdSessionId,
        status,
      });
    }
    return await readWarmSessionClaim(touchConfirm, args.thresholdSessionId);
  }

  async function getEd25519SigningSessionStatus(args: {
    runtime: ExactEd25519SealedSessionRuntime;
    authorization: ActiveWalletSessionAuthorizationProjection | null;
    nowMs: number;
  }): Promise<SigningSessionStatus> {
    const runtime = args.runtime;
    const thresholdSessionId = String(runtime.thresholdSessionId);
    const metadata = ed25519SessionMetadata(runtime);
    if (
      !args.authorization ||
      !(await ed25519AuthorizationMatchesRuntime({
        runtime,
        authorization: args.authorization,
      }))
    ) {
      return {
        sessionId: thresholdSessionId,
        status: 'unavailable',
        statusCode: 'auth_missing',
        ...metadata,
      };
    }
    if (args.authorization.expiresAtMs <= args.nowMs || runtime.expiresAtMs <= args.nowMs) {
      return {
        sessionId: thresholdSessionId,
        status: 'expired',
        expiresAtMs: Math.min(
          args.authorization.expiresAtMs,
          runtime.expiresAtMs,
        ),
        ...metadata,
      };
    }
    if (runtime.remainingUses <= 0) {
      return {
        sessionId: thresholdSessionId,
        status: 'exhausted',
        remainingUses: 0,
        expiresAtMs: runtime.expiresAtMs,
        ...metadata,
      };
    }
    const claim = await readEd25519WarmSessionClaim(runtime);
    const status = toSigningSessionStatus({
      sessionId: thresholdSessionId,
      claim,
      authMethod: metadata.authMethod,
      retention: metadata.retention ?? null,
    });
    if (status.status === 'not_found') {
      return {
        sessionId: thresholdSessionId,
        status: 'active',
        remainingUses: runtime.remainingUses,
        expiresAtMs: runtime.expiresAtMs,
        ...metadata,
      };
    }
    return status;
  }

  return {
    getEd25519SigningSessionStatus,
    readEd25519WarmSessionClaim,
  };
}
