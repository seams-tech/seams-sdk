import { resolveEmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import {
  buildEmailOtpEcdsaSigningSessionAuthority,
  type EmailOtpEcdsaSigningSessionAuthority,
} from '../emailOtp/ecdsaSigningSessionAuthority';
import {
  buildEmailOtpEd25519SigningSessionAuthority,
  type EmailOtpEd25519SigningSessionAuthority,
} from '../emailOtp/ed25519SigningSessionAuthority';
import { emailOtpAuthContextProviderUserId, selectedEcdsaLane } from '../identity/laneIdentity';
import {
  toExactEcdsaSigningLaneIdentity,
  thresholdEcdsaLaneCandidateFromSessionRecord,
  thresholdEcdsaSessionRecordReadModel,
  type ThresholdSessionSealTransportAuthMaterial,
} from '../persistence/records';
import {
  exactSigningLaneIdentityMatches,
  type ExactEcdsaSigningLaneIdentity,
  type ExactEd25519SigningLaneIdentity,
} from '../identity/exactSigningLaneIdentity';
import {
  readWarmSessionCapabilityRecordsForWallet,
  readWarmSessionEcdsaRecordByThresholdSessionId,
  readWarmSessionEd25519RecordForAccount,
  readWarmSessionEd25519RecordByThresholdSessionId,
} from './store';
import {
  deriveEcdsaCapabilityState,
  deriveEd25519CapabilityState,
  readWarmSessionClaim,
  resolveEcdsaAuthMaterial,
  resolveEcdsaSealTransport,
  resolveEd25519AuthMaterial,
  type WarmSessionReadPorts,
} from './readModel';
import { tryBuildEcdsaSessionIdentity } from './ecdsaProvisionPlan';
import { assertWarmSessionEnvelopeInvariant } from './types';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  parseSigningSessionSealKeyVersion,
  type SigningSessionSealKeyVersion,
} from '../keyMaterialBrands';
import type {
  WarmSessionEcdsaAuthMaterial,
  WarmSessionEcdsaCapabilityState,
  WarmSessionEd25519AuthMaterial,
  WarmSessionEd25519CapabilityState,
  WarmSessionEnvelope,
} from './types';
import type { WarmSigningStatusReader } from './statusReader';
import type { AccountId } from '@/core/types/accountIds';

export type WarmSessionCapabilityReaderSealConfigured = {
  seal: 'configured';
  signingSessionSealKeyVersion: SigningSessionSealKeyVersion;
  shamirPrimeB64u: string;
};

export type WarmSessionCapabilityReaderSealUnavailable = {
  seal: 'unconfigured';
  signingSessionSealKeyVersion?: never;
  shamirPrimeB64u?: never;
};

export type WarmSessionCapabilityReaderSeal =
  | WarmSessionCapabilityReaderSealConfigured
  | WarmSessionCapabilityReaderSealUnavailable;

export type WarmSessionCapabilityReaderCoreDeps = {
  touchConfirm: WarmSessionReadPorts | null;
  statusReader: Pick<
    WarmSigningStatusReader,
    | 'readWalletScopedClaimsForRecords'
    | 'readEcdsaWarmSessionClaimForRecord'
    | 'resolveExactEcdsaRecord'
  >;
  signingSessionSeal: WarmSessionCapabilityReaderSeal;
};

export type WarmSessionCapabilityReaderCore = {
  getWarmSession: (walletId: WalletId) => Promise<WarmSessionEnvelope>;
  getEd25519CapabilityForNearAccount: (
    nearAccountId: AccountId,
  ) => Promise<WarmSessionEd25519CapabilityState | null>;
  resolveEd25519RecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => WarmSessionEd25519CapabilityState['record'];
  resolveEcdsaRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => WarmSessionEcdsaCapabilityState['record'];
  resolveEd25519AuthByThresholdSessionId: (
    thresholdSessionId: string,
  ) => WarmSessionEd25519AuthMaterial | null;
  resolveEcdsaAuthByThresholdSessionId: (
    thresholdSessionId: string,
  ) => WarmSessionEcdsaAuthMaterial | null;
  resolveEmailOtpEd25519SigningSessionAuthority: (args: {
    lane: ExactEd25519SigningLaneIdentity;
  }) => EmailOtpEd25519SigningSessionAuthority | null;
  resolveEmailOtpEcdsaSigningSessionAuthority: (args: {
    lane: ExactEcdsaSigningLaneIdentity;
  }) => EmailOtpEcdsaSigningSessionAuthority | null;
  getEd25519CapabilityByThresholdSessionId: (
    thresholdSessionId: string,
  ) => Promise<WarmSessionEd25519CapabilityState | null>;
  getEcdsaCapabilityByThresholdSessionId: (
    thresholdSessionId: string,
  ) => Promise<WarmSessionEcdsaCapabilityState | null>;
  getEcdsaCapabilityForLane: (
    lane: ExactEcdsaSigningLaneIdentity,
  ) => Promise<WarmSessionEcdsaCapabilityState | null>;
  resolveEcdsaSealTransportByThresholdSessionId: (args: {
    lane: ExactEcdsaSigningLaneIdentity;
  }) => ThresholdSessionSealTransportAuthMaterial | null;
};

async function getEd25519CapabilityForNearAccount(
  getByThresholdSessionId: WarmSessionCapabilityReaderCore['getEd25519CapabilityByThresholdSessionId'],
  nearAccountId: AccountId,
): Promise<WarmSessionEd25519CapabilityState | null> {
  const record = readWarmSessionEd25519RecordForAccount(nearAccountId);
  if (!record) return null;
  return await getByThresholdSessionId(record.thresholdSessionId);
}

function recordOwnedEd25519WalletSessionJwt(
  auth: WarmSessionEd25519AuthMaterial | null,
): string | null {
  if (!auth || auth.walletSessionJwtSource !== 'ed25519_record') return null;
  return String(auth.walletSessionJwt || '').trim() || null;
}

function recordOwnedEcdsaWalletSessionJwt(
  auth: WarmSessionEcdsaAuthMaterial | null,
): string | null {
  if (!auth || auth.state !== 'ready' || auth.walletSessionJwtSource !== 'ecdsa_record') {
    return null;
  }
  return String(auth.walletSessionJwt || '').trim() || null;
}

export function createWarmSessionCapabilityReaderCore(
  deps: WarmSessionCapabilityReaderCoreDeps,
): WarmSessionCapabilityReaderCore {
  function buildEd25519CapabilityState(args: {
    record: WarmSessionEd25519CapabilityState['record'];
    auth: WarmSessionEd25519AuthMaterial | null;
    prfClaim: WarmSessionEd25519CapabilityState['prfClaim'];
  }): WarmSessionEd25519CapabilityState {
    const state = deriveEd25519CapabilityState(args);
    if (!args.record) {
      return {
        capability: 'ed25519',
        record: null,
        auth: null,
        prfClaim: null,
        state: 'missing',
      };
    }
    if (state === 'missing') {
      throw new Error(
        '[WarmSessionStore] Ed25519 capability state cannot be missing with a record',
      );
    }
    if (args.record.source === 'email_otp') {
      if (!args.record.emailOtpAuthContext) {
        throw new Error(
          '[WarmSessionStore] Email OTP Ed25519 capability requires emailOtpAuthContext',
        );
      }
      if (state === 'auth_missing') {
        return {
          capability: 'ed25519',
          record: args.record,
          auth: args.auth?.walletSessionJwtSource === 'none' ? args.auth : null,
          prfClaim: args.prfClaim,
          emailOtpAuthContext: args.record.emailOtpAuthContext,
          state,
        };
      }
      if (!args.auth || args.auth.walletSessionJwtSource !== 'ed25519_record') {
        throw new Error(
          `[WarmSessionStore] Ed25519 capability state=${state} requires Wallet Session JWT auth`,
        );
      }
      return {
        capability: 'ed25519',
        record: args.record,
        auth: args.auth,
        prfClaim: args.prfClaim,
        emailOtpAuthContext: args.record.emailOtpAuthContext,
        state,
      };
    }
    if (state === 'auth_missing') {
      return {
        capability: 'ed25519',
        record: args.record,
        auth: args.auth?.walletSessionJwtSource === 'none' ? args.auth : null,
        prfClaim: args.prfClaim,
        state,
      };
    }
    if (!args.auth || args.auth.walletSessionJwtSource !== 'ed25519_record') {
      throw new Error(
        `[WarmSessionStore] Ed25519 capability state=${state} requires Wallet Session JWT auth`,
      );
    }
    return {
      capability: 'ed25519',
      record: args.record,
      auth: args.auth,
      prfClaim: args.prfClaim,
      state,
    };
  }

  function buildEcdsaCapabilityState(args: {
    record: WarmSessionEcdsaCapabilityState['record'];
    auth: WarmSessionEcdsaAuthMaterial | null;
    prfClaim: WarmSessionEcdsaCapabilityState['prfClaim'];
  }): WarmSessionEcdsaCapabilityState {
    const state = deriveEcdsaCapabilityState(args);
    if (!args.record) {
      return {
        capability: 'ecdsa',
        record: null,
        key: null,
        lane: null,
        auth: null,
        prfClaim: null,
        state: 'missing',
      };
    }
    if (state === 'missing') {
      throw new Error('[WarmSessionStore] ECDSA capability state cannot be missing with a record');
    }
    const key = thresholdEcdsaSessionRecordReadModel(args.record).key;
    const candidate = thresholdEcdsaLaneCandidateFromSessionRecord({ record: args.record });
    const lane = selectedEcdsaLane({
      key,
      keyHandle: args.record.keyHandle,
      walletId: args.record.walletId,
      auth: candidate.auth,
      signingGrantId: args.record.signingGrantId,
      thresholdSessionId: args.record.thresholdSessionId,
      chainTarget: args.record.chainTarget,
    });

    if (args.record.source === 'email_otp') {
      if (!args.record.emailOtpAuthContext) {
        throw new Error(
          '[WarmSessionStore] Email OTP ECDSA capability requires emailOtpAuthContext',
        );
      }
      if (state === 'auth_missing') {
        return {
          capability: 'ecdsa',
          record: args.record,
          key,
          lane,
          auth: args.auth?.state === 'unavailable' ? args.auth : null,
          prfClaim: args.prfClaim,
          emailOtpAuthContext: args.record.emailOtpAuthContext,
          state,
        };
      }
      if (!args.auth || args.auth.state !== 'ready') {
        throw new Error(
          `[WarmSessionStore] ECDSA capability state=${state} requires Wallet Session JWT auth`,
        );
      }
      if (state === 'ready' || state === 'material_pending') {
        if (!args.prfClaim || args.prfClaim.state !== 'warm') {
          throw new Error(
            `[WarmSessionStore] ECDSA capability state=${state} requires a warm PRF claim`,
          );
        }
        return {
          capability: 'ecdsa',
          record: args.record,
          key,
          lane,
          auth: args.auth,
          prfClaim: args.prfClaim,
          emailOtpAuthContext: args.record.emailOtpAuthContext,
          state,
        };
      }
      return {
        capability: 'ecdsa',
        record: args.record,
        key,
        lane,
        auth: args.auth,
        prfClaim: args.prfClaim,
        emailOtpAuthContext: args.record.emailOtpAuthContext,
        state,
      };
    }
    if (state === 'auth_missing') {
      return {
        capability: 'ecdsa',
        record: args.record,
        key,
        lane,
        auth: args.auth?.state === 'unavailable' ? args.auth : null,
        prfClaim: args.prfClaim,
        state,
      };
    }
    if (!args.auth || args.auth.state !== 'ready') {
      throw new Error(
        `[WarmSessionStore] ECDSA capability state=${state} requires Wallet Session JWT auth`,
      );
    }
    if (state === 'ready' || state === 'material_pending') {
      if (!args.prfClaim || args.prfClaim.state !== 'warm') {
        throw new Error(
          `[WarmSessionStore] ECDSA capability state=${state} requires a warm PRF claim`,
        );
      }
      return {
        capability: 'ecdsa',
        record: args.record,
        key,
        lane,
        auth: args.auth,
        prfClaim: args.prfClaim,
        state,
      };
    }
    return {
      capability: 'ecdsa',
      record: args.record,
      key,
      lane,
      auth: args.auth,
      prfClaim: args.prfClaim,
      state,
    };
  }

  async function getWarmSession(walletId: WalletId): Promise<WarmSessionEnvelope> {
    const normalizedWalletId = toWalletId(walletId);
    const records = readWarmSessionCapabilityRecordsForWallet(normalizedWalletId);

    const ed25519Auth = resolveEd25519AuthMaterial(records.ed25519);
    const evmAuth = resolveEcdsaAuthMaterial(records.ecdsa.evm);
    const tempoAuth = resolveEcdsaAuthMaterial(records.ecdsa.tempo);

    const { ed25519Claim, evmClaim, tempoClaim } =
      await deps.statusReader.readWalletScopedClaimsForRecords(records);

    return assertWarmSessionEnvelopeInvariant({
      walletId: normalizedWalletId,
      capabilities: {
        ed25519: buildEd25519CapabilityState({
          record: records.ed25519,
          auth: ed25519Auth,
          prfClaim: ed25519Claim,
        }),
        ecdsa: {
          evm: buildEcdsaCapabilityState({
            record: records.ecdsa.evm,
            auth: evmAuth,
            prfClaim: evmClaim,
          }),
          tempo: buildEcdsaCapabilityState({
            record: records.ecdsa.tempo,
            auth: tempoAuth,
            prfClaim: tempoClaim,
          }),
        },
      },
      updatedAtMs: Date.now(),
    });
  }

  function resolveEd25519RecordByThresholdSessionId(
    thresholdSessionId: string,
  ): WarmSessionEd25519CapabilityState['record'] {
    return readWarmSessionEd25519RecordByThresholdSessionId(thresholdSessionId);
  }

  function resolveEcdsaRecordByThresholdSessionId(
    thresholdSessionId: string,
  ): WarmSessionEcdsaCapabilityState['record'] {
    return readWarmSessionEcdsaRecordByThresholdSessionId(thresholdSessionId);
  }

  function resolveEd25519AuthByThresholdSessionId(
    thresholdSessionId: string,
  ): WarmSessionEd25519AuthMaterial | null {
    return resolveEd25519AuthMaterial(
      readWarmSessionEd25519RecordByThresholdSessionId(thresholdSessionId),
    );
  }

  function resolveEcdsaAuthByThresholdSessionId(
    thresholdSessionId: string,
  ): WarmSessionEcdsaAuthMaterial | null {
    const record = readWarmSessionEcdsaRecordByThresholdSessionId(thresholdSessionId);
    return record ? resolveEcdsaAuthMaterial(record) : null;
  }

  function ed25519RecordMatchesExactLane(args: {
    record: WarmSessionEd25519CapabilityState['record'];
    lane: ExactEd25519SigningLaneIdentity;
  }): boolean {
    const record = args.record;
    const lane = args.lane;
    const signer = lane.signer;
    if (!record) return false;
    if (record.source !== 'email_otp') return false;
    if (lane.auth.kind !== 'email_otp') return false;
    if (String(record.walletId || '').trim() !== String(signer.account.wallet.walletId)) {
      return false;
    }
    if (String(record.nearAccountId || '').trim() !== String(signer.account.nearAccountId)) {
      return false;
    }
    if (
      String(record.nearEd25519SigningKeyId || '').trim() !== String(signer.nearEd25519SigningKeyId)
    ) {
      return false;
    }
    if (String(record.signingGrantId || '').trim() !== String(lane.signingGrantId)) return false;
    if (String(record.thresholdSessionId || '').trim() !== String(lane.thresholdSessionId)) {
      return false;
    }
    if (!record.emailOtpAuthContext) return false;
    return (
      emailOtpAuthContextProviderUserId(record.emailOtpAuthContext) === lane.auth.providerSubjectId
    );
  }

  function ecdsaRecordMatchesExactLane(args: {
    record: WarmSessionEcdsaCapabilityState['record'];
    lane: ExactEcdsaSigningLaneIdentity;
  }): boolean {
    if (!args.record) return false;
    if (args.record.source !== 'email_otp' && args.lane.auth.kind === 'email_otp') return false;
    try {
      return exactSigningLaneIdentityMatches(
        toExactEcdsaSigningLaneIdentity(args.record),
        args.lane,
      );
    } catch {
      return false;
    }
  }

  function resolveEmailOtpEd25519SigningSessionAuthority(args: {
    lane: ExactEd25519SigningLaneIdentity;
  }): EmailOtpEd25519SigningSessionAuthority | null {
    const thresholdSessionId = String(args.lane.thresholdSessionId || '').trim();
    if (!thresholdSessionId) return null;
    if (args.lane.auth.kind !== 'email_otp') return null;
    const record = readWarmSessionEd25519RecordByThresholdSessionId(thresholdSessionId);
    if (!ed25519RecordMatchesExactLane({ record, lane: args.lane })) return null;
    const auth = resolveEd25519AuthMaterial(record);
    const jwt = recordOwnedEd25519WalletSessionJwt(auth);
    if (record?.source !== 'email_otp' || !jwt || !record.emailOtpAuthContext) return null;
    const lane = resolveEmailOtpAuthLane({
      routeAuth: { kind: 'wallet_session', jwt },
      thresholdSessionId,
      authorizingSigningGrantId: record.signingGrantId,
      curve: 'ed25519',
    });
    return buildEmailOtpEd25519SigningSessionAuthority({
      authLane: lane,
      authority: record.emailOtpAuthContext.authority,
    });
  }

  function resolveEmailOtpEcdsaSigningSessionAuthority(args: {
    lane: ExactEcdsaSigningLaneIdentity;
  }): EmailOtpEcdsaSigningSessionAuthority | null {
    const thresholdSessionId = String(args.lane.thresholdSessionId || '').trim();
    if (!thresholdSessionId) return null;
    if (args.lane.auth.kind !== 'email_otp') return null;
    const record = readWarmSessionEcdsaRecordByThresholdSessionId(thresholdSessionId);
    if (!ecdsaRecordMatchesExactLane({ record, lane: args.lane })) return null;
    const auth = resolveEcdsaAuthMaterial(record);
    const jwt = recordOwnedEcdsaWalletSessionJwt(auth);
    const identity = record ? tryBuildEcdsaSessionIdentity(record) : null;
    if (record?.source !== 'email_otp' || !jwt || !identity) return null;
    const lane = resolveEmailOtpAuthLane({
      routeAuth: { kind: 'wallet_session', jwt },
      thresholdSessionId: identity.thresholdSessionId,
      authorizingSigningGrantId: identity.signingGrantId,
      curve: 'ecdsa',
      chainTarget: args.lane.signer.chainTarget,
    });
    return buildEmailOtpEcdsaSigningSessionAuthority({
      authLane: lane,
      authority: record.emailOtpAuthContext.authority,
    });
  }

  async function getEd25519CapabilityByThresholdSessionId(
    thresholdSessionId: string,
  ): Promise<WarmSessionEd25519CapabilityState | null> {
    const record = readWarmSessionEd25519RecordByThresholdSessionId(thresholdSessionId);
    if (!record) return null;
    const auth = resolveEd25519AuthMaterial(record);
    const prfClaim = await readWarmSessionClaim(deps.touchConfirm, record.thresholdSessionId);
    return buildEd25519CapabilityState({ record, auth, prfClaim });
  }

  async function getEcdsaCapabilityByThresholdSessionId(
    thresholdSessionIdRaw: string,
  ): Promise<WarmSessionEcdsaCapabilityState | null> {
    const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
    if (!thresholdSessionId) return null;
    const record = readWarmSessionEcdsaRecordByThresholdSessionId(thresholdSessionId);
    if (!record) return null;
    const auth = resolveEcdsaAuthMaterial(record);
    const prfClaim = await deps.statusReader.readEcdsaWarmSessionClaimForRecord(record);
    return buildEcdsaCapabilityState({ record, auth, prfClaim });
  }

  async function getEcdsaCapabilityForLane(
    lane: ExactEcdsaSigningLaneIdentity,
  ): Promise<WarmSessionEcdsaCapabilityState | null> {
    const exactRecord = deps.statusReader.resolveExactEcdsaRecord({ lane });
    if (exactRecord.kind !== 'found') return null;
    const record = exactRecord.record;
    const auth = resolveEcdsaAuthMaterial(record);
    const prfClaim = await deps.statusReader.readEcdsaWarmSessionClaimForRecord(record);
    return buildEcdsaCapabilityState({ record, auth, prfClaim });
  }

  function resolveEcdsaSealTransportByThresholdSessionId(args: {
    lane: ExactEcdsaSigningLaneIdentity;
  }): ThresholdSessionSealTransportAuthMaterial | null {
    const exactRecord = deps.statusReader.resolveExactEcdsaRecord({
      lane: args.lane,
    });
    if (exactRecord.kind !== 'found') return null;
    const record = exactRecord.record;
    if (!record) return null;
    const auth = resolveEcdsaAuthMaterial(record);
    const fallbackSigningSessionSealKeyVersion =
      deps.signingSessionSeal.seal === 'configured'
        ? deps.signingSessionSeal.signingSessionSealKeyVersion
        : undefined;
    const fallbackShamirPrimeB64u =
      deps.signingSessionSeal.seal === 'configured' ? deps.signingSessionSeal.shamirPrimeB64u : '';
    return resolveEcdsaSealTransport({
      record,
      auth,
      signingSessionSealKeyVersion: record.signingSessionSealKeyVersion
        ? parseSigningSessionSealKeyVersion(record.signingSessionSealKeyVersion)
        : fallbackSigningSessionSealKeyVersion,
      shamirPrimeB64u: String(
        record.signingSessionSealShamirPrimeB64u || fallbackShamirPrimeB64u,
      ).trim(),
    });
  }

  return {
    getWarmSession,
    getEd25519CapabilityForNearAccount: getEd25519CapabilityForNearAccount.bind(
      null,
      getEd25519CapabilityByThresholdSessionId,
    ),
    resolveEd25519RecordByThresholdSessionId,
    resolveEcdsaRecordByThresholdSessionId,
    resolveEd25519AuthByThresholdSessionId,
    resolveEcdsaAuthByThresholdSessionId,
    resolveEmailOtpEd25519SigningSessionAuthority,
    resolveEmailOtpEcdsaSigningSessionAuthority,
    getEd25519CapabilityByThresholdSessionId,
    getEcdsaCapabilityByThresholdSessionId,
    getEcdsaCapabilityForLane,
    resolveEcdsaSealTransportByThresholdSessionId,
  };
}
