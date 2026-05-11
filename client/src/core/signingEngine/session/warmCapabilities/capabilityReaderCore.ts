import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ThresholdSessionSealTransportAuthMaterial } from '../persistence/records';
import {
  readWarmSessionCapabilityRecordsForAccount,
  readWarmSessionEcdsaRecordByThresholdSessionIdForTarget,
  readWarmSessionEcdsaRecordByThresholdSessionId,
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
import { assertWarmSessionEnvelopeInvariant } from './types';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  WarmSessionEcdsaAuthMaterial,
  WarmSessionEcdsaCapabilityState,
  WarmSessionEd25519AuthMaterial,
  WarmSessionEd25519CapabilityState,
  WarmSessionEnvelope,
} from './types';
import type { WarmSigningStatusReader } from './statusReader';

export type WarmSessionCapabilityReaderCoreDeps = {
  touchConfirm?: WarmSessionReadPorts;
  statusReader: Pick<
    WarmSigningStatusReader,
    'readWalletScopedClaimsForRecords' | 'readEcdsaWarmSessionClaimForRecord'
  >;
  signingSessionSeal?: {
    keyVersion?: string;
    shamirPrimeB64u?: string;
  };
};

export type WarmSessionCapabilityReaderCore = {
  getWarmSession: (nearAccountId: AccountId | string) => Promise<WarmSessionEnvelope>;
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
  resolveEmailOtpSigningSessionAuthLane: (args: {
    thresholdSessionId: string;
    curve: 'ed25519' | 'ecdsa';
  }) => EmailOtpAuthLane | null;
  getEd25519CapabilityByThresholdSessionId: (
    thresholdSessionId: string,
  ) => Promise<WarmSessionEd25519CapabilityState | null>;
  getEcdsaCapabilityByThresholdSessionId: (
    thresholdSessionId: string,
  ) => Promise<WarmSessionEcdsaCapabilityState | null>;
  resolveEcdsaSealTransportByThresholdSessionId: (
    args: {
      thresholdSessionId: string;
      chainTarget: ThresholdEcdsaChainTarget;
    },
  ) => ThresholdSessionSealTransportAuthMaterial | null;
};

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
      throw new Error('[WarmSessionStore] Ed25519 capability state cannot be missing with a record');
    }
    if (args.record.source === 'email_otp') {
      if (!args.record.emailOtpAuthContext) {
        throw new Error(
          '[WarmSessionStore] Email OTP Ed25519 capability requires emailOtpAuthContext',
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
        auth: null,
        prfClaim: null,
        state: 'missing',
      };
    }
    if (state === 'missing') {
      throw new Error('[WarmSessionStore] ECDSA capability state cannot be missing with a record');
    }
    if (args.record.source === 'email_otp') {
      if (!args.record.emailOtpAuthContext) {
        throw new Error(
          '[WarmSessionStore] Email OTP ECDSA capability requires emailOtpAuthContext',
        );
      }
      return {
        capability: 'ecdsa',
        record: args.record,
        auth: args.auth,
        prfClaim: args.prfClaim,
        emailOtpAuthContext: args.record.emailOtpAuthContext,
        state,
      };
    }
    return {
      capability: 'ecdsa',
      record: args.record,
      auth: args.auth,
      prfClaim: args.prfClaim,
      state,
    };
  }

  async function getWarmSession(nearAccountId: AccountId | string): Promise<WarmSessionEnvelope> {
    const accountId = toAccountId(nearAccountId);
    const records = readWarmSessionCapabilityRecordsForAccount(accountId);

    const ed25519Auth = resolveEd25519AuthMaterial(records.ed25519);
    const evmAuth = resolveEcdsaAuthMaterial(records.ecdsa.evm);
    const tempoAuth = resolveEcdsaAuthMaterial(records.ecdsa.tempo);

    const { ed25519Claim, evmClaim, tempoClaim } =
      await deps.statusReader.readWalletScopedClaimsForRecords(accountId, records);

    return assertWarmSessionEnvelopeInvariant({
      accountId,
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

  function resolveEmailOtpSigningSessionAuthLane(args: {
    thresholdSessionId: string;
    curve: 'ed25519' | 'ecdsa';
  }): EmailOtpAuthLane | null {
    const thresholdSessionId = String(args.thresholdSessionId || '').trim();
    if (!thresholdSessionId) return null;
    if (args.curve === 'ed25519') {
      const record = readWarmSessionEd25519RecordByThresholdSessionId(thresholdSessionId);
      const jwt = String(record?.thresholdSessionAuthToken || '').trim();
      const walletSigningSessionId = String(record?.walletSigningSessionId || '').trim();
      if (record?.source !== 'email_otp' || !jwt || !walletSigningSessionId) return null;
      return {
        kind: 'signing_session',
        jwt,
        thresholdSessionId,
        walletSigningSessionId,
        curve: 'ed25519',
      };
    }
    const record = readWarmSessionEcdsaRecordByThresholdSessionId(thresholdSessionId);
    const jwt = String(record?.thresholdSessionAuthToken || '').trim();
    const walletSigningSessionId = String(record?.walletSigningSessionId || '').trim();
    if (record?.source !== 'email_otp' || !jwt || !walletSigningSessionId) return null;
    return {
      kind: 'signing_session',
      jwt,
      thresholdSessionId,
      walletSigningSessionId,
      curve: 'ecdsa',
      chainTarget: record.chainTarget,
    };
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

  function resolveEcdsaSealTransportByThresholdSessionId(args: {
    thresholdSessionId: string;
    chainTarget: ThresholdEcdsaChainTarget;
  }): ThresholdSessionSealTransportAuthMaterial | null {
    const record = readWarmSessionEcdsaRecordByThresholdSessionIdForTarget(args);
    if (!record) return null;
    const auth = resolveEcdsaAuthMaterial(record);
    return resolveEcdsaSealTransport({
      record,
      auth,
      keyVersion: String(
        record.signingSessionSealKeyVersion || deps.signingSessionSeal?.keyVersion || '',
      ).trim(),
      shamirPrimeB64u: String(
        record.signingSessionSealShamirPrimeB64u || deps.signingSessionSeal?.shamirPrimeB64u || '',
      ).trim(),
    });
  }

  return {
    getWarmSession,
    resolveEd25519RecordByThresholdSessionId,
    resolveEcdsaRecordByThresholdSessionId,
    resolveEd25519AuthByThresholdSessionId,
    resolveEcdsaAuthByThresholdSessionId,
    resolveEmailOtpSigningSessionAuthLane,
    getEd25519CapabilityByThresholdSessionId,
    getEcdsaCapabilityByThresholdSessionId,
    resolveEcdsaSealTransportByThresholdSessionId,
  };
}
