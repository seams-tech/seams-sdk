import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthLane } from '../../emailOtp/authLane';
import type { ThresholdSessionSealTransportAuthMaterial } from '../../api/thresholdLifecycle/thresholdSessionStore';
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
import type { ThresholdEcdsaChainTarget } from '../signingSession/ecdsaChainTarget';
import type {
  WarmSessionEcdsaAuthMaterial,
  WarmSessionEcdsaCapabilityState,
  WarmSessionEd25519AuthMaterial,
  WarmSessionEd25519CapabilityState,
  WarmSessionEnvelope,
} from './types';
import type { WarmSessionStatusReader } from './statusReader';

export type WarmSessionCapabilityReaderCoreDeps = {
  touchConfirm?: WarmSessionReadPorts;
  statusReader: Pick<
    WarmSessionStatusReader,
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
        ed25519: {
          capability: 'ed25519',
          record: records.ed25519,
          auth: ed25519Auth,
          prfClaim: ed25519Claim,
          state: deriveEd25519CapabilityState({
            record: records.ed25519,
            auth: ed25519Auth,
            prfClaim: ed25519Claim,
            emailOtpAuthContext: records.ed25519?.emailOtpAuthContext || null,
          }),
          ...(records.ed25519?.emailOtpAuthContext
            ? { emailOtpAuthContext: records.ed25519.emailOtpAuthContext }
            : {}),
        },
        ecdsa: {
          evm: {
            capability: 'ecdsa',
            record: records.ecdsa.evm,
            auth: evmAuth,
            prfClaim: evmClaim,
            ...(records.ecdsa.evm?.emailOtpAuthContext
              ? { emailOtpAuthContext: records.ecdsa.evm.emailOtpAuthContext }
              : {}),
            state: deriveEcdsaCapabilityState({
              record: records.ecdsa.evm,
              auth: evmAuth,
              prfClaim: evmClaim,
              emailOtpAuthContext: records.ecdsa.evm?.emailOtpAuthContext || null,
            }),
          },
          tempo: {
            capability: 'ecdsa',
            record: records.ecdsa.tempo,
            auth: tempoAuth,
            prfClaim: tempoClaim,
            ...(records.ecdsa.tempo?.emailOtpAuthContext
              ? { emailOtpAuthContext: records.ecdsa.tempo.emailOtpAuthContext }
              : {}),
            state: deriveEcdsaCapabilityState({
              record: records.ecdsa.tempo,
              auth: tempoAuth,
              prfClaim: tempoClaim,
              emailOtpAuthContext: records.ecdsa.tempo?.emailOtpAuthContext || null,
            }),
          },
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
      const jwt = String(record?.thresholdSessionJwt || '').trim();
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
    const jwt = String(record?.thresholdSessionJwt || '').trim();
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
    return {
      capability: 'ed25519',
      record,
      auth,
      prfClaim,
      state: deriveEd25519CapabilityState({
        record,
        auth,
        prfClaim,
        emailOtpAuthContext: record.emailOtpAuthContext || null,
      }),
      ...(record.emailOtpAuthContext ? { emailOtpAuthContext: record.emailOtpAuthContext } : {}),
    };
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
    return {
      capability: 'ecdsa',
      record,
      auth,
      prfClaim,
      state: deriveEcdsaCapabilityState({
        record,
        auth,
        prfClaim,
        emailOtpAuthContext: record.emailOtpAuthContext || null,
      }),
      ...(record.emailOtpAuthContext ? { emailOtpAuthContext: record.emailOtpAuthContext } : {}),
    };
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
