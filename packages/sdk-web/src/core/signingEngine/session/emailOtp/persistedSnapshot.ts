import { chainFamilyFromNetwork } from '@/core/config/chains';
import { toAccountId } from '@/core/types/accountIds';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import {
  thresholdEcdsaChainTargetFromConfig,
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget,
  listStoredThresholdEd25519SessionRecordsForAccount,
  listThresholdEcdsaRuntimeLanesForWallet,
} from '@/core/signingEngine/session/persistence/records';
import type { listExactSealedSessionsForWallet } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  ed25519AvailableLaneIdentityKey,
  readAvailableSigningLanes,
  runtimeEcdsaRecordClaimKey,
  warmStatusToAvailableSigningLanesRuntimeClaim,
  type AvailableSigningLanes,
  type AvailableSigningLanesRuntimeClaim,
  type AvailableSigningLanesRuntimeEcdsaRecord,
  type AvailableSigningLanesRuntimeEd25519Record,
  type ReadAvailableSigningLanesInput,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import { resolveEmailOtpEcdsaWorkerSessionId } from '@/core/signingEngine/session/availability/readiness';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/types';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';

export type EmailOtpPersistedSessionSnapshotPorts = {
  configs: SeamsConfigsReadonly;
  listExactSealedSessionsForWallet: typeof listExactSealedSessionsForWallet;
  readWarmSessionStatusOnly: (sessionId: string) => Promise<WarmSessionStatusResult>;
};

function runtimeEcdsaRecordBoundaryKey(
  record: AvailableSigningLanesRuntimeEcdsaRecord,
): string | null {
  const verifiedPublicFacts = record.verifiedPublicFacts;
  if (!verifiedPublicFacts) return null;
  const keyHandle = String(verifiedPublicFacts.keyHandle || '').trim();
  const thresholdOwnerAddress = String(verifiedPublicFacts.thresholdOwnerAddress || '')
    .trim()
    .toLowerCase();
  const participantIds = verifiedPublicFacts.participantIds
    .map((participantId) => Number(participantId))
    .join(',');
  const publicKeyB64u = String(verifiedPublicFacts.publicKeyB64u || '').trim();
  if (!keyHandle || !thresholdOwnerAddress || !publicKeyB64u || !participantIds) return null;
  return [
    record.authMethod,
    record.curve,
    thresholdEcdsaChainTargetKey(record.chainTarget),
    record.key.walletId,
    keyHandle,
    thresholdOwnerAddress,
    participantIds,
    publicKeyB64u,
    record.signingGrantId,
    record.thresholdSessionId,
  ]
    .map((part) => String(part))
    .join(':');
}

export function configuredEmailOtpEcdsaSnapshotChainTargets(
  configs: SeamsConfigsReadonly,
): ThresholdEcdsaChainTarget[] {
  const targets: ThresholdEcdsaChainTarget[] = [];
  const seen = new Set<string>();
  for (const chain of configs.network.chains) {
    const family = chainFamilyFromNetwork(chain.network);
    if (family !== 'evm' && family !== 'tempo') continue;
    const chainTarget = thresholdEcdsaChainTargetFromConfig(chain);
    const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
    if (seen.has(targetKey)) continue;
    seen.add(targetKey);
    targets.push(chainTarget);
  }
  if (!targets.length) {
    throw new Error('[EmailOtpSession] exact ECDSA snapshot requires configured ECDSA targets');
  }
  return targets;
}

export async function readEmailOtpPersistedSessionSnapshot(
  args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'>,
  ports: EmailOtpPersistedSessionSnapshotPorts,
): Promise<AvailableSigningLanes> {
  const accountId = String(toAccountId(args.walletId) || '').trim();
  const listRecords =
    ports.configs.signing.sessionPersistenceMode === 'sealed_refresh_v1'
      ? ports.listExactSealedSessionsForWallet
      : async () => [];

  return await readAvailableSigningLanes(
    {
      ...args,
      walletId: accountId,
      ecdsaChainTargets: configuredEmailOtpEcdsaSnapshotChainTargets(ports.configs),
    },
    {
      listSealedRecordsForWallet: async ({ walletId: recordWalletId, filter }) => {
        const listByAuthMethod = async (authMethod: 'email_otp' | 'passkey') => {
          if (filter.curve === 'ecdsa') {
            return await listRecords({
              walletId: recordWalletId,
              filter: {
                authMethod,
                curve: 'ecdsa',
                chainTarget: filter.chainTarget,
              },
            });
          }
          return await listRecords({
            walletId: recordWalletId,
            filter: { authMethod, curve: 'ed25519' },
          });
        };
        if (filter.authMethod) {
          return await listByAuthMethod(filter.authMethod);
        }
        const [emailOtpRecords, passkeyRecords] = await Promise.all([
          listByAuthMethod('email_otp'),
          listByAuthMethod('passkey'),
        ]);
        return [...emailOtpRecords, ...passkeyRecords];
      },
      listRuntimeEcdsaLanesForWallet: async ({ walletId: recordWalletId }) => {
        const runtimeRecords: AvailableSigningLanesRuntimeEcdsaRecord[] = [];
        const seen = new Set<string>();
        for (const runtimeLane of listThresholdEcdsaRuntimeLanesForWallet(
          { recordsByLane: new Map() },
          recordWalletId,
        )) {
          if (runtimeLane.authMethod !== 'email_otp') continue;
          if (!runtimeLane.routerAbEcdsaHssNormalSigning) continue;
          const record: AvailableSigningLanesRuntimeEcdsaRecord = {
            key: runtimeLane.key,
            routerAbEcdsaHssNormalSigning: runtimeLane.routerAbEcdsaHssNormalSigning,
            keyHandle: runtimeLane.keyHandle,
            ...(runtimeLane.verifiedPublicFacts
              ? { verifiedPublicFacts: runtimeLane.verifiedPublicFacts }
              : {}),
            thresholdEcdsaPublicKeyB64u: runtimeLane.thresholdEcdsaPublicKeyB64u,
            authMethod: 'email_otp',
            curve: 'ecdsa',
            chainTarget: runtimeLane.chainTarget,
            thresholdSessionId: runtimeLane.thresholdSessionId,
            signingGrantId: runtimeLane.signingGrantId,
            ...(runtimeLane.remainingUses == null
              ? {}
              : { remainingUses: runtimeLane.remainingUses }),
            ...(runtimeLane.expiresAtMs == null ? {} : { expiresAtMs: runtimeLane.expiresAtMs }),
            ...(runtimeLane.updatedAtMs == null ? {} : { updatedAtMs: runtimeLane.updatedAtMs }),
          };
          const identityKey = runtimeEcdsaRecordBoundaryKey(record);
          if (!identityKey || seen.has(identityKey)) continue;
          seen.add(identityKey);
          runtimeRecords.push(record);
        }
        return runtimeRecords;
      },
      listRuntimeEd25519RecordsForAccount: async ({ accountId: recordAccountId }) => {
        const records: AvailableSigningLanesRuntimeEd25519Record[] = [];
        const seen = new Set<string>();
        const pushRecord = (record: AvailableSigningLanesRuntimeEd25519Record) => {
          const identityKey = ed25519AvailableLaneIdentityKey(record);
          if (!identityKey || seen.has(identityKey)) return;
          seen.add(identityKey);
          records.push(record);
        };
        for (const runtimeRecord of listStoredThresholdEd25519SessionRecordsForAccount(
          recordAccountId,
        )) {
          const authMethod =
            runtimeRecord.source === SIGNER_AUTH_METHODS.emailOtp ? 'email_otp' : 'passkey';
          if (args.authMethod && args.authMethod !== authMethod) continue;
          if (!runtimeRecord.routerAbNormalSigning) continue;
          pushRecord({
            authMethod,
            curve: 'ed25519',
            chain: 'near',
            routerAbNormalSigning: runtimeRecord.routerAbNormalSigning,
            thresholdSessionId: runtimeRecord.thresholdSessionId,
            signingGrantId: String(runtimeRecord.signingGrantId || '').trim(),
            remainingUses: runtimeRecord.remainingUses,
            expiresAtMs: runtimeRecord.expiresAtMs,
            updatedAtMs: runtimeRecord.updatedAtMs,
          });
        }
        return records;
      },
      readRuntimeEcdsaClaimsForRecords: async (runtimeRecords) => {
        const claims = new Map<string, AvailableSigningLanesRuntimeClaim | null>();
        await Promise.all(
          runtimeRecords.map(async (runtimeRecord) => {
            const claimKey = runtimeEcdsaRecordClaimKey(runtimeRecord);
            if (!claimKey) return;
            const sessionId = String(runtimeRecord.thresholdSessionId || '').trim();
            const storedRecord = getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget({
              thresholdSessionId: sessionId,
              chainTarget: runtimeRecord.chainTarget,
            });
            if (!storedRecord || storedRecord.source !== SIGNER_AUTH_METHODS.emailOtp) {
              claims.set(claimKey, null);
              return;
            }
            if (
              String(storedRecord.walletId) !== String(runtimeRecord.key.walletId) ||
              String(storedRecord.keyHandle) !== String(runtimeRecord.keyHandle) ||
              String(storedRecord.signingGrantId || '').trim() !==
                String(runtimeRecord.signingGrantId || '').trim()
            ) {
              claims.set(claimKey, null);
              return;
            }
            const statusSessionId = resolveEmailOtpEcdsaWorkerSessionId(storedRecord);
            if (!statusSessionId) {
              claims.set(claimKey, null);
              return;
            }
            const status = await ports.readWarmSessionStatusOnly(statusSessionId);
            claims.set(
              claimKey,
              warmStatusToAvailableSigningLanesRuntimeClaim({ thresholdSessionId: sessionId, status }),
            );
          }),
        );
        return claims;
      },
      readRuntimeClaimsForSessions: async (sessionIds) => {
        const claims = new Map<string, AvailableSigningLanesRuntimeClaim | null>();
        await Promise.all(
          sessionIds.map(async (sessionId) => {
            const status = await ports.readWarmSessionStatusOnly(sessionId);
            claims.set(
              sessionId,
              warmStatusToAvailableSigningLanesRuntimeClaim({ thresholdSessionId: sessionId, status }),
            );
          }),
        );
        return claims;
      },
    },
  );
}
