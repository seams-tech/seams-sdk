import type { AccountAuthMetadata } from '@/core/signingEngine/auth';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from '../thresholdLifecycle/thresholdSessionStore';
import type {
  SigningSessionSnapshot,
  SigningSessionSnapshotEcdsaLane,
} from '../../session/snapshotReader';
import type { SigningSessionPreparedBudgetIdentity } from '../../session/signingSession/budget';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type { RestorePersistedSessionForSigningInput } from '../../session/restoreCoordinator';
import {
  selectTransactionLane,
  type EvmFamilyEcdsaConcreteSnapshotLane,
} from '../../session/signingSession/transactionState';
import {
  prepareThresholdSigningOperation,
  type PreparedThresholdSigningOperation,
} from '../../session/signingSession/preparedOperation';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
  emitSigningLaneResolutionTrace,
  emitSigningPlannerDecisionTrace,
} from '../../session/signingSession/trace';
import {
  requireResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaKeyRef,
  summarizeEvmFamilyEcdsaLane,
  summarizeEvmFamilyEcdsaSessionRecord,
  type EcdsaSigningLookupArgs,
  type EvmFamilyEcdsaAuthMethod,
  type PasskeyEcdsaSigningLookupArgs,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import {
  resolveEvmFamilyEcdsaSigningSelection,
  type EvmFamilyEcdsaSigningSelectionDeps,
} from './ecdsaSelection';
import {
  resolveEvmFamilyEcdsaPlannerReadiness,
  type EvmFamilyPreConfirmSigningDeps,
} from './authPlanning';
import { resolveEvmFamilyTransactionAccountAuth } from './accountAuth';
import type { EvmFamilyChain } from './types';

function resolveEcdsaSnapshotCandidate(args: {
  snapshot: SigningSessionSnapshot;
  nearAccountId: string;
  chain: EvmFamilyChain;
  accountAuth: AccountAuthMetadata;
}): EvmFamilyEcdsaConcreteSnapshotLane | null {
  const primaryAuthMethod =
    args.accountAuth.primaryAuthMethod === 'email_otp' ? 'email_otp' : 'passkey';
  const selection = selectTransactionLane({
    intent: {
      walletId: args.nearAccountId,
      curve: 'ecdsa',
      chain: args.chain,
      authSelectionPolicy: { kind: 'account_class', authMethod: primaryAuthMethod },
      operationUsesNeeded: 1,
    },
    snapshot: args.snapshot,
  });
  if (!selection.ok) {
    if (selection.failure.kind === 'no_candidate') return null;
    throw new Error(
      `[SigningEngine][ecdsa] transaction lane selection failed: ${selection.failure.kind}`,
    );
  }
  if (selection.lane.curve !== 'ecdsa' || selection.snapshotLane.curve !== 'ecdsa') {
    throw new Error('[SigningEngine][ecdsa] selector returned a non-ECDSA lane');
  }
  return selection.snapshotLane as EvmFamilyEcdsaConcreteSnapshotLane;
}

function assertSelectionMatchesSnapshotCandidate(args: {
  candidate: SigningSessionSnapshotEcdsaLane | null;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
}): void {
  const candidate = args.candidate;
  if (!candidate) return;
  if (candidate.authMethod && candidate.authMethod !== args.lane.authMethod) {
    throw new Error(
      `[SigningEngine][ecdsa] prepared restore auth method ${candidate.authMethod} did not match selected lane auth method ${args.lane.authMethod}`,
    );
  }
  if (
    candidate.thresholdSessionId &&
    candidate.thresholdSessionId !== String(args.lane.thresholdSessionId)
  ) {
    throw new Error(
      '[SigningEngine][ecdsa] prepared restore threshold session did not match selected lane',
    );
  }
  if (
    candidate.walletSigningSessionId &&
    candidate.walletSigningSessionId !== String(args.lane.walletSigningSessionId)
  ) {
    throw new Error(
      '[SigningEngine][ecdsa] prepared restore wallet signing session did not match selected lane',
    );
  }
}

export type PreparedEvmFamilyEcdsaSigningSession = {
  accountAuth: AccountAuthMetadata;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  snapshotGeneration: number;
  budgetIdentity?: SigningSessionPreparedBudgetIdentity;
  budgetProjectionVersion?: string;
  budgetIdentityThresholdSessionId?: string;
  signingLane: ResolvedEvmFamilyEcdsaSigningLane;
  preparedOperation: PreparedThresholdSigningOperation<
    ResolvedEvmFamilyEcdsaSigningLane,
    Record<string, unknown>
  >;
  warmRecord?: ThresholdEcdsaSessionRecord;
  warmKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  emailOtpReauthRecord?: ThresholdEcdsaSessionRecord;
};

export type PrepareEvmFamilyEcdsaSigningDeps = EvmFamilyEcdsaSigningSelectionDeps &
  EvmFamilyPreConfirmSigningDeps & {
    restorePersistedSessionForSigning: (
      args: Extract<RestorePersistedSessionForSigningInput, { curve: 'ecdsa' }>,
    ) => Promise<unknown>;
    readSigningSessionSnapshotForSigning: (args: {
      walletId: string;
      authMethod?: 'email_otp' | 'passkey';
    }) => Promise<SigningSessionSnapshot>;
    getEmailOtpThresholdEcdsaKeyRefForSigning: (
      args: EcdsaSigningLookupArgs,
    ) => ThresholdEcdsaSecp256k1KeyRef;
    getEmailOtpThresholdEcdsaSessionRecordForSigning: (
      args: EcdsaSigningLookupArgs,
    ) => ThresholdEcdsaSessionRecord;
    getPasskeyThresholdEcdsaKeyRefForSigning: (
      args: PasskeyEcdsaSigningLookupArgs,
    ) => ThresholdEcdsaSecp256k1KeyRef;
    getPasskeyThresholdEcdsaSessionRecordForSigning: (
      args: PasskeyEcdsaSigningLookupArgs,
    ) => ThresholdEcdsaSessionRecord;
  };

export async function prepareEvmFamilyEcdsaSigningSession(args: {
  deps: PrepareEvmFamilyEcdsaSigningDeps;
  nearAccountId: string;
  chain: EvmFamilyChain;
  diagnostics: Record<string, unknown>;
  signingSessionCoordinator: SigningSessionCoordinator;
  forceFreshAuth?: boolean;
}): Promise<PreparedEvmFamilyEcdsaSigningSession> {
  const preparedOperation = await prepareThresholdSigningOperation({
    intent: {
      kind: 'transaction_sign',
      chain: args.chain,
      curve: 'ecdsa',
      walletId: args.nearAccountId,
      reason: 'transaction',
    },
    coordinator: args.signingSessionCoordinator,
    forceFreshAuth: args.forceFreshAuth === true,
    missingWhenExpiresAtMissing: true,
    prepareBudgetIdentity: true,
    onPlannerTrace: (event) => emitSigningPlannerDecisionTrace('evm-family', event),
    lifecycleAdapter: {
      prepare: async () => {
        const candidateSnapshot = await args.deps.readSigningSessionSnapshotForSigning({
          walletId: args.nearAccountId,
        });
        const accountAuth = await resolveEvmFamilyTransactionAccountAuth({
          deps: args.deps,
          nearAccountId: args.nearAccountId,
          senderSignatureAlgorithm: 'secp256k1',
        });
        const snapshotCandidate = resolveEcdsaSnapshotCandidate({
          snapshot: candidateSnapshot,
          nearAccountId: args.nearAccountId,
          chain: args.chain,
          accountAuth,
        });
        const primaryAuthMethod =
          accountAuth.primaryAuthMethod === 'email_otp' ? 'email_otp' : 'passkey';
        const authMethod = snapshotCandidate?.authMethod || primaryAuthMethod;
        let selection:
          | Awaited<ReturnType<typeof resolveEvmFamilyEcdsaSigningSelection>>
          | null = null;
        // Transaction prepare first reads the side-effect-free signing-session
        // snapshot, then restores only the selected exact auth-method lane.
        // Broad probing belongs to startup/session-status maintenance paths.
        const restoreResults: Record<string, unknown> = {};
        if (snapshotCandidate) {
          args.diagnostics.sealedRestoreBeforeSelection = {
            attempted: true,
            completed: false,
            authMethod,
            snapshotCandidate: authMethod,
          };
          await args.deps
            .restorePersistedSessionForSigning({
              walletId: args.nearAccountId,
              authMethod,
              curve: 'ecdsa',
              chain: args.chain,
              walletSigningSessionId: snapshotCandidate.walletSigningSessionId,
              thresholdSessionId: snapshotCandidate.thresholdSessionId,
              reason: 'transaction',
            })
            .then(
              (result) => {
                restoreResults[authMethod] = result;
              },
              (error) => {
                const message = error instanceof Error ? error.message : String(error);
                restoreResults[authMethod] = { error: message };
                console.debug(
                  '[SigningEngine][ecdsa] sealed restore before lane selection skipped',
                  {
                    nearAccountId: args.nearAccountId,
                    chain: args.chain,
                    authMethod,
                    message,
                  },
                );
              },
            );
        } else {
          // Fresh unlocks can have runtime lane material before the side-effect-free
          // snapshot has a durable exact candidate. In that case, skip restore and
          // let lane selection prove the runtime identity below.
          args.diagnostics.sealedRestoreBeforeSelection = {
            attempted: false,
            completed: true,
            authMethod,
            reason: 'no_exact_snapshot_candidate',
          };
          selection = await resolveEvmFamilyEcdsaSigningSelection({
            deps: args.deps,
            nearAccountId: args.nearAccountId,
            chain: args.chain,
            senderSignatureAlgorithm: 'secp256k1',
            authMethod,
          });
        }
        args.diagnostics.sealedRestoreBeforeSelection = {
          attempted: !!snapshotCandidate,
          completed: true,
          authMethod,
          results: restoreResults,
          selectedSnapshotCandidate: snapshotCandidate
            ? {
                authMethod: snapshotCandidate.authMethod,
                state: snapshotCandidate.state,
                thresholdSessionId: snapshotCandidate.thresholdSessionId,
                walletSigningSessionId: snapshotCandidate.walletSigningSessionId,
                source: snapshotCandidate.source,
              }
            : null,
        };

        selection =
          selection ||
          (await resolveEvmFamilyEcdsaSigningSelection({
            deps: args.deps,
            nearAccountId: args.nearAccountId,
            chain: args.chain,
            senderSignatureAlgorithm: 'secp256k1',
            authMethod,
            ...(snapshotCandidate ? { snapshotCandidate } : {}),
          }));
        const snapshot = await args.deps.readSigningSessionSnapshotForSigning({
          walletId: args.nearAccountId,
          authMethod: selection.authMethod,
        });
        const signingLane = selection.lane;
        emitSigningLaneResolutionTrace('evm-family', signingLane, {
          reason: 'evm_family_ecdsa_selection',
        });
        args.diagnostics.selection = {
          authMethod: selection.authMethod,
          source: selection.source,
          lane: summarizeEvmFamilyEcdsaLane(signingLane),
          warmRecord: summarizeEvmFamilyEcdsaSessionRecord(selection.warmRecord),
          warmKeyRef: summarizeEvmFamilyEcdsaKeyRef(selection.warmKeyRef),
          reauthRecord: summarizeEvmFamilyEcdsaSessionRecord(selection.reauthRecord),
        };
        if (!signingLane) {
          console.warn(
            '[SigningEngine][ecdsa] EVM-family signing has no selected lane after selection',
            {
              ...args.diagnostics,
            },
          );
        }
        const resolvedLane = requireResolvedEvmFamilyEcdsaSigningLane({
          lane: signingLane,
          chain: args.chain,
          context: 'EVM-family signing preparation',
          diagnostics: args.diagnostics,
        });
        assertSelectionMatchesSnapshotCandidate({
          candidate: snapshotCandidate,
          lane: resolvedLane,
        });
        const readiness = await resolveEvmFamilyEcdsaPlannerReadiness({
          deps: args.deps,
          lane: resolvedLane,
          ...(selection.warmRecord ? { record: selection.warmRecord } : {}),
          ...(selection.warmKeyRef ? { keyRef: selection.warmKeyRef } : {}),
        });
        emitSigningBoundaryTrace(
          'evm-family',
          createSigningBoundaryTraceEvent({
            event: 'pre_confirm_readiness_checked',
            lane: resolvedLane,
            readinessStatus: readiness.readiness.status,
            phase: 'pre_confirm',
          }),
        );
        return {
          lane: resolvedLane,
          readiness: {
            readiness: readiness.readiness,
            expiresAtMs: readiness.expiresAtMs,
            remainingUses: readiness.remainingUses,
          },
          snapshotGeneration: snapshot.generation,
          metadata: {
            accountAuth: selection.accountAuth,
            authMethod: selection.authMethod,
            source: selection.source,
            snapshotGeneration: snapshot.generation,
            ...(selection.warmRecord ? { warmRecord: selection.warmRecord } : {}),
            ...(selection.warmKeyRef ? { warmKeyRef: selection.warmKeyRef } : {}),
            ...(selection.reauthRecord ? { emailOtpReauthRecord: selection.reauthRecord } : {}),
            ...(readiness.signingRootId ? { signingRootId: readiness.signingRootId } : {}),
          },
        };
      },
    },
  });
  const metadata = preparedOperation.metadata as {
    accountAuth: AccountAuthMetadata;
    authMethod: EvmFamilyEcdsaAuthMethod;
    source: ThresholdEcdsaSessionStoreSource;
    snapshotGeneration: number;
    warmRecord?: ThresholdEcdsaSessionRecord;
    warmKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
    emailOtpReauthRecord?: ThresholdEcdsaSessionRecord;
  };

  return {
    accountAuth: metadata.accountAuth,
    authMethod: metadata.authMethod,
    source: metadata.source,
    snapshotGeneration: metadata.snapshotGeneration,
    signingLane: preparedOperation.lane,
    preparedOperation,
    ...(preparedOperation.budgetIdentity
      ? {
          budgetIdentity: preparedOperation.budgetIdentity,
          budgetProjectionVersion: preparedOperation.budgetIdentity.projectionVersion,
          budgetIdentityThresholdSessionId: String(preparedOperation.lane.thresholdSessionId),
        }
      : {}),
    ...(metadata.warmRecord ? { warmRecord: metadata.warmRecord } : {}),
    ...(metadata.warmKeyRef ? { warmKeyRef: metadata.warmKeyRef } : {}),
    ...(metadata.emailOtpReauthRecord
      ? { emailOtpReauthRecord: metadata.emailOtpReauthRecord }
      : {}),
  };
}
