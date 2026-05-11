import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { EcdsaLaneCandidate, ThresholdEcdsaSessionStoreSource } from '../../session/identity/laneIdentity';
import { SigningSessionIds } from '../../session/operationState/types';
import {
  buildEvmTransactionSigningLane,
  buildTempoTransactionSigningLane,
} from '../../session/operationState/lanes';
import {
  resolveEvmFamilyTransactionAccountAuth,
  type EvmFamilyAccountMetadataDeps,
} from './accountAuth';
import {
  buildEcdsaMaterialStateForCandidate,
  summarizeEcdsaMaterialState,
  summarizeVisibleEcdsaMaterial,
  type EcdsaMaterialState,
  type EcdsaMaterialSummary,
  type ReadyEcdsaMaterial,
} from './ecdsaMaterialState';
import {
  findExactEcdsaKeyRefForSelectedLane,
  findExactEcdsaSessionRecordForSelectedLane,
  isSingleUseEmailOtpEcdsaRecord,
  logEvmFamilyEcdsaLaneDiagnostic,
  requireResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaLane,
  tryGetEmailOtpThresholdEcdsaKeyRefForSigning,
  tryGetEmailOtpThresholdEcdsaSessionRecordForSigning,
  tryGetPasskeyThresholdEcdsaKeyRefForSigning,
  tryGetPasskeyThresholdEcdsaSessionRecordForSigning,
  type EvmFamilyEcdsaAuthMethod,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import type {
  EvmFamilyEcdsaSessionReaderDeps,
  PasskeyEcdsaSessionStoreSource,
} from '../../interfaces/operationDeps';
import type { EvmFamilyChain, EvmFamilySenderSignatureAlgorithm } from './types';
import type {
  ThresholdEcdsaChainTarget,
  WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { WalletBudgetUnknown } from '../../session/budget/budgetProjection';

const PASSKEY_ECDSA_SIGNING_SOURCE_PRIORITY = [
  'login',
  'manual-bootstrap',
  'registration',
] as const satisfies readonly PasskeyEcdsaSessionStoreSource[];

export type EvmFamilyEcdsaSigningSelectionDeps = EvmFamilyAccountMetadataDeps &
  EvmFamilyEcdsaSessionReaderDeps;

export type EcdsaSelectionDiagnostics = {
  selectedLaneCandidate: {
    authMethod: EcdsaLaneCandidate['authMethod'];
    chain: EcdsaLaneCandidate['chain'];
    chainTarget: ThresholdEcdsaChainTarget;
    state: EcdsaLaneCandidate['state'];
    source: EcdsaLaneCandidate['source'];
    walletSigningSessionId: string;
    thresholdSessionId: string;
    remainingUses: number | null;
    expiresAtMs: number | null;
    updatedAtMs: number | null;
  };
  exactCandidateMaterial: EcdsaMaterialSummary;
  visibleEmailOtpMaterial: EcdsaMaterialSummary | { present: false };
  visiblePasskeyMaterials: readonly (EcdsaMaterialSummary | { present: false })[];
  selectedPasskeyMaterial: EcdsaMaterialSummary | { present: false };
};

export type ReadyEvmFamilyEcdsaSigningSelection = {
  kind: 'ready';
  accountAuth: AccountAuthMetadata;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  material: ReadyEcdsaMaterial;
  diagnostics: EcdsaSelectionDiagnostics;
};

export type ReauthRequiredEvmFamilyEcdsaSigningSelection = {
  kind: 'reauth_required';
  accountAuth: AccountAuthMetadata;
  authMethod: EvmFamilyEcdsaAuthMethod;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  material: EcdsaMaterialState;
  reason: 'single_use_email_otp' | 'missing_hot_material' | 'expired' | 'exhausted';
  diagnostics: EcdsaSelectionDiagnostics;
};

export type BudgetBlockedEvmFamilyEcdsaSigningSelection = {
  kind: 'budget_blocked';
  accountAuth: AccountAuthMetadata;
  authMethod: EvmFamilyEcdsaAuthMethod;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  material: ReadyEcdsaMaterial;
  budget: WalletBudgetUnknown | { kind: 'exhausted'; remainingUses: 0 };
  diagnostics: EcdsaSelectionDiagnostics;
};

export type MissingMaterialEvmFamilyEcdsaSigningSelection = {
  kind: 'missing_material';
  accountAuth: AccountAuthMetadata;
  authMethod: EvmFamilyEcdsaAuthMethod;
  candidate: EcdsaLaneCandidate;
  material: EcdsaMaterialState;
  diagnostics: EcdsaSelectionDiagnostics;
};

export type EvmFamilyEcdsaSigningSelectionResult =
  | ReadyEvmFamilyEcdsaSigningSelection
  | ReauthRequiredEvmFamilyEcdsaSigningSelection
  | BudgetBlockedEvmFamilyEcdsaSigningSelection
  | MissingMaterialEvmFamilyEcdsaSigningSelection;

function accountAuthWithSelectedPrimary(
  accountAuth: AccountAuthMetadata,
  authMethod: EvmFamilyEcdsaAuthMethod,
): AccountAuthMetadata {
  return {
    ...accountAuth,
    primaryAuthMethod: authMethod,
    linkedAuthMethods: Array.from(new Set([...accountAuth.linkedAuthMethods, authMethod])),
  };
}

function exactEcdsaCandidateRequiresHotMaterial(candidate: EcdsaLaneCandidate): boolean {
  return (
    candidate.state === 'ready' ||
    candidate.state === 'restorable' ||
    candidate.state === 'deferred'
  );
}

function signingLaneFromExactLaneCandidate(
  candidate: EcdsaLaneCandidate,
): ResolvedEvmFamilyEcdsaSigningLane {
  const buildLane =
    candidate.chainTarget.kind === 'tempo'
      ? buildTempoTransactionSigningLane
      : buildEvmTransactionSigningLane;
  const base = {
    accountId: candidate.accountId,
    subjectId: candidate.subjectId,
    chainTarget: candidate.chainTarget,
    ecdsaThresholdKeyId: candidate.ecdsaThresholdKeyId,
    signingRootId: candidate.signingRootId,
    signingRootVersion: candidate.signingRootVersion,
    walletSigningSessionId: SigningSessionIds.walletSigningSession(
      candidate.walletSigningSessionId,
    ),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(candidate.thresholdSessionId),
  };
  const lane = buildLane(
    candidate.authMethod === SIGNER_AUTH_METHODS.emailOtp
      ? {
          ...base,
          authMethod: SIGNER_AUTH_METHODS.emailOtp,
          retention: 'session',
          sessionOrigin: 'per_operation',
        }
      : {
          ...base,
          authMethod: SIGNER_AUTH_METHODS.passkey,
          storageSource: 'manual-bootstrap',
        },
  );
  return requireResolvedEvmFamilyEcdsaSigningLane({
    lane,
    chain: candidate.chain,
    context: 'build exact ECDSA candidate signing lane',
  });
}

function summarizeLaneCandidate(candidate: EcdsaLaneCandidate): EcdsaSelectionDiagnostics['selectedLaneCandidate'] {
  return {
    authMethod: candidate.authMethod,
    chain: candidate.chain,
    chainTarget: candidate.chainTarget,
    state: candidate.state,
    source: candidate.source,
    walletSigningSessionId: candidate.walletSigningSessionId,
    thresholdSessionId: candidate.thresholdSessionId,
    remainingUses: candidate.remainingUses,
    expiresAtMs: candidate.expiresAtMs,
    updatedAtMs: candidate.updatedAtMs,
  };
}

type PasskeyVisibleMaterial = {
  source: PasskeyEcdsaSessionStoreSource;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
};

function listPasskeyVisibleMaterials(args: {
  deps: EvmFamilyEcdsaSigningSelectionDeps;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
}): PasskeyVisibleMaterial[] {
  const candidates: PasskeyVisibleMaterial[] = [];
  for (const source of PASSKEY_ECDSA_SIGNING_SOURCE_PRIORITY) {
    const record = tryGetPasskeyThresholdEcdsaSessionRecordForSigning({
      deps: args.deps,
      subjectId: args.subjectId,
      chainTarget: args.chainTarget,
      source,
    });
    const keyRef = tryGetPasskeyThresholdEcdsaKeyRefForSigning({
      deps: args.deps,
      subjectId: args.subjectId,
      chainTarget: args.chainTarget,
      source,
    });
    if (!record && !keyRef) continue;
    candidates.push({
      source,
      ...(record ? { record } : {}),
      ...(keyRef ? { keyRef } : {}),
    });
  }
  return candidates;
}

function buildEcdsaSelectionDiagnostics(args: {
  candidate: EcdsaLaneCandidate;
  exactCandidateMaterial: EcdsaMaterialState;
  emailOtpRecord?: ThresholdEcdsaSessionRecord;
  emailOtpKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  passkeyVisibleMaterials: readonly PasskeyVisibleMaterial[];
  selectedPasskeyMaterial?: PasskeyVisibleMaterial;
}): EcdsaSelectionDiagnostics {
  return {
    selectedLaneCandidate: summarizeLaneCandidate(args.candidate),
    exactCandidateMaterial: summarizeEcdsaMaterialState(args.exactCandidateMaterial),
    visibleEmailOtpMaterial: summarizeVisibleEcdsaMaterial({
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
      source: SIGNER_AUTH_METHODS.emailOtp,
      chainTarget: args.candidate.chainTarget,
      ...(args.emailOtpRecord ? { record: args.emailOtpRecord } : {}),
      ...(args.emailOtpKeyRef ? { keyRef: args.emailOtpKeyRef } : {}),
    }),
    visiblePasskeyMaterials: args.passkeyVisibleMaterials.map((material) =>
      summarizeVisibleEcdsaMaterial({
        authMethod: SIGNER_AUTH_METHODS.passkey,
        source: material.source,
        chainTarget: args.candidate.chainTarget,
        ...(material.record ? { record: material.record } : {}),
        ...(material.keyRef ? { keyRef: material.keyRef } : {}),
      }),
    ),
    selectedPasskeyMaterial: args.selectedPasskeyMaterial
      ? summarizeVisibleEcdsaMaterial({
          authMethod: SIGNER_AUTH_METHODS.passkey,
          source: args.selectedPasskeyMaterial.source,
          chainTarget: args.candidate.chainTarget,
          ...(args.selectedPasskeyMaterial.record
            ? { record: args.selectedPasskeyMaterial.record }
            : {}),
          ...(args.selectedPasskeyMaterial.keyRef
            ? { keyRef: args.selectedPasskeyMaterial.keyRef }
            : {}),
        })
      : { present: false },
  };
}

function selectPasskeyMaterialForCandidate(args: {
  candidate: EcdsaLaneCandidate;
  exactRecord?: ThresholdEcdsaSessionRecord;
  exactKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  exactSource?: ThresholdEcdsaSessionStoreSource;
  passkeyVisibleMaterials: readonly PasskeyVisibleMaterial[];
  chainTarget: ThresholdEcdsaChainTarget;
}): { material: EcdsaMaterialState; selected?: PasskeyVisibleMaterial } {
  if (args.exactRecord || args.exactKeyRef) {
    const exactMaterial = buildEcdsaMaterialStateForCandidate({
      candidate: args.candidate,
      record: args.exactRecord,
      keyRef: args.exactKeyRef,
      authMethod: SIGNER_AUTH_METHODS.passkey,
      source: (args.exactSource || 'manual-bootstrap') as ThresholdEcdsaSessionStoreSource,
      chainTarget: args.chainTarget,
    });
    if (exactMaterial.kind !== 'missing') {
      return {
        material: exactMaterial,
        selected: {
          source: (args.exactSource || 'manual-bootstrap') as PasskeyEcdsaSessionStoreSource,
          ...(args.exactRecord ? { record: args.exactRecord } : {}),
          ...(args.exactKeyRef ? { keyRef: args.exactKeyRef } : {}),
        },
      };
    }
  }
  for (const candidateMaterial of args.passkeyVisibleMaterials) {
    const material = buildEcdsaMaterialStateForCandidate({
      candidate: args.candidate,
      record: candidateMaterial.record,
      keyRef: candidateMaterial.keyRef,
      authMethod: SIGNER_AUTH_METHODS.passkey,
      source: candidateMaterial.source,
      chainTarget: args.chainTarget,
    });
    if (material.kind !== 'missing') {
      return { material, selected: candidateMaterial };
    }
  }
  return {
    material: buildEcdsaMaterialStateForCandidate({
      candidate: args.candidate,
      record: undefined,
      keyRef: undefined,
      authMethod: SIGNER_AUTH_METHODS.passkey,
      source: 'manual-bootstrap',
      chainTarget: args.chainTarget,
    }),
  };
}

function selectSessionSourceForAccountAuth(args: {
  emailOtpRecord?: ThresholdEcdsaSessionRecord;
  emailOtpKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  selectedPasskeyMaterial?: PasskeyVisibleMaterial;
}): { sessionSource?: string; isEmailOtpThresholdContext?: boolean } {
  const hasEmailOtpVisible = Boolean(args.emailOtpRecord || args.emailOtpKeyRef);
  const hasPasskeyVisible = Boolean(
    args.selectedPasskeyMaterial?.record || args.selectedPasskeyMaterial?.keyRef,
  );
  if (hasEmailOtpVisible === hasPasskeyVisible) return {};
  if (hasEmailOtpVisible) {
    return {
      sessionSource: args.emailOtpRecord?.source || SIGNER_AUTH_METHODS.emailOtp,
      isEmailOtpThresholdContext: true,
    };
  }
  return {
    sessionSource: args.selectedPasskeyMaterial?.record?.source || args.selectedPasskeyMaterial?.source,
    isEmailOtpThresholdContext: false,
  };
}

export async function resolveEvmFamilyEcdsaSigningSelection(args: {
  deps: EvmFamilyEcdsaSigningSelectionDeps;
  nearAccountId: string;
  subjectId: WalletSubjectId;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  authMethod: EvmFamilyEcdsaAuthMethod;
  laneCandidate: EcdsaLaneCandidate;
  allowMissingHotMaterial?: boolean;
}): Promise<EvmFamilyEcdsaSigningSelectionResult> {
  const lane = signingLaneFromExactLaneCandidate(args.laneCandidate);
  const exactRecordForCandidate = findExactEcdsaSessionRecordForSelectedLane({
    deps: args.deps,
    lane,
  });
  const exactKeyRefMatchForCandidate = findExactEcdsaKeyRefForSelectedLane({
    deps: args.deps,
    lane,
  });
  const exactKeyRefForCandidate = exactKeyRefMatchForCandidate?.keyRef;

  const emailOtpRecord = tryGetEmailOtpThresholdEcdsaSessionRecordForSigning({
    deps: args.deps,
    subjectId: args.subjectId,
    chainTarget: args.chainTarget,
  });
  const emailOtpKeyRef = tryGetEmailOtpThresholdEcdsaKeyRefForSigning({
    deps: args.deps,
    subjectId: args.subjectId,
    chainTarget: args.chainTarget,
  });
  const passkeyVisibleMaterials = listPasskeyVisibleMaterials({
    deps: args.deps,
    subjectId: args.subjectId,
    chainTarget: args.chainTarget,
  });
  const exactCandidateMaterial =
    args.laneCandidate.authMethod === SIGNER_AUTH_METHODS.emailOtp
      ? buildEcdsaMaterialStateForCandidate({
          candidate: args.laneCandidate,
          record: exactRecordForCandidate || emailOtpRecord,
          keyRef: exactKeyRefForCandidate || emailOtpKeyRef,
          authMethod: SIGNER_AUTH_METHODS.emailOtp,
          source: SIGNER_AUTH_METHODS.emailOtp,
          chainTarget: args.chainTarget,
        })
      : selectPasskeyMaterialForCandidate({
          candidate: args.laneCandidate,
          exactRecord: exactRecordForCandidate,
          exactKeyRef: exactKeyRefForCandidate,
          exactSource:
            exactRecordForCandidate?.source ||
            exactKeyRefMatchForCandidate?.source ||
            undefined,
          passkeyVisibleMaterials,
          chainTarget: args.chainTarget,
        }).material;

  const selectedPasskeyMaterial = selectPasskeyMaterialForCandidate({
    candidate: args.laneCandidate,
    exactRecord: exactRecordForCandidate,
    exactKeyRef: exactKeyRefForCandidate,
    exactSource:
      exactRecordForCandidate?.source || exactKeyRefMatchForCandidate?.source || undefined,
    passkeyVisibleMaterials,
    chainTarget: args.chainTarget,
  });

  const accountAuthInputs = selectSessionSourceForAccountAuth({
    ...(emailOtpRecord ? { emailOtpRecord } : {}),
    ...(emailOtpKeyRef ? { emailOtpKeyRef } : {}),
    ...(selectedPasskeyMaterial.selected
      ? { selectedPasskeyMaterial: selectedPasskeyMaterial.selected }
      : {}),
  });
  const accountAuth = await resolveEvmFamilyTransactionAccountAuth({
    deps: args.deps,
    nearAccountId: args.nearAccountId,
    senderSignatureAlgorithm: args.senderSignatureAlgorithm,
    ...(accountAuthInputs.sessionSource ? { sessionSource: accountAuthInputs.sessionSource } : {}),
    ...(typeof accountAuthInputs.isEmailOtpThresholdContext === 'boolean'
      ? { isEmailOtpThresholdContext: accountAuthInputs.isEmailOtpThresholdContext }
      : {}),
  });
  const selectedAccountAuth = accountAuthWithSelectedPrimary(
    accountAuth,
    args.laneCandidate.authMethod,
  );

  const diagnostics = buildEcdsaSelectionDiagnostics({
    candidate: args.laneCandidate,
    exactCandidateMaterial,
    ...(emailOtpRecord ? { emailOtpRecord } : {}),
    ...(emailOtpKeyRef ? { emailOtpKeyRef } : {}),
    passkeyVisibleMaterials,
    ...(selectedPasskeyMaterial.selected
      ? { selectedPasskeyMaterial: selectedPasskeyMaterial.selected }
      : {}),
  });
  try {
    console.info('[SigningEngine][ecdsa][selection]', {
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      requestedAuthMethod: args.authMethod,
      selectedAuthMethod: args.laneCandidate.authMethod,
      selectionDiagnostics: diagnostics,
    });
  } catch {}

  if (
    !args.allowMissingHotMaterial &&
    exactEcdsaCandidateRequiresHotMaterial(args.laneCandidate) &&
    exactCandidateMaterial.kind !== 'ready_material'
  ) {
    return {
      kind: 'missing_material',
      accountAuth: selectedAccountAuth,
      authMethod: args.laneCandidate.authMethod as EvmFamilyEcdsaAuthMethod,
      candidate: args.laneCandidate,
      material: exactCandidateMaterial,
      diagnostics,
    };
  }

  if (args.laneCandidate.state === 'expired') {
    return {
      kind: 'reauth_required',
      accountAuth: selectedAccountAuth,
      authMethod: args.laneCandidate.authMethod as EvmFamilyEcdsaAuthMethod,
      lane,
      material: exactCandidateMaterial,
      reason: 'expired',
      diagnostics,
    };
  }

  if (args.laneCandidate.state === 'exhausted') {
    if (exactCandidateMaterial.kind === 'ready_material') {
      return {
        kind: 'budget_blocked',
        accountAuth: selectedAccountAuth,
        authMethod: args.laneCandidate.authMethod as EvmFamilyEcdsaAuthMethod,
        lane,
        material: exactCandidateMaterial,
        budget: { kind: 'exhausted', remainingUses: 0 },
        diagnostics,
      };
    }
    return {
      kind: 'reauth_required',
      accountAuth: selectedAccountAuth,
      authMethod: args.laneCandidate.authMethod as EvmFamilyEcdsaAuthMethod,
      lane,
      material: exactCandidateMaterial,
      reason: 'exhausted',
      diagnostics,
    };
  }

  if (
    exactCandidateMaterial.kind === 'ready_material' &&
    args.laneCandidate.authMethod === SIGNER_AUTH_METHODS.emailOtp &&
    isSingleUseEmailOtpEcdsaRecord(exactCandidateMaterial.record)
  ) {
    return {
      kind: 'reauth_required',
      accountAuth: selectedAccountAuth,
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
      lane,
      material: exactCandidateMaterial,
      reason: 'single_use_email_otp',
      diagnostics,
    };
  }

  if (exactCandidateMaterial.kind !== 'ready_material') {
    return {
      kind: 'reauth_required',
      accountAuth: selectedAccountAuth,
      authMethod: args.laneCandidate.authMethod as EvmFamilyEcdsaAuthMethod,
      lane,
      material: exactCandidateMaterial,
      reason: 'missing_hot_material',
      diagnostics,
    };
  }

  if (args.laneCandidate.authMethod !== exactCandidateMaterial.authMethod) {
    logEvmFamilyEcdsaLaneDiagnostic('selected ECDSA material auth method mismatch', {
      lane: summarizeEvmFamilyEcdsaLane(lane),
      material: summarizeEcdsaMaterialState(exactCandidateMaterial),
    });
    throw new Error('[SigningEngine][ecdsa] selected ECDSA material auth method mismatch');
  }

  return {
    kind: 'ready',
    accountAuth: selectedAccountAuth,
    authMethod: args.laneCandidate.authMethod as EvmFamilyEcdsaAuthMethod,
    source: exactCandidateMaterial.source,
    lane,
    material: exactCandidateMaterial,
    diagnostics,
  };
}
