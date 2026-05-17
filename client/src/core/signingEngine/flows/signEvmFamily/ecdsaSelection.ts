import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type {
  EcdsaLaneCandidate,
  ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import { SigningSessionIds } from '../../session/operationState/types';
import {
  buildEvmTransactionSigningLane,
  buildTempoTransactionSigningLane,
} from '../../session/operationState/lanes';
import {
  resolveEvmFamilyTransactionWalletAuth,
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

type EcdsaSelectionLaneCandidateDiagnosticsBase = {
  authMethod: EcdsaLaneCandidate['authMethod'];
  chain: EcdsaLaneCandidate['chain'];
  chainTarget: ThresholdEcdsaChainTarget;
  state: EcdsaLaneCandidate['state'];
  walletSigningSessionId: string;
  thresholdSessionId: string;
  remainingUses: number | null;
  expiresAtMs: number | null;
  updatedAtMs: number | null;
};

type EcdsaSelectionLaneCandidateDiagnostics =
  | (EcdsaSelectionLaneCandidateDiagnosticsBase & {
      source: 'evm_family_shared_key';
      sourceChainTarget: ThresholdEcdsaChainTarget;
    })
  | (EcdsaSelectionLaneCandidateDiagnosticsBase & {
      source: Exclude<EcdsaLaneCandidate['source'], 'evm_family_shared_key'>;
      sourceChainTarget?: never;
    });

export type EcdsaSelectionDiagnostics = {
  selectedLaneCandidate: EcdsaSelectionLaneCandidateDiagnostics;
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

export type EmailOtpEcdsaReauthAuthority = {
  kind: 'email_otp_signing_session';
  thresholdSessionId: string;
  chainTarget: ThresholdEcdsaChainTarget;
};

type ReauthRequiredEvmFamilyEcdsaSigningSelectionBase = {
  kind: 'reauth_required';
  accountAuth: AccountAuthMetadata;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  material: EcdsaMaterialState;
  reason: 'single_use_email_otp' | 'missing_hot_material' | 'expired' | 'exhausted';
  diagnostics: EcdsaSelectionDiagnostics;
};

export type ReauthRequiredEvmFamilyEcdsaSigningSelection =
  | (ReauthRequiredEvmFamilyEcdsaSigningSelectionBase & {
      authMethod: 'email_otp';
      reauthAuthority: EmailOtpEcdsaReauthAuthority;
    })
  | (ReauthRequiredEvmFamilyEcdsaSigningSelectionBase & {
      authMethod: 'passkey';
      reauthAuthority?: never;
    });

export type BudgetBlockedEvmFamilyEcdsaSigningSelection = {
  kind: 'budget_blocked';
  accountAuth: AccountAuthMetadata;
  authMethod: EvmFamilyEcdsaAuthMethod;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  material: ReadyEcdsaMaterial;
  budget: WalletBudgetUnknown;
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

function walletAuthWithSelectedPrimary(
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
  return candidate.state === 'ready';
}

function reauthRequiredSelection(args: {
  accountAuth: AccountAuthMetadata;
  candidate: EcdsaLaneCandidate;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  material: EcdsaMaterialState;
  materialChainTarget: ThresholdEcdsaChainTarget;
  reason: ReauthRequiredEvmFamilyEcdsaSigningSelection['reason'];
  diagnostics: EcdsaSelectionDiagnostics;
}): ReauthRequiredEvmFamilyEcdsaSigningSelection {
  const base = {
    kind: 'reauth_required' as const,
    accountAuth: args.accountAuth,
    lane: args.lane,
    material: args.material,
    reason: args.reason,
    diagnostics: args.diagnostics,
  };
  if (args.candidate.authMethod === SIGNER_AUTH_METHODS.emailOtp) {
    return {
      ...base,
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
      reauthAuthority: {
        kind: 'email_otp_signing_session',
        thresholdSessionId: args.candidate.thresholdSessionId,
        chainTarget: args.materialChainTarget,
      },
    };
  }
  return {
    ...base,
    authMethod: SIGNER_AUTH_METHODS.passkey,
  };
}

function signingLaneFromExactLaneCandidate(
  candidate: EcdsaLaneCandidate,
): ResolvedEvmFamilyEcdsaSigningLane {
  const buildLane =
    candidate.chainTarget.kind === 'tempo'
      ? buildTempoTransactionSigningLane
      : buildEvmTransactionSigningLane;
  const base = {
    key: candidate.key,
    walletId: candidate.walletId,
    subjectId: candidate.key.subjectId,
    chainTarget: candidate.chainTarget,
    ecdsaThresholdKeyId: candidate.key.ecdsaThresholdKeyId,
    signingRootId: candidate.key.signingRootId,
    signingRootVersion: candidate.key.signingRootVersion,
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

function laneCandidateDiagnosticsBase(
  candidate: EcdsaLaneCandidate,
): EcdsaSelectionLaneCandidateDiagnosticsBase {
  return {
    authMethod: candidate.authMethod,
    chain: candidate.chain,
    chainTarget: candidate.chainTarget,
    state: candidate.state,
    walletSigningSessionId: candidate.walletSigningSessionId,
    thresholdSessionId: candidate.thresholdSessionId,
    remainingUses: candidate.remainingUses,
    expiresAtMs: candidate.expiresAtMs,
    updatedAtMs: candidate.updatedAtMs,
  };
}

function summarizeLaneCandidate(
  candidate: EcdsaLaneCandidate,
): EcdsaSelectionDiagnostics['selectedLaneCandidate'] {
  const base = laneCandidateDiagnosticsBase(candidate);
  switch (candidate.source) {
    case 'evm_family_shared_key':
      return {
        ...base,
        source: 'evm_family_shared_key',
        sourceChainTarget: candidate.sourceChainTarget,
      };
    case 'durable_sealed_record':
    case 'runtime_session_record':
    case 'runtime_and_durable':
    case 'unknown':
      return {
        ...base,
        source: candidate.source,
      };
  }
}

type PasskeyVisibleMaterial = {
  source: PasskeyEcdsaSessionStoreSource;
  record: ThresholdEcdsaSessionRecord;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
};

type PasskeyMaterialSelectionResult =
  | {
      kind: 'selected';
      material: EcdsaMaterialState;
      selected: PasskeyVisibleMaterial;
    }
  | {
      kind: 'missing';
      material: EcdsaMaterialState;
    };

type PasskeyMaterialDiagnosticsSelection =
  | PasskeyMaterialSelectionResult
  | {
      kind: 'not_applicable';
      reason: 'email_otp_candidate';
      material?: never;
      selected?: never;
    };

function passkeySessionStoreSourceFromExactSource(
  source: ThresholdEcdsaSessionStoreSource | undefined,
): PasskeyEcdsaSessionStoreSource {
  switch (source) {
    case undefined:
      return 'manual-bootstrap';
    case 'login':
    case 'manual-bootstrap':
    case 'registration':
      return source;
    case 'email_otp':
      throw new Error('[SigningEngine][ecdsa] passkey material cannot use Email OTP source');
  }
}

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
    if (!record || !keyRef) continue;
    candidates.push({
      source,
      record,
      keyRef,
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
  passkeySelection: PasskeyMaterialDiagnosticsSelection;
  materialChainTarget: ThresholdEcdsaChainTarget;
}): EcdsaSelectionDiagnostics {
  const selectedPasskeyMaterial =
    args.passkeySelection.kind === 'selected'
      ? summarizeVisibleEcdsaMaterial({
          authMethod: SIGNER_AUTH_METHODS.passkey,
          source: args.passkeySelection.selected.source,
          chainTarget: args.candidate.chainTarget,
          materialChainTarget: args.materialChainTarget,
          record: args.passkeySelection.selected.record,
          keyRef: args.passkeySelection.selected.keyRef,
        })
      : { present: false as const };
  return {
    selectedLaneCandidate: summarizeLaneCandidate(args.candidate),
    exactCandidateMaterial: summarizeEcdsaMaterialState(args.exactCandidateMaterial),
    visibleEmailOtpMaterial: summarizeVisibleEcdsaMaterial({
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
      source: SIGNER_AUTH_METHODS.emailOtp,
      chainTarget: args.candidate.chainTarget,
      materialChainTarget: args.materialChainTarget,
      ...(args.emailOtpRecord ? { record: args.emailOtpRecord } : {}),
      ...(args.emailOtpKeyRef ? { keyRef: args.emailOtpKeyRef } : {}),
    }),
    visiblePasskeyMaterials: args.passkeyVisibleMaterials.map((material) =>
      summarizeVisibleEcdsaMaterial({
        authMethod: SIGNER_AUTH_METHODS.passkey,
        source: material.source,
        chainTarget: args.candidate.chainTarget,
        materialChainTarget: args.materialChainTarget,
        record: material.record,
        keyRef: material.keyRef,
      }),
    ),
    selectedPasskeyMaterial,
  };
}

function selectPasskeyMaterialForCandidate(args: {
  candidate: EcdsaLaneCandidate;
  exactRecord?: ThresholdEcdsaSessionRecord;
  exactKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  exactSource?: ThresholdEcdsaSessionStoreSource;
  passkeyVisibleMaterials: readonly PasskeyVisibleMaterial[];
  chainTarget: ThresholdEcdsaChainTarget;
  materialChainTarget: ThresholdEcdsaChainTarget;
}): PasskeyMaterialSelectionResult {
  if (args.exactRecord || args.exactKeyRef) {
    const exactSource = passkeySessionStoreSourceFromExactSource(args.exactSource);
    const exactMaterial = buildEcdsaMaterialStateForCandidate({
      candidate: args.candidate,
      record: args.exactRecord,
      keyRef: args.exactKeyRef,
      authMethod: SIGNER_AUTH_METHODS.passkey,
      source: exactSource,
      chainTarget: args.chainTarget,
      materialChainTarget: args.materialChainTarget,
    });
    if (exactMaterial.kind === 'ready_material') {
      return {
        kind: 'selected',
        material: exactMaterial,
        selected: {
          source: exactSource,
          record: exactMaterial.record,
          keyRef: exactMaterial.keyRef,
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
      materialChainTarget: args.materialChainTarget,
    });
    if (material.kind === 'ready_material') {
      return { kind: 'selected', material, selected: candidateMaterial };
    }
  }
  return {
    kind: 'missing',
    material: buildEcdsaMaterialStateForCandidate({
      candidate: args.candidate,
      record: undefined,
      keyRef: undefined,
      authMethod: SIGNER_AUTH_METHODS.passkey,
      source: 'manual-bootstrap',
      chainTarget: args.chainTarget,
      materialChainTarget: args.materialChainTarget,
    }),
  };
}

function selectSessionSourceForWalletAuth(args: {
  emailOtpRecord?: ThresholdEcdsaSessionRecord;
  emailOtpKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  passkeySelection: PasskeyMaterialDiagnosticsSelection;
}): { sessionSource?: string; isEmailOtpThresholdContext?: boolean } {
  const hasEmailOtpVisible = Boolean(args.emailOtpRecord || args.emailOtpKeyRef);
  const hasPasskeyVisible = args.passkeySelection.kind === 'selected';
  if (hasEmailOtpVisible === hasPasskeyVisible) return {};
  if (hasEmailOtpVisible) {
    return {
      sessionSource: args.emailOtpRecord?.source || SIGNER_AUTH_METHODS.emailOtp,
      isEmailOtpThresholdContext: true,
    };
  }
  if (args.passkeySelection.kind !== 'selected') return {};
  return {
    sessionSource:
      args.passkeySelection.selected.record.source || args.passkeySelection.selected.source,
    isEmailOtpThresholdContext: false,
  };
}

export async function resolveEvmFamilyEcdsaSigningSelection(args: {
  deps: EvmFamilyEcdsaSigningSelectionDeps;
  walletId: string;
  subjectId: WalletSubjectId;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  authMethod: EvmFamilyEcdsaAuthMethod;
  laneCandidate: EcdsaLaneCandidate;
  allowMissingHotMaterial?: boolean;
}): Promise<EvmFamilyEcdsaSigningSelectionResult> {
  const lane = signingLaneFromExactLaneCandidate(args.laneCandidate);
  const materialChainTarget =
    args.laneCandidate.source === 'evm_family_shared_key'
      ? args.laneCandidate.sourceChainTarget
      : args.chainTarget;
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
    chainTarget: materialChainTarget,
  });
  const emailOtpKeyRef = tryGetEmailOtpThresholdEcdsaKeyRefForSigning({
    deps: args.deps,
    subjectId: args.subjectId,
    chainTarget: materialChainTarget,
  });
  const passkeyVisibleMaterials = listPasskeyVisibleMaterials({
    deps: args.deps,
    subjectId: args.subjectId,
    chainTarget: materialChainTarget,
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
          materialChainTarget,
        })
      : selectPasskeyMaterialForCandidate({
          candidate: args.laneCandidate,
          exactRecord: exactRecordForCandidate,
          exactKeyRef: exactKeyRefForCandidate,
          exactSource:
            exactRecordForCandidate?.source || exactKeyRefMatchForCandidate?.source || undefined,
          passkeyVisibleMaterials,
          chainTarget: args.chainTarget,
          materialChainTarget,
        }).material;

  const selectedPasskeyMaterial: PasskeyMaterialDiagnosticsSelection =
    args.laneCandidate.authMethod === SIGNER_AUTH_METHODS.emailOtp
      ? { kind: 'not_applicable', reason: 'email_otp_candidate' }
      : selectPasskeyMaterialForCandidate({
          candidate: args.laneCandidate,
          exactRecord: exactRecordForCandidate,
          exactKeyRef: exactKeyRefForCandidate,
          exactSource:
            exactRecordForCandidate?.source || exactKeyRefMatchForCandidate?.source || undefined,
          passkeyVisibleMaterials,
          chainTarget: args.chainTarget,
          materialChainTarget,
        });

  const walletAuthInputs = selectSessionSourceForWalletAuth({
    ...(emailOtpRecord ? { emailOtpRecord } : {}),
    ...(emailOtpKeyRef ? { emailOtpKeyRef } : {}),
    passkeySelection: selectedPasskeyMaterial,
  });
  const walletAuth = await resolveEvmFamilyTransactionWalletAuth({
    deps: args.deps,
    walletId: args.walletId,
    senderSignatureAlgorithm: args.senderSignatureAlgorithm,
    ...(walletAuthInputs.sessionSource ? { sessionSource: walletAuthInputs.sessionSource } : {}),
    ...(typeof walletAuthInputs.isEmailOtpThresholdContext === 'boolean'
      ? { isEmailOtpThresholdContext: walletAuthInputs.isEmailOtpThresholdContext }
      : {}),
  });
  const selectedAccountAuth = walletAuthWithSelectedPrimary(
    walletAuth,
    args.laneCandidate.authMethod,
  );

  const diagnostics = buildEcdsaSelectionDiagnostics({
    candidate: args.laneCandidate,
    exactCandidateMaterial,
    ...(emailOtpRecord ? { emailOtpRecord } : {}),
    ...(emailOtpKeyRef ? { emailOtpKeyRef } : {}),
    passkeyVisibleMaterials,
    materialChainTarget,
    passkeySelection: selectedPasskeyMaterial,
  });
  try {
    console.info('[SigningEngine][ecdsa][selection]', {
      walletId: args.walletId,
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
    return reauthRequiredSelection({
      accountAuth: selectedAccountAuth,
      candidate: args.laneCandidate,
      lane,
      material: exactCandidateMaterial,
      materialChainTarget,
      reason: 'expired',
      diagnostics,
    });
  }

  if (args.laneCandidate.state === 'exhausted') {
    return reauthRequiredSelection({
      accountAuth: selectedAccountAuth,
      candidate: args.laneCandidate,
      lane,
      material: exactCandidateMaterial,
      materialChainTarget,
      reason: 'exhausted',
      diagnostics,
    });
  }

  if (
    exactCandidateMaterial.kind === 'ready_material' &&
    args.laneCandidate.authMethod === SIGNER_AUTH_METHODS.emailOtp &&
    isSingleUseEmailOtpEcdsaRecord(exactCandidateMaterial.record)
  ) {
    return reauthRequiredSelection({
      accountAuth: selectedAccountAuth,
      candidate: args.laneCandidate,
      lane,
      material: exactCandidateMaterial,
      materialChainTarget,
      reason: 'single_use_email_otp',
      diagnostics,
    });
  }

  if (exactCandidateMaterial.kind !== 'ready_material') {
    return reauthRequiredSelection({
      accountAuth: selectedAccountAuth,
      candidate: args.laneCandidate,
      lane,
      material: exactCandidateMaterial,
      materialChainTarget,
      reason: 'missing_hot_material',
      diagnostics,
    });
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
