import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type {
  EcdsaLaneCandidate,
  ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import { laneCandidateAuthMethod } from '../../session/identity/laneIdentity';
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
  findExactEcdsaSessionRecordForSelectedLane,
  logEvmFamilyEcdsaLaneDiagnostic,
  requireResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaLane,
  tryGetEmailOtpThresholdEcdsaSessionRecordForSigning,
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
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type { WalletBudgetUnknown } from '../../session/budget/budgetProjection';
import type { ReauthAnchorIdentity } from '../../session/operationState/transactionState';

const PASSKEY_ECDSA_SIGNING_SOURCE_PRIORITY = [
  'login',
  'manual-bootstrap',
  'registration',
] as const satisfies readonly PasskeyEcdsaSessionStoreSource[];

export type EvmFamilyEcdsaSigningSelectionDeps = EvmFamilyAccountMetadataDeps &
  EvmFamilyEcdsaSessionReaderDeps;

type EcdsaSelectionLaneCandidateDiagnosticsBase = {
  authMethod: EvmFamilyEcdsaAuthMethod;
  chain: EcdsaLaneCandidate['chain'];
  chainTarget: ThresholdEcdsaChainTarget;
  state: EcdsaLaneCandidate['state'];
  signingGrantId: string;
  thresholdSessionId: string;
  remainingUses: number | null;
  expiresAtMs: number | null;
  updatedAtMs: number | null;
};

function ecdsaLaneCandidateAuthMethod(candidate: EcdsaLaneCandidate): EvmFamilyEcdsaAuthMethod {
  const authMethod = laneCandidateAuthMethod(candidate);
  switch (authMethod) {
    case SIGNER_AUTH_METHODS.emailOtp:
      return SIGNER_AUTH_METHODS.emailOtp;
    case SIGNER_AUTH_METHODS.passkey:
      return SIGNER_AUTH_METHODS.passkey;
  }
  authMethod satisfies never;
  throw new Error('[SigningEngine][ecdsa] unsupported ECDSA lane auth method');
}

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
  reason: 'missing_hot_material' | 'expired' | 'exhausted';
  diagnostics: EcdsaSelectionDiagnostics;
};

type ReauthAnchorBackedEvmFamilyEcdsaSigningSelection = {
  reason: 'expired' | 'exhausted';
  reauthAnchor: ReauthAnchorIdentity;
};

type MaterialBackedEvmFamilyEcdsaSigningSelection = {
  reason: 'missing_hot_material';
  reauthAnchor?: never;
};

export type ReauthRequiredEvmFamilyEcdsaSigningSelection =
  | (ReauthRequiredEvmFamilyEcdsaSigningSelectionBase &
      ReauthAnchorBackedEvmFamilyEcdsaSigningSelection & {
        authMethod: 'email_otp';
        reauthAuthority: EmailOtpEcdsaReauthAuthority;
      })
  | (ReauthRequiredEvmFamilyEcdsaSigningSelectionBase &
      ReauthAnchorBackedEvmFamilyEcdsaSigningSelection & {
        authMethod: 'passkey';
        reauthAuthority?: never;
      })
  | (ReauthRequiredEvmFamilyEcdsaSigningSelectionBase &
      MaterialBackedEvmFamilyEcdsaSigningSelection & {
      authMethod: 'email_otp';
      reauthAuthority: EmailOtpEcdsaReauthAuthority;
    })
  | (ReauthRequiredEvmFamilyEcdsaSigningSelectionBase &
      MaterialBackedEvmFamilyEcdsaSigningSelection & {
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
  reauthAnchor?: ReauthAnchorIdentity;
  diagnostics: EcdsaSelectionDiagnostics;
}): ReauthRequiredEvmFamilyEcdsaSigningSelection {
  const common = {
    kind: 'reauth_required' as const,
    accountAuth: args.accountAuth,
    lane: args.lane,
    material: args.material,
    diagnostics: args.diagnostics,
  };
  if (args.reason === 'expired' || args.reason === 'exhausted') {
    if (!args.reauthAnchor) {
      throw new Error('[SigningEngine][ecdsa] exhausted/expired reauth requires a reauth anchor');
    }
    const base = {
      ...common,
      reason: args.reason,
      reauthAnchor: args.reauthAnchor,
    };
    if (ecdsaLaneCandidateAuthMethod(args.candidate) === SIGNER_AUTH_METHODS.emailOtp) {
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
  const base = {
    ...common,
    reason: args.reason,
  };
  if (ecdsaLaneCandidateAuthMethod(args.candidate) === SIGNER_AUTH_METHODS.emailOtp) {
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
    keyHandle: candidate.keyHandle,
    walletId: candidate.walletId,
    chainTarget: candidate.chainTarget,
    signingGrantId: SigningSessionIds.signingGrant(
      candidate.signingGrantId,
    ),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(candidate.thresholdSessionId),
  };
  const lane = buildLane(
    candidate.auth.kind === 'email_otp'
      ? {
          ...base,
          auth: candidate.auth,
          retention: 'session',
          sessionOrigin: 'per_operation',
        }
      : {
          ...base,
          auth: candidate.auth,
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
    authMethod: ecdsaLaneCandidateAuthMethod(candidate),
    chain: candidate.chain,
    chainTarget: candidate.chainTarget,
    state: candidate.state,
    signingGrantId: candidate.signingGrantId,
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
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
}): PasskeyVisibleMaterial[] {
  const candidates: PasskeyVisibleMaterial[] = [];
  for (const source of PASSKEY_ECDSA_SIGNING_SOURCE_PRIORITY) {
    const record = tryGetPasskeyThresholdEcdsaSessionRecordForSigning({
      deps: args.deps,
      walletId: args.walletId,
      chainTarget: args.chainTarget,
      source,
    });
    if (!record) continue;
    candidates.push({
      source,
      record,
    });
  }
  return candidates;
}

function buildEcdsaSelectionDiagnostics(args: {
  candidate: EcdsaLaneCandidate;
  exactCandidateMaterial: EcdsaMaterialState;
  emailOtpRecord?: ThresholdEcdsaSessionRecord;
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
    }),
    visiblePasskeyMaterials: args.passkeyVisibleMaterials.map((material) =>
      summarizeVisibleEcdsaMaterial({
        authMethod: SIGNER_AUTH_METHODS.passkey,
        source: material.source,
        chainTarget: args.candidate.chainTarget,
        materialChainTarget: args.materialChainTarget,
        record: material.record,
      }),
    ),
    selectedPasskeyMaterial,
  };
}

function selectPasskeyMaterialForCandidate(args: {
  candidate: EcdsaLaneCandidate;
  exactRecord?: ThresholdEcdsaSessionRecord;
  exactSource?: ThresholdEcdsaSessionStoreSource;
  passkeyVisibleMaterials: readonly PasskeyVisibleMaterial[];
  chainTarget: ThresholdEcdsaChainTarget;
  materialChainTarget: ThresholdEcdsaChainTarget;
}): PasskeyMaterialSelectionResult {
  if (args.exactRecord) {
    const exactSource = passkeySessionStoreSourceFromExactSource(args.exactSource);
    const exactMaterial = buildEcdsaMaterialStateForCandidate({
      candidate: args.candidate,
      record: args.exactRecord,
      authMethod: SIGNER_AUTH_METHODS.passkey,
      source: exactSource,
      chainTarget: args.chainTarget,
      materialChainTarget: args.materialChainTarget,
    });
    if (exactMaterial.kind === 'ready_to_sign') {
      return {
        kind: 'selected',
        material: exactMaterial,
        selected: {
          source: exactSource,
          record: exactMaterial.record,
        },
      };
    }
    if (exactMaterial.kind === 'reauth_required') {
      return {
        kind: 'selected',
        material: exactMaterial,
        selected: {
          source: exactSource,
          record: exactMaterial.record,
        },
      };
    }
  }
  for (const candidateMaterial of args.passkeyVisibleMaterials) {
    const material = buildEcdsaMaterialStateForCandidate({
      candidate: args.candidate,
      record: candidateMaterial.record,
      authMethod: SIGNER_AUTH_METHODS.passkey,
      source: candidateMaterial.source,
      chainTarget: args.chainTarget,
      materialChainTarget: args.materialChainTarget,
    });
    if (material.kind === 'ready_to_sign') {
      return { kind: 'selected', material, selected: candidateMaterial };
    }
    if (material.kind === 'reauth_required') {
      return { kind: 'selected', material, selected: candidateMaterial };
    }
  }
  return {
    kind: 'missing',
    material: buildEcdsaMaterialStateForCandidate({
      candidate: args.candidate,
      record: undefined,
      authMethod: SIGNER_AUTH_METHODS.passkey,
      source: 'manual-bootstrap',
      chainTarget: args.chainTarget,
      materialChainTarget: args.materialChainTarget,
    }),
  };
}

function selectSessionSourceForWalletAuth(args: {
  emailOtpRecord?: ThresholdEcdsaSessionRecord;
  passkeySelection: PasskeyMaterialDiagnosticsSelection;
}): { sessionSource?: string; isEmailOtpThresholdContext?: boolean } {
  const hasEmailOtpVisible = Boolean(args.emailOtpRecord);
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
  walletId: WalletId;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  authMethod: EvmFamilyEcdsaAuthMethod;
  laneCandidate: EcdsaLaneCandidate;
  reauthAnchor?: ReauthAnchorIdentity;
  allowMissingHotMaterial?: boolean;
}): Promise<EvmFamilyEcdsaSigningSelectionResult> {
  const lane = signingLaneFromExactLaneCandidate(args.laneCandidate);
  const materialChainTarget =
    args.laneCandidate.source === 'evm_family_shared_key'
      ? args.laneCandidate.sourceChainTarget
      : args.chainTarget;
  const exactRecordForCandidate =
    args.laneCandidate.source === 'evm_family_shared_key'
      ? undefined
      : findExactEcdsaSessionRecordForSelectedLane({
          deps: args.deps,
          lane,
        });

  const emailOtpRecord = tryGetEmailOtpThresholdEcdsaSessionRecordForSigning({
    deps: args.deps,
    walletId: args.walletId,
    chainTarget: materialChainTarget,
  });
  const candidateAuthMethod = ecdsaLaneCandidateAuthMethod(args.laneCandidate);
  const visibleEmailOtpRecord =
    emailOtpRecord ||
    (candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp &&
    exactRecordForCandidate?.source === SIGNER_AUTH_METHODS.emailOtp
      ? exactRecordForCandidate
      : undefined);
  const passkeyVisibleMaterials = listPasskeyVisibleMaterials({
    deps: args.deps,
    walletId: args.walletId,
    chainTarget: materialChainTarget,
  });
  const exactCandidateMaterial =
    candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp
      ? buildEcdsaMaterialStateForCandidate({
          candidate: args.laneCandidate,
          record:
            args.laneCandidate.source === 'evm_family_shared_key'
              ? emailOtpRecord
              : exactRecordForCandidate,
          authMethod: SIGNER_AUTH_METHODS.emailOtp,
          source: SIGNER_AUTH_METHODS.emailOtp,
          chainTarget: args.chainTarget,
          materialChainTarget,
        })
      : selectPasskeyMaterialForCandidate({
          candidate: args.laneCandidate,
          exactRecord: exactRecordForCandidate,
          exactSource: exactRecordForCandidate?.source || undefined,
          passkeyVisibleMaterials,
          chainTarget: args.chainTarget,
          materialChainTarget,
        }).material;

  const selectedPasskeyMaterial: PasskeyMaterialDiagnosticsSelection =
    candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp
      ? { kind: 'not_applicable', reason: 'email_otp_candidate' }
      : selectPasskeyMaterialForCandidate({
          candidate: args.laneCandidate,
          exactRecord: exactRecordForCandidate,
          exactSource: exactRecordForCandidate?.source || undefined,
          passkeyVisibleMaterials,
          chainTarget: args.chainTarget,
          materialChainTarget,
        });

  const walletAuthInputs = selectSessionSourceForWalletAuth({
    ...(visibleEmailOtpRecord ? { emailOtpRecord: visibleEmailOtpRecord } : {}),
    passkeySelection: selectedPasskeyMaterial,
  });
  const walletAuth = await resolveEvmFamilyTransactionWalletAuth({
    deps: args.deps,
    walletId: args.walletId,
    senderSignatureAlgorithm: args.senderSignatureAlgorithm,
    chainTarget: args.chainTarget,
    ...(walletAuthInputs.sessionSource ? { sessionSource: walletAuthInputs.sessionSource } : {}),
    ...(typeof walletAuthInputs.isEmailOtpThresholdContext === 'boolean'
      ? { isEmailOtpThresholdContext: walletAuthInputs.isEmailOtpThresholdContext }
      : {}),
  });
  const selectedAccountAuth = walletAuthWithSelectedPrimary(
    walletAuth,
    candidateAuthMethod,
  );

  const diagnostics = buildEcdsaSelectionDiagnostics({
    candidate: args.laneCandidate,
    exactCandidateMaterial,
    ...(visibleEmailOtpRecord ? { emailOtpRecord: visibleEmailOtpRecord } : {}),
    passkeyVisibleMaterials,
    materialChainTarget,
    passkeySelection: selectedPasskeyMaterial,
  });

  if (
    !args.allowMissingHotMaterial &&
    exactEcdsaCandidateRequiresHotMaterial(args.laneCandidate) &&
    exactCandidateMaterial.kind !== 'ready_to_sign'
  ) {
    return {
      kind: 'missing_material',
      accountAuth: selectedAccountAuth,
      authMethod: candidateAuthMethod,
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
      ...(args.reauthAnchor ? { reauthAnchor: args.reauthAnchor } : {}),
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
      ...(args.reauthAnchor ? { reauthAnchor: args.reauthAnchor } : {}),
      diagnostics,
    });
  }

  if (exactCandidateMaterial.kind !== 'ready_to_sign') {
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

  if (candidateAuthMethod !== exactCandidateMaterial.authMethod) {
    logEvmFamilyEcdsaLaneDiagnostic('selected ECDSA material auth method mismatch', {
      lane: summarizeEvmFamilyEcdsaLane(lane),
      material: summarizeEcdsaMaterialState(exactCandidateMaterial),
    });
    throw new Error('[SigningEngine][ecdsa] selected ECDSA material auth method mismatch');
  }

  return {
    kind: 'ready',
    accountAuth: selectedAccountAuth,
    authMethod: candidateAuthMethod,
    source: exactCandidateMaterial.source,
    lane,
    material: exactCandidateMaterial,
    diagnostics,
  };
}
