import type {
  ClearAllVolatileWarmSessionMaterialCommand,
  ClearVolatileWarmMaterialCommand,
  ClearVolatileWarmSessionMaterialCommand,
  VolatileWarmSessionMaterialClearAll,
  VolatileWarmSessionMaterialClearer,
} from './uiConfirm.types';
import type {
  DeleteDurableSealedSessionCommand,
  DurableSealedSessionDeleteReason,
} from '../session/persistence/durableSealedSessionCommands';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import { createClearVolatileWarmSessionMaterialCommand } from '../session/warmCapabilities/volatileWarmMaterialCommands';
import { parseThresholdEd25519SessionId } from '@shared/utils/domainIds';

const parsedThresholdSessionId = parseThresholdEd25519SessionId('threshold-session-1');
if (!parsedThresholdSessionId.ok) throw new Error('expected threshold session id');
const volatileSessionId = parsedThresholdSessionId.value;

const clearSessionCommand: ClearVolatileWarmSessionMaterialCommand =
  createClearVolatileWarmSessionMaterialCommand(volatileSessionId);

const clearAllCommand: ClearAllVolatileWarmSessionMaterialCommand = {
  kind: 'clear_volatile_warm_material',
  scope: { kind: 'all' },
};

const volatileSessionClearer: VolatileWarmSessionMaterialClearer = {
  clearVolatileWarmSessionMaterial: async () => undefined,
};

const volatileAllClearer: VolatileWarmSessionMaterialClearAll = {
  clearAllVolatileWarmSessionMaterial: async () => undefined,
};

declare const materialActivation: MpcMaterialActivationRef;

const durableDeleteCommand: DeleteDurableSealedSessionCommand = {
  kind: 'delete_durable_sealed_session',
  durableRecord: {
    authMethod: 'passkey',
    curve: 'ed25519',
    materialActivation,
  },
  deleteReason: 'trusted_persisted_delete',
  preserveResolvedIdentity: false,
};

void volatileSessionClearer.clearVolatileWarmSessionMaterial(clearSessionCommand);
void volatileAllClearer.clearAllVolatileWarmSessionMaterial(clearAllCommand);
void durableDeleteCommand;

const invalidVolatileDeleteCommand: ClearVolatileWarmMaterialCommand = {
  kind: 'clear_volatile_warm_material',
  scope: { kind: 'session', thresholdSessionId: volatileSessionId },
  // @ts-expect-error Volatile clears cannot carry durable sealed-record identity.
  durableRecord: {},
};

void invalidVolatileDeleteCommand;

const invalidVolatileDeleteReasonCommand: ClearVolatileWarmMaterialCommand = {
  kind: 'clear_volatile_warm_material',
  scope: { kind: 'session', thresholdSessionId: volatileSessionId },
  // @ts-expect-error Volatile clears cannot carry durable delete reasons.
  deleteReason: 'trusted_persisted_delete',
};

void invalidVolatileDeleteReasonCommand;

const invalidRawVolatileSessionCommand: ClearVolatileWarmSessionMaterialCommand = {
  kind: 'clear_volatile_warm_material',
  scope: {
    kind: 'session',
    // @ts-expect-error Volatile clear commands require a parsed volatile session id.
    sessionId: 'threshold-session-raw',
  },
};

void invalidRawVolatileSessionCommand;

// @ts-expect-error Session clearers cannot receive all-scope commands.
void volatileSessionClearer.clearVolatileWarmSessionMaterial(clearAllCommand);

// @ts-expect-error All clearers cannot receive session-scope commands.
void volatileAllClearer.clearAllVolatileWarmSessionMaterial(clearSessionCommand);

const invalidDurableDeleteCommand: DeleteDurableSealedSessionCommand = {
  kind: 'delete_durable_sealed_session',
  durableRecord: {
    authMethod: 'passkey',
    curve: 'ed25519',
    materialActivation,
  },
  deleteReason: 'trusted_persisted_delete',
  preserveResolvedIdentity: false,
  // @ts-expect-error Durable deletes cannot carry volatile clear scopes.
  scope: { kind: 'session', thresholdSessionId: volatileSessionId },
};

void invalidDurableDeleteCommand;

const invalidEd25519DurableIdentity: DeleteDurableSealedSessionCommand = {
  kind: 'delete_durable_sealed_session',
  // @ts-expect-error Ed25519 durable identity is keyed by activation, never a threshold session.
  durableRecord: {
    authMethod: 'passkey',
    curve: 'ed25519',
    materialActivation,
    thresholdSessionId: 'threshold-session-1',
  },
  deleteReason: 'trusted_persisted_delete',
  preserveResolvedIdentity: false,
};
void invalidEd25519DurableIdentity;

const invalidDurableEcdsaCommand: DeleteDurableSealedSessionCommand = {
  kind: 'delete_durable_sealed_session',
  durableRecord: {
    authMethod: 'passkey',
    curve: 'ecdsa',
    thresholdSessionId: 'threshold-session-1',
    // @ts-expect-error ECDSA durable deletes require an exact chain target.
    chainTarget: undefined,
  },
  deleteReason: 'trusted_persisted_delete',
  preserveResolvedIdentity: false,
};

void invalidDurableEcdsaCommand;

function assertNever(value: never): never {
  throw new Error(String(value));
}

function durableDeleteReasonLabel(reason: DurableSealedSessionDeleteReason): string {
  switch (reason) {
    case 'account_removed':
    case 'device_removed':
    case 'expired':
    case 'exhausted':
    case 'invalid_persisted_record':
    case 'migration_rejected':
    case 'trusted_persisted_delete':
      return reason;
    default:
      return assertNever(reason);
  }
}

void durableDeleteReasonLabel('trusted_persisted_delete');
