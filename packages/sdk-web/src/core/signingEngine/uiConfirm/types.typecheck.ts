import type {
  ClearAllVolatileWarmSessionMaterialCommand,
  ClearVolatileWarmMaterialCommand,
  ClearVolatileWarmSessionMaterialCommand,
  DurableSealedSessionRecordDeleter,
  VolatileWarmSessionMaterialClearAll,
  VolatileWarmSessionMaterialClearer,
} from './uiConfirm.types';
import type {
  DeleteDurableSealedSessionCommand,
  DurableSealedSessionDeleteReason,
} from '../session/persistence/durableSealedSessionCommands';
import { createClearVolatileWarmSessionMaterialCommand } from '../session/warmCapabilities/volatileWarmMaterialCommands';
import { parseVolatileWarmSessionId } from '../session/warmCapabilities/volatileWarmSessionId';

function must<T>(value: T | null): T {
  if (value == null) throw new Error('expected value');
  return value;
}

const volatileSessionId = must(parseVolatileWarmSessionId('threshold-session-1'));

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

const durableRecordDeleter: DurableSealedSessionRecordDeleter = {
  deleteDurableSealedSessionRecord: async () => undefined,
};

const durableDeleteCommand: DeleteDurableSealedSessionCommand = {
  kind: 'delete_durable_sealed_session',
  durableRecord: {
    authMethod: 'passkey',
    curve: 'ed25519',
    thresholdSessionId: 'threshold-session-1',
  },
  deleteReason: 'trusted_persisted_delete',
  preserveResolvedIdentity: false,
};

void volatileSessionClearer.clearVolatileWarmSessionMaterial(clearSessionCommand);
void volatileAllClearer.clearAllVolatileWarmSessionMaterial(clearAllCommand);
void durableRecordDeleter.deleteDurableSealedSessionRecord(durableDeleteCommand);

const invalidVolatileDeleteCommand: ClearVolatileWarmMaterialCommand = {
  kind: 'clear_volatile_warm_material',
  scope: { kind: 'session', sessionId: volatileSessionId },
  // @ts-expect-error Volatile clears cannot carry durable sealed-record identity.
  durableRecord: {},
};

void invalidVolatileDeleteCommand;

const invalidVolatileDeleteReasonCommand: ClearVolatileWarmMaterialCommand = {
  kind: 'clear_volatile_warm_material',
  scope: { kind: 'session', sessionId: volatileSessionId },
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
    thresholdSessionId: 'threshold-session-1',
  },
  deleteReason: 'trusted_persisted_delete',
  preserveResolvedIdentity: false,
  // @ts-expect-error Durable deletes cannot carry volatile clear scopes.
  scope: { kind: 'session', sessionId: volatileSessionId },
};

void invalidDurableDeleteCommand;

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
