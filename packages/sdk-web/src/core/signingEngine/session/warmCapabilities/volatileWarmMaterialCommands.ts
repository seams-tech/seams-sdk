import type {
  ClearAllVolatileWarmSessionMaterialCommand,
  ClearVolatileWarmMaterialCommand,
  ClearVolatileWarmSessionMaterialCommand,
  VolatileWarmSessionScope,
} from '../../uiConfirm/types';
import {
  parseVolatileWarmSessionId,
  type VolatileWarmSessionId,
} from './volatileWarmSessionId';

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : null;
}

export function parseVolatileWarmSessionScope(value: unknown): VolatileWarmSessionScope | null {
  const raw = asRecord(value);
  if (!raw) return null;
  if (raw.kind === 'all') return { kind: 'all' };
  if (raw.kind !== 'session') return null;
  const sessionId = parseVolatileWarmSessionId(raw.sessionId);
  if (!sessionId) return null;
  return {
    kind: 'session',
    sessionId,
  };
}

export function parseClearVolatileWarmMaterialCommand(
  value: unknown,
): ClearVolatileWarmMaterialCommand | null {
  const raw = asRecord(value);
  if (!raw || raw.kind !== 'clear_volatile_warm_material') return null;
  if (raw.durableRecord != null || raw.resolvedIdentity != null || raw.deleteReason != null) {
    return null;
  }
  const scope = parseVolatileWarmSessionScope(raw.scope);
  if (!scope) return null;
  return {
    kind: 'clear_volatile_warm_material',
    scope,
  };
}

export function createClearVolatileWarmSessionMaterialCommand(
  sessionId: VolatileWarmSessionId,
): ClearVolatileWarmSessionMaterialCommand {
  return {
    kind: 'clear_volatile_warm_material',
    scope: {
      kind: 'session',
      sessionId,
    },
  };
}

export function createClearAllVolatileWarmSessionMaterialCommand(): ClearAllVolatileWarmSessionMaterialCommand {
  return {
    kind: 'clear_volatile_warm_material',
    scope: {
      kind: 'all',
    },
  };
}
