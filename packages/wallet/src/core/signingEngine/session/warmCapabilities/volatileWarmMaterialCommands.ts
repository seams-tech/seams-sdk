import type {
  ClearAllVolatileWarmSessionMaterialCommand,
  ClearVolatileWarmMaterialCommand,
  ClearVolatileWarmSessionMaterialCommand,
  VolatileWarmSessionScope,
} from '../../uiConfirm/uiConfirm.types';
import {
  parseThresholdSessionId,
  type ThresholdSessionId,
} from '@shared/utils/domainIds';

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : null;
}

export function parseVolatileWarmSessionScope(value: unknown): VolatileWarmSessionScope | null {
  const raw = asRecord(value);
  if (!raw) return null;
  if (raw.kind === 'all') return { kind: 'all' };
  if (raw.kind !== 'session') return null;
  const thresholdSessionId = parseThresholdSessionId(raw.thresholdSessionId);
  if (!thresholdSessionId.ok) return null;
  return {
    kind: 'session',
    thresholdSessionId: thresholdSessionId.value,
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
  thresholdSessionId: ThresholdSessionId,
): ClearVolatileWarmSessionMaterialCommand {
  return {
    kind: 'clear_volatile_warm_material',
    scope: {
      kind: 'session',
      thresholdSessionId,
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
