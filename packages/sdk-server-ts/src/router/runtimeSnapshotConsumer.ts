import type {
  RouterApiRuntimeSnapshotEnvelope,
  RouterApiRuntimeSnapshotConsumer,
  RouterApiRuntimePolicyScope,
} from './routerApi';
import type { ThresholdRuntimeSnapshotExpectation } from '../core/types';

type RuntimeSnapshotValidationErrorCode =
  | 'runtime_snapshots_not_configured'
  | 'runtime_snapshot_scope_missing'
  | 'runtime_snapshot_invalid_expectation'
  | 'runtime_snapshot_not_found'
  | 'runtime_snapshot_id_mismatch'
  | 'runtime_snapshot_version_mismatch'
  | 'runtime_snapshot_checksum_mismatch';

type RuntimeSnapshotValidationResult =
  | { ok: true }
  | { ok: false; code: RuntimeSnapshotValidationErrorCode; message: string };

export interface RouterApiRuntimeSnapshotPublishedUpdate {
  scope: RouterApiRuntimePolicyScope;
  envelope: RouterApiRuntimeSnapshotEnvelope;
}

export interface InMemoryRouterApiRuntimeSnapshotConsumer {
  runtimeSnapshots: RouterApiRuntimeSnapshotConsumer;
  applyPublishedUpdate: (update: RouterApiRuntimeSnapshotPublishedUpdate) => void;
  applyOutboxEvent: (event: { payload: unknown }) => RouterApiRuntimeSnapshotPublishedUpdate;
}

function parseExpectation(
  raw: unknown,
): { parsed: ThresholdRuntimeSnapshotExpectation | null; error?: string } {
  if (raw === undefined || raw === null) return { parsed: null };
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { parsed: null, error: 'runtimeSnapshot must be an object when provided' };
  }
  const row = raw as Record<string, unknown>;
  const snapshotId = String(row.snapshotId || '').trim();
  const checksum = String(row.checksum || '').trim();
  const hasVersion = row.version !== undefined && row.version !== null;
  let version: number | undefined;
  if (hasVersion) {
    const parsed = Number(row.version);
    if (!Number.isFinite(parsed) || parsed <= 0 || Math.floor(parsed) !== parsed) {
      return {
        parsed: null,
        error: 'runtimeSnapshot.version must be a positive integer when provided',
      };
    }
    version = parsed;
  }
  if (row.snapshotId !== undefined && !snapshotId) {
    return { parsed: null, error: 'runtimeSnapshot.snapshotId must be a non-empty string' };
  }
  if (row.checksum !== undefined && !checksum) {
    return { parsed: null, error: 'runtimeSnapshot.checksum must be a non-empty string' };
  }
  if (!snapshotId && !checksum && version === undefined) {
    return {
      parsed: null,
      error:
        'runtimeSnapshot must include at least one of snapshotId, version, or checksum when provided',
    };
  }
  return {
    parsed: {
      ...(snapshotId ? { snapshotId } : {}),
      ...(version !== undefined ? { version } : {}),
      ...(checksum ? { checksum } : {}),
    },
  };
}

export async function validateRuntimeSnapshotExpectation(input: {
  runtimeSnapshots: RouterApiRuntimeSnapshotConsumer | null | undefined;
  scope?: RouterApiRuntimePolicyScope;
  expectationRaw: unknown;
}): Promise<RuntimeSnapshotValidationResult> {
  const expectationResult = parseExpectation(input.expectationRaw);
  if (expectationResult.error) {
    return {
      ok: false,
      code: 'runtime_snapshot_invalid_expectation',
      message: expectationResult.error,
    };
  }
  const expectation = expectationResult.parsed;
  if (!expectation) return { ok: true };
  const scope = input.scope;
  if (!scope) {
    return {
      ok: false,
      code: 'runtime_snapshot_scope_missing',
      message: 'threshold session is missing runtimePolicyScope',
    };
  }
  if (!input.runtimeSnapshots) {
    return {
      ok: false,
      code: 'runtime_snapshots_not_configured',
      message: 'Runtime snapshot consumer is not configured on this server',
    };
  }
  const latest = await input.runtimeSnapshots.getLatestSnapshot(scope);
  if (!latest) {
    return {
      ok: false,
      code: 'runtime_snapshot_not_found',
      message: `No runtime snapshot found for org=${scope.orgId} project=${scope.projectId} env=${scope.envId}`,
    };
  }
  if (expectation.snapshotId && latest.snapshotId !== expectation.snapshotId) {
    return {
      ok: false,
      code: 'runtime_snapshot_id_mismatch',
      message: `Runtime snapshot id mismatch: expected ${expectation.snapshotId}, got ${latest.snapshotId}`,
    };
  }
  if (expectation.version !== undefined && latest.version !== expectation.version) {
    return {
      ok: false,
      code: 'runtime_snapshot_version_mismatch',
      message: `Runtime snapshot version mismatch: expected ${expectation.version}, got ${latest.version}`,
    };
  }
  if (expectation.checksum && latest.checksum !== expectation.checksum) {
    return {
      ok: false,
      code: 'runtime_snapshot_checksum_mismatch',
      message: `Runtime snapshot checksum mismatch: expected ${expectation.checksum}, got ${latest.checksum}`,
    };
  }
  return { ok: true };
}

function makeScopeKey(scope: RouterApiRuntimePolicyScope): string {
  return `${scope.orgId}::${scope.projectId}::${scope.envId}`;
}

function parsePublishedUpdateFromOutboxPayload(
  payloadRaw: unknown,
): RouterApiRuntimeSnapshotPublishedUpdate | null {
  if (!payloadRaw || typeof payloadRaw !== 'object' || Array.isArray(payloadRaw)) return null;
  const payload = payloadRaw as Record<string, unknown>;
  const snapshotRaw = payload.snapshot;
  if (!snapshotRaw || typeof snapshotRaw !== 'object' || Array.isArray(snapshotRaw)) return null;
  const snapshot = snapshotRaw as Record<string, unknown>;

  const orgId = String(snapshot.orgId || '').trim();
  const envId = String(snapshot.envId || snapshot.environmentId || '').trim();
  const projectId = String(snapshot.projectId || '').trim();
  const signingRootVersion = String(snapshot.signingRootVersion || '').trim();
  const snapshotId = String(snapshot.snapshotId || '').trim();
  const checksum = String(snapshot.checksum || '').trim();
  const effectiveAt = String(snapshot.effectiveAt || '').trim();
  const versionRaw = Number(snapshot.version);
  if (
    !orgId ||
    !projectId ||
    !envId ||
    !signingRootVersion ||
    !snapshotId ||
    !checksum ||
    !effectiveAt ||
    !Number.isFinite(versionRaw) ||
    versionRaw <= 0 ||
    Math.floor(versionRaw) !== versionRaw
  ) {
    return null;
  }
  return {
    scope: {
      orgId,
      projectId,
      envId,
      signingRootVersion,
    },
    envelope: {
      snapshotId,
      version: versionRaw,
      checksum,
      effectiveAt,
    },
  };
}

export function createInMemoryRouterApiRuntimeSnapshotConsumer(): InMemoryRouterApiRuntimeSnapshotConsumer {
  const latestByScope = new Map<string, RouterApiRuntimeSnapshotEnvelope>();

  return {
    runtimeSnapshots: {
      async getLatestSnapshot(scope): Promise<RouterApiRuntimeSnapshotEnvelope | null> {
        const latest = latestByScope.get(makeScopeKey(scope));
        return latest
          ? {
              snapshotId: latest.snapshotId,
              version: latest.version,
              checksum: latest.checksum,
              effectiveAt: latest.effectiveAt,
            }
          : null;
      },
    },
    applyPublishedUpdate(update): void {
      latestByScope.set(makeScopeKey(update.scope), {
        snapshotId: update.envelope.snapshotId,
        version: update.envelope.version,
        checksum: update.envelope.checksum,
        effectiveAt: update.envelope.effectiveAt,
      });
    },
    applyOutboxEvent(event): RouterApiRuntimeSnapshotPublishedUpdate {
      const parsed = parsePublishedUpdateFromOutboxPayload(event.payload);
      if (!parsed) {
        throw new Error('Invalid runtime snapshot outbox payload');
      }
      latestByScope.set(makeScopeKey(parsed.scope), parsed.envelope);
      return parsed;
    },
  };
}
