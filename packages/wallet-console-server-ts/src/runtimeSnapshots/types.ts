export interface ConsoleRuntimeSnapshotPayload {
  policy: Record<string, unknown>;
  gasSponsorship: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface ConsoleRuntimeSnapshot {
  orgId: string;
  projectId: string | null;
  environmentId: string;
  snapshotId: string;
  version: number;
  effectiveAt: string;
  checksum: string;
  payload: ConsoleRuntimeSnapshotPayload;
  createdAt: string;
  createdBy: string;
}

export interface ListConsoleRuntimeSnapshotsRequest {
  environmentId: string;
  projectId?: string;
  limit?: number;
}

export interface GetLatestConsoleRuntimeSnapshotRequest {
  environmentId: string;
  projectId?: string;
}

export interface PublishConsoleRuntimeSnapshotRequest {
  environmentId: string;
  projectId?: string;
  snapshotId?: string;
  effectiveAt?: string;
  payload: ConsoleRuntimeSnapshotPayload;
}

export interface PublishCurrentConsoleRuntimeSnapshotRequest {
  environmentId: string;
  projectId?: string;
  snapshotId?: string;
  effectiveAt?: string;
}

export interface ConsoleRuntimeSnapshotOutboxEvent {
  namespace: string;
  orgId: string;
  projectId: string | null;
  environmentId: string;
  eventId: string;
  eventType: 'RUNTIME_SNAPSHOT_PUBLISHED_V1';
  snapshotId: string;
  snapshotVersion: number;
  payload: Record<string, unknown>;
  createdAt: string;
  dispatchedAt: string | null;
}

export interface ConsoleRuntimeSnapshotOutboxDispatchFailure {
  orgId: string;
  eventId: string;
  code: string;
  message: string;
}

export interface ConsoleRuntimeSnapshotOutboxDispatchResult {
  namespace: string;
  orgCount: number;
  dispatchedCount: number;
  failureCount: number;
  failures: ConsoleRuntimeSnapshotOutboxDispatchFailure[];
}
