import { expect, test } from '@playwright/test';
import {
  createInMemoryRelayRuntimeSnapshotConsumer,
  validateRuntimeSnapshotExpectation,
} from '@server/router/express-adaptor';

test.describe('runtime snapshot consumer helpers', () => {
  test('applies outbox payload and resolves latest snapshot by scope', async () => {
    const cache = createInMemoryRelayRuntimeSnapshotConsumer();
    const applied = cache.applyOutboxEvent({
      payload: {
        eventType: 'runtime_snapshot.published.v1',
        snapshot: {
          orgId: 'org-runtime-1',
          projectId: 'project-alpha',
          environmentId: 'prod',
          snapshotId: 'snap_1',
          version: 1,
          checksum: 'checksum_1',
          effectiveAt: '2026-03-01T00:00:00.000Z',
        },
      },
    });
    expect(applied.scope.orgId).toBe('org-runtime-1');
    expect(applied.envelope.snapshotId).toBe('snap_1');

    const latest = await cache.runtimeSnapshots.getLatestSnapshot({
      orgId: 'org-runtime-1',
      projectId: 'project-alpha',
      environmentId: 'prod',
    });
    expect(latest?.snapshotId).toBe('snap_1');
    expect(latest?.version).toBe(1);
    expect(latest?.checksum).toBe('checksum_1');
  });

  test('validateRuntimeSnapshotExpectation checks version/checksum against consumer', async () => {
    const cache = createInMemoryRelayRuntimeSnapshotConsumer();
    cache.applyPublishedUpdate({
      scope: {
        orgId: 'org-runtime-2',
        environmentId: 'staging',
      },
      envelope: {
        snapshotId: 'snap_2',
        version: 4,
        checksum: 'checksum_2',
        effectiveAt: '2026-03-02T00:00:00.000Z',
      },
    });

    const ok = await validateRuntimeSnapshotExpectation({
      runtimeSnapshots: cache.runtimeSnapshots,
      scope: {
        orgId: 'org-runtime-2',
        environmentId: 'staging',
      },
      expectationRaw: {
        snapshotId: 'snap_2',
        version: 4,
        checksum: 'checksum_2',
      },
    });
    expect(ok.ok).toBe(true);

    const mismatch = await validateRuntimeSnapshotExpectation({
      runtimeSnapshots: cache.runtimeSnapshots,
      scope: {
        orgId: 'org-runtime-2',
        environmentId: 'staging',
      },
      expectationRaw: {
        version: 5,
      },
    });
    expect(mismatch.ok).toBe(false);
    if (!mismatch.ok) {
      expect(mismatch.code).toBe('runtime_snapshot_version_mismatch');
    }
  });

  test('invalid outbox payload is rejected', async () => {
    const cache = createInMemoryRelayRuntimeSnapshotConsumer();
    await expect(() =>
      cache.applyOutboxEvent({
        payload: {
          eventType: 'runtime_snapshot.published.v1',
          snapshot: {
            orgId: '',
            environmentId: 'prod',
            snapshotId: '',
            version: 0,
            checksum: '',
            effectiveAt: '',
          },
        },
      }),
    ).toThrow('Invalid runtime snapshot outbox payload');
  });
});

