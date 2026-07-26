import type {
  CloudflareVersionedJsonRecordPutResult,
  CloudflareVersionedJsonRecordReadResult,
} from '../../../packages/sdk-server-ts/src/router/cloudflare/versionedJsonRecordStore';
import type { SessionAdapter } from '../../../packages/sdk-server-ts/src/router/routerApi';
import type {
  RouterAbEd25519YaoRegistrationSideEffectRecordV1,
  RouterAbEd25519YaoRegistrationSideEffectStoreV1,
} from '../../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRegistrationSideEffectBoundary';
import {
  createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
  type RouterAbEd25519YaoProductRegistrationPartitionBatchResultV1,
  type RouterAbEd25519YaoProductRegistrationPartitionMutationV1,
  type RouterAbEd25519YaoProductRegistrationPartitionRecordStoreV1,
  type RouterAbEd25519YaoProductRegistrationPartitionRecordV1,
  type RouterAbEd25519YaoProductRegistrationPartitionedStateCommitInputV1,
  type RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1,
  type RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
  type RouterAbEd25519YaoProductRegistrationPartitionedStateV1,
} from '../../../packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistrationPartitionedStateStore';

type StoredSideEffect<T, P = undefined> = {
  readonly version: number;
  readonly value: RouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P>;
};

export class RegistrationSideEffectMemoryStore<T, P = undefined>
  implements RouterAbEd25519YaoRegistrationSideEffectStoreV1<T, P>
{
  readonly records = new Map<string, StoredSideEffect<T, P>>();
  claimWinner: RouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P> | null = null;
  terminalWinner: RouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P> | null = null;
  readonly throwReadCalls = new Set<number>();
  throwReads = 0;
  throwClaimPuts = 0;
  throwTerminalPuts = 0;
  private readCalls = 0;

  async read(
    key: string,
  ): Promise<
    CloudflareVersionedJsonRecordReadResult<RouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P>>
  > {
    this.readCalls += 1;
    if (this.throwReadCalls.delete(this.readCalls)) {
      throw new Error('side-effect read unavailable');
    }
    if (this.throwReads > 0) {
      this.throwReads -= 1;
      throw new Error('side-effect read unavailable');
    }
    const record = this.records.get(key);
    return record
      ? {
          kind: 'present',
          value: structuredClone(record.value),
          version: String(record.version),
        }
      : { kind: 'missing' };
  }

  async put(
    key: string,
    value: RouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P>,
    expectedVersion: string | null,
  ): Promise<CloudflareVersionedJsonRecordPutResult> {
    if (
      value.kind === 'router_ab_ed25519_yao_registration_side_effect_claim_v1' &&
      this.throwClaimPuts > 0
    ) {
      this.throwClaimPuts -= 1;
      throw new Error('side-effect claim write unavailable');
    }
    if (
      value.kind === 'router_ab_ed25519_yao_registration_side_effect_completion_v1' &&
      this.throwTerminalPuts > 0
    ) {
      this.throwTerminalPuts -= 1;
      throw new Error('side-effect terminal write unavailable');
    }
    const current = this.records.get(key);
    if (
      expectedVersion === null
        ? current !== undefined
        : String(current?.version) !== expectedVersion
    ) {
      return { kind: 'version_mismatch' };
    }
    if (
      this.claimWinner &&
      value.kind === 'router_ab_ed25519_yao_registration_side_effect_claim_v1'
    ) {
      this.records.set(key, {
        version: (current?.version ?? 0) + 1,
        value: structuredClone(this.claimWinner),
      });
      this.claimWinner = null;
      return { kind: 'version_mismatch' };
    }
    if (
      this.terminalWinner &&
      value.kind === 'router_ab_ed25519_yao_registration_side_effect_completion_v1'
    ) {
      this.records.set(key, {
        version: (current?.version ?? 0) + 1,
        value: structuredClone(this.terminalWinner),
      });
      this.terminalWinner = null;
      return { kind: 'version_mismatch' };
    }
    const version = (current?.version ?? 0) + 1;
    this.records.set(key, { version, value: structuredClone(value) });
    return { kind: 'stored', version: String(version) };
  }
}

export class UnusedSessionAdapter implements SessionAdapter {
  async signJwt(): Promise<string> {
    throw new Error('Session signing is outside this fixture');
  }

  async parse(): Promise<never> {
    throw new Error('Session parsing is outside this fixture');
  }

  buildSetCookie(): string {
    throw new Error('Cookie building is outside this fixture');
  }

  buildClearCookie(): string {
    throw new Error('Cookie clearing is outside this fixture');
  }

  async refresh(): Promise<never> {
    throw new Error('Session refresh is outside this fixture');
  }
}

export class StaticWalletSessionAdapter implements SessionAdapter {
  async signJwt(): Promise<string> {
    return 'registration.wallet.session';
  }

  async parse(): Promise<never> {
    throw new Error('Session parsing is outside this fixture');
  }

  buildSetCookie(): string {
    return '';
  }

  buildClearCookie(): string {
    return '';
  }

  async refresh(): Promise<{ ok: false }> {
    return { ok: false };
  }
}

type StoredPartition = {
  readonly version: number;
  readonly value: RouterAbEd25519YaoProductRegistrationPartitionRecordV1;
};

export class RegistrationBridgePartitionRecordStore implements RouterAbEd25519YaoProductRegistrationPartitionRecordStoreV1 {
  readonly records = new Map<string, StoredPartition>();

  async readMany(keys: readonly string[]): Promise<
    readonly {
      readonly key: string;
      readonly result: CloudflareVersionedJsonRecordReadResult<RouterAbEd25519YaoProductRegistrationPartitionRecordV1>;
    }[]
  > {
    return keys.map((key) => {
      const record = this.records.get(key);
      return {
        key,
        result: record
          ? {
              kind: 'present' as const,
              value: structuredClone(record.value),
              version: String(record.version),
            }
          : { kind: 'missing' as const },
      };
    });
  }

  async putMany(
    mutations: readonly RouterAbEd25519YaoProductRegistrationPartitionMutationV1[],
  ): Promise<RouterAbEd25519YaoProductRegistrationPartitionBatchResultV1> {
    for (const mutation of mutations) {
      const current = this.records.get(mutation.key);
      if (
        mutation.expectedVersion === null
          ? current !== undefined
          : String(current?.version) !== mutation.expectedVersion
      ) {
        return { kind: 'version_mismatch', key: mutation.key };
      }
    }
    for (const mutation of mutations) {
      const current = this.records.get(mutation.key);
      this.records.set(mutation.key, {
        version: (current?.version ?? 0) + 1,
        value: structuredClone(mutation.value),
      });
    }
    return {
      kind: 'stored',
      versions: mutations.map((mutation) => ({
        key: mutation.key,
        version: String(this.records.get(mutation.key)?.version ?? 0),
      })),
    };
  }
}

export function createRegistrationBridgePartitionStore(): RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1 {
  return createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1(
    new RegistrationBridgePartitionRecordStore(),
  );
}

export class OneConflictRegistrationBridgePartitionStore implements RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1 {
  private conflictPending = true;

  constructor(
    private readonly delegate: RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
  ) {}

  async load(
    lifecycleId: string,
  ): Promise<RouterAbEd25519YaoProductRegistrationPartitionedStateV1> {
    return await this.delegate.load(lifecycleId);
  }

  async commit(
    input: RouterAbEd25519YaoProductRegistrationPartitionedStateCommitInputV1,
  ): Promise<RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1> {
    if (this.conflictPending) {
      this.conflictPending = false;
      const winner = await this.delegate.load(input.lifecycleId);
      winner.state.export.authorizationNonces.add('concurrent-winner');
      const committed = await this.delegate.commit({
        lifecycleId: input.lifecycleId,
        state: winner.state,
        sharedState: winner.sharedState,
        sharedVersion: winner.sharedVersion,
        ceremonyVersion: winner.ceremonyVersion,
      });
      if (committed.kind !== 'stored') throw new Error('fixture winner failed to commit');
    }
    return await this.delegate.commit(input);
  }
}

export class AlwaysConflictRegistrationBridgePartitionStore implements RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1 {
  commitAttempts = 0;

  constructor(
    private readonly delegate: RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
  ) {}

  async load(
    lifecycleId: string,
  ): Promise<RouterAbEd25519YaoProductRegistrationPartitionedStateV1> {
    return await this.delegate.load(lifecycleId);
  }

  async commit(
    input: RouterAbEd25519YaoProductRegistrationPartitionedStateCommitInputV1,
  ): Promise<RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1> {
    this.commitAttempts += 1;
    const winner = await this.delegate.load(input.lifecycleId);
    winner.state.export.authorizationNonces.add(`concurrent-winner-${this.commitAttempts}`);
    const committed = await this.delegate.commit({
      lifecycleId: input.lifecycleId,
      state: winner.state,
      sharedState: winner.sharedState,
      sharedVersion: winner.sharedVersion,
      ceremonyVersion: winner.ceremonyVersion,
    });
    if (committed.kind !== 'stored') throw new Error('fixture winner failed to commit');
    return await this.delegate.commit(input);
  }
}
