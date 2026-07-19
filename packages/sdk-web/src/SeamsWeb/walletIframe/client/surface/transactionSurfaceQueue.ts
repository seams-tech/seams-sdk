import type { WalletIframeRequestId } from '@/core/types/walletIframeIdentity';

export type WalletIframeTransactionSurfaceLease = {
  kind: 'wallet_iframe_transaction_surface_lease_v1';
  requestId: WalletIframeRequestId;
  release(): void;
};

type TransactionSurfaceQueueState =
  | {
      kind: 'idle';
      leaseId?: never;
      requestId?: never;
    }
  | {
      kind: 'active';
      leaseId: number;
      requestId: WalletIframeRequestId;
    };

type TransactionSurfaceWaiter = {
  requestId: WalletIframeRequestId;
  deadlineAtMs: number;
  deferred: TransactionSurfaceLeaseDeferred;
  timer: ReturnType<typeof setTimeout> | null;
};

class TransactionSurfaceLeaseDeferred {
  readonly promise: Promise<WalletIframeTransactionSurfaceLease>;
  private resolvePromise!: (lease: WalletIframeTransactionSurfaceLease) => void;
  private rejectPromise!: (error: Error) => void;

  constructor() {
    this.promise = new Promise(this.capturePromise.bind(this));
  }

  resolve(lease: WalletIframeTransactionSurfaceLease): void {
    this.resolvePromise(lease);
  }

  reject(error: Error): void {
    this.rejectPromise(error);
  }

  private capturePromise(
    resolve: (lease: WalletIframeTransactionSurfaceLease) => void,
    reject: (error: Error) => void,
  ): void {
    this.resolvePromise = resolve;
    this.rejectPromise = reject;
  }
}

class TransactionSurfaceLease implements WalletIframeTransactionSurfaceLease {
  readonly kind = 'wallet_iframe_transaction_surface_lease_v1';
  readonly requestId: WalletIframeRequestId;
  private readonly queue: WalletIframeTransactionSurfaceQueue;
  private readonly leaseId: number;
  private released = false;

  constructor(args: {
    queue: WalletIframeTransactionSurfaceQueue;
    leaseId: number;
    requestId: WalletIframeRequestId;
  }) {
    this.queue = args.queue;
    this.leaseId = args.leaseId;
    this.requestId = args.requestId;
  }

  release(): void {
    if (this.released) return;
    this.released = true;
    this.queue.release(this.leaseId);
  }
}

export class WalletIframeTransactionSurfaceQueue {
  private state: TransactionSurfaceQueueState = { kind: 'idle' };
  private readonly waiters: TransactionSurfaceWaiter[] = [];
  private nextLeaseId = 0;

  acquire(args: {
    requestId: WalletIframeRequestId;
    deadlineAtMs: number;
  }): Promise<WalletIframeTransactionSurfaceLease> {
    if (Date.now() >= args.deadlineAtMs) {
      return Promise.reject(this.timeoutError(args.requestId));
    }
    if (this.state.kind === 'idle' && this.waiters.length === 0) {
      return Promise.resolve(this.startLease(args.requestId));
    }

    const deferred = new TransactionSurfaceLeaseDeferred();
    const waiter: TransactionSurfaceWaiter = {
      requestId: args.requestId,
      deadlineAtMs: args.deadlineAtMs,
      deferred,
      timer: null,
    };
    waiter.timer = setTimeout(
      this.expireWaiter.bind(this, waiter),
      Math.max(1, args.deadlineAtMs - Date.now()),
    );
    this.waiters.push(waiter);
    return deferred.promise;
  }

  release(leaseId: number): void {
    if (this.state.kind !== 'active' || this.state.leaseId !== leaseId) return;
    this.state = { kind: 'idle' };
    this.grantNext();
  }

  private startLease(requestId: WalletIframeRequestId): WalletIframeTransactionSurfaceLease {
    const leaseId = ++this.nextLeaseId;
    this.state = { kind: 'active', leaseId, requestId };
    return new TransactionSurfaceLease({ queue: this, leaseId, requestId });
  }

  private grantNext(): void {
    while (this.state.kind === 'idle') {
      const waiter = this.waiters.shift();
      if (!waiter) return;
      this.clearWaiterTimer(waiter);
      if (Date.now() >= waiter.deadlineAtMs) {
        waiter.deferred.reject(this.timeoutError(waiter.requestId));
        continue;
      }
      waiter.deferred.resolve(this.startLease(waiter.requestId));
    }
  }

  private expireWaiter(waiter: TransactionSurfaceWaiter): void {
    const index = this.waiters.indexOf(waiter);
    if (index < 0) return;
    this.waiters.splice(index, 1);
    this.clearWaiterTimer(waiter);
    waiter.deferred.reject(this.timeoutError(waiter.requestId));
  }

  private clearWaiterTimer(waiter: TransactionSurfaceWaiter): void {
    if (waiter.timer === null) return;
    clearTimeout(waiter.timer);
    waiter.timer = null;
  }

  private timeoutError(requestId: WalletIframeRequestId): Error {
    return new Error(
      `Wallet request ${requestId} timed out before acquiring the transaction surface`,
    );
  }
}
