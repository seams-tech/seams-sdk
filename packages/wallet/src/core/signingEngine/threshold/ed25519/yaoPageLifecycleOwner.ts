export type DisposableEd25519YaoClientOwner = {
  dispose(): void;
};

type PageLifecycleState = { kind: 'active' } | { kind: 'disposed' };

export class Ed25519YaoPageLifecycleOwner {
  private state: PageLifecycleState = { kind: 'active' };
  private readonly handlePageHideBound: EventListener;

  constructor(
    private readonly eventTarget: EventTarget | null,
    private readonly clientOwner: DisposableEd25519YaoClientOwner,
  ) {
    this.handlePageHideBound = this.handlePageHide.bind(this);
    this.eventTarget?.addEventListener('pagehide', this.handlePageHideBound);
  }

  private handlePageHide(): void {
    this.dispose();
  }

  dispose(): void {
    if (this.state.kind === 'disposed') return;
    this.state = { kind: 'disposed' };
    this.eventTarget?.removeEventListener('pagehide', this.handlePageHideBound);
    this.clientOwner.dispose();
  }
}
