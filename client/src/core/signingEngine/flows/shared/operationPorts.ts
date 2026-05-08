export type OperationCommandExecutor<TCommand> = {
  execute(command: TCommand): Promise<void>;
};

export type OperationTransitionObserver<TTransitionEvent> = (
  event: TTransitionEvent,
) => void | Promise<void>;
