export type CapabilityPreparationResult<
  Ready,
  Resume,
  Requirement,
  Replacement,
  Failure,
> =
  | {
      kind: 'ready';
      value: Ready;
      resume?: never;
      requirement?: never;
      replacement?: never;
      failure?: never;
    }
  | {
      kind: 'pending';
      resume: Resume;
      value?: never;
      requirement?: never;
      replacement?: never;
      failure?: never;
    }
  | {
      kind: 'authorization_required';
      requirement: Requirement;
      value?: never;
      resume?: never;
      replacement?: never;
      failure?: never;
    }
  | {
      kind: 'superseded';
      replacement: Replacement;
      value?: never;
      resume?: never;
      requirement?: never;
      failure?: never;
    }
  | {
      kind: 'failed';
      failure: Failure;
      value?: never;
      resume?: never;
      requirement?: never;
      replacement?: never;
    };
