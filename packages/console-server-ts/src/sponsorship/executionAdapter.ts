export interface SponsorshipExecutionAdapter<TResult, TKind extends string, TMeta> {
  executorKind: TKind;
  meta: TMeta;
  execute: () => Promise<TResult>;
}

export async function executeSponsorshipAdapter<TResult, TKind extends string, TMeta>(
  adapter: SponsorshipExecutionAdapter<TResult, TKind, TMeta>,
): Promise<TResult> {
  return await adapter.execute();
}
