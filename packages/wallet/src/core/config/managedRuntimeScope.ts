import type { SeamsConfigsReadonly } from '../types/seams';

export type ManagedRuntimeScopeBootstrap = {
  readonly projectEnvironmentId: string;
  readonly publishableKey: string;
};

export function resolveManagedRuntimeScopeBootstrap(
  configs: SeamsConfigsReadonly,
): ManagedRuntimeScopeBootstrap | undefined {
  const registration = configs.registration;
  if (registration.mode !== 'managed') return undefined;
  const projectEnvironmentId = String(registration.projectEnvironmentId || '').trim();
  const publishableKey = String(registration.publishableKey || '').trim();
  if (!projectEnvironmentId || !publishableKey) return undefined;
  return { projectEnvironmentId, publishableKey };
}
