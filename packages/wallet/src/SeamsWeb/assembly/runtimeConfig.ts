import type { SigningRuntimeConfig } from '@/core/runtime/runtime.types';
import type { SeamsConfigsReadonly } from '@/core/types/seams';

export function toSigningRuntimeConfig(config: SeamsConfigsReadonly): SigningRuntimeConfig {
  return {
    network: config.network,
    registration: config.registration,
    signing: config.signing,
  };
}
