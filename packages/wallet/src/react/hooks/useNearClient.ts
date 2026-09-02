import { useMemo } from 'react';
import { MinimalNearClient, type NearClient } from '@/core/rpcClients/near/NearClient';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';

export const useNearClient = (
  rpcNodeURL: string = resolvePrimaryNearRpcUrl(PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains),
): NearClient => {
  const nearClient = useMemo(() => {
    return new MinimalNearClient(rpcNodeURL);
  }, [rpcNodeURL]);

  return nearClient;
};
