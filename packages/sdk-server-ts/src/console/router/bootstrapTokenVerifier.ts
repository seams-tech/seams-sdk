import { parseBootstrapToken } from '../bootstrapTokens/secret';
import type { ConsoleBootstrapTokenService } from '../bootstrapTokens/service';
import type {
  RouterApiBootstrapTokenRedeemRequest,
  RouterApiBootstrapTokenRecord,
  RouterApiBootstrapTokenRedeemResult,
  RouterApiBootstrapTokenVerifier,
} from '../../router/apiCredentialPorts';

function isBootstrapToken(token: string): boolean {
  return parseBootstrapToken(token) !== null;
}

class ConsoleRouterApiBootstrapTokenVerifier implements RouterApiBootstrapTokenVerifier {
  constructor(private readonly tokenStore: ConsoleBootstrapTokenService) {}

  isBootstrapToken(token: string): boolean {
    return isBootstrapToken(token);
  }

  async peekTokenRecord(token: string): Promise<RouterApiBootstrapTokenRecord | null> {
    return await this.tokenStore.peekTokenRecord(token);
  }

  async redeemToken(
    request: RouterApiBootstrapTokenRedeemRequest,
  ): Promise<RouterApiBootstrapTokenRedeemResult> {
    return await this.tokenStore.redeemToken(request);
  }
}

export function createRouterApiBootstrapTokenVerifier(
  tokenStore: ConsoleBootstrapTokenService,
): RouterApiBootstrapTokenVerifier {
  return new ConsoleRouterApiBootstrapTokenVerifier(tokenStore);
}
