import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { IdentityStore, LinkIdentityResult } from '../../../../core/IdentityStore';
import type {
  RouterApiIdentityService,
} from '../../../framework/authServicePort';
import {
  githubOAuthPublicConfig,
  verifyGithubOAuthCodeWithIdentityStore,
} from '../../../../core/authService/githubOAuth';
import type { GithubOAuthConfig } from '../../../../core/types';
import {
  CloudflareD1OidcJwksCache,
  parseRs256JwtForVerification,
  validateGoogleIdTokenClaims,
  verifyRs256JwtSignature,
} from './d1OidcBoundary';

type VerifyGoogleLoginInput = Parameters<RouterApiIdentityService['verifyGoogleLogin']>[0];
type VerifyGoogleLoginResult = Awaited<ReturnType<RouterApiIdentityService['verifyGoogleLogin']>>;
type GoogleOidcPublicConfig = ReturnType<RouterApiIdentityService['getGoogleOidcPublicConfig']>;
type GithubOAuthPublicConfig = ReturnType<RouterApiIdentityService['getGithubOAuthPublicConfig']>;

type OidcIdentityLinker = (input: {
  readonly userId: string;
  readonly subject: string;
  readonly allowMoveIfSoleIdentity?: boolean;
}) => Promise<LinkIdentityResult>;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

export class CloudflareD1OidcVerificationService {
  private readonly googleOidcClientId: string | undefined;
  private readonly githubOAuth: GithubOAuthConfig | undefined;
  private readonly identityStore: IdentityStore;
  private readonly linkIdentity: OidcIdentityLinker;
  private readonly oidcJwksCache = new CloudflareD1OidcJwksCache();

  constructor(input: {
    readonly googleOidcClientId: string | undefined;
    readonly githubOAuth: GithubOAuthConfig | undefined;
    readonly identityStore: IdentityStore;
    readonly linkIdentity: OidcIdentityLinker;
  }) {
    this.googleOidcClientId = input.googleOidcClientId;
    this.githubOAuth = input.githubOAuth;
    this.identityStore = input.identityStore;
    this.linkIdentity = input.linkIdentity;
  }

  getGoogleOidcPublicConfig(): GoogleOidcPublicConfig {
    const clientId = toOptionalTrimmedString(this.googleOidcClientId);
    return {
      configured: Boolean(clientId),
      ...(clientId ? { clientId } : {}),
    };
  }

  getGithubOAuthPublicConfig(): GithubOAuthPublicConfig {
    return githubOAuthPublicConfig(this.githubOAuth);
  }

  async verifyGithubOAuthCode(
    input: Parameters<RouterApiIdentityService['verifyGithubOAuthCode']>[0],
  ): Promise<Awaited<ReturnType<RouterApiIdentityService['verifyGithubOAuthCode']>>> {
    return await verifyGithubOAuthCodeWithIdentityStore({
      request: input,
      config: this.githubOAuth,
      identityStore: this.identityStore,
    });
  }
  async verifyGoogleLogin(input: VerifyGoogleLoginInput): Promise<VerifyGoogleLoginResult> {
    try {
      const clientId = toOptionalTrimmedString(this.googleOidcClientId);
      if (!clientId) {
        return {
          ok: false,
          verified: false,
          code: 'not_configured',
          message: 'Google OIDC is not configured on this Worker',
        };
      }
      const idToken = toOptionalTrimmedString(input.idToken ?? input.id_token);
      if (!idToken) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'id_token is required',
        };
      }
      const subtle = globalThis.crypto?.subtle;
      if (!subtle) {
        return {
          ok: false,
          verified: false,
          code: 'unsupported',
          message: 'WebCrypto (crypto.subtle) is unavailable in this runtime',
        };
      }

      const parsed = parseRs256JwtForVerification({
        token: idToken,
        tokenLabel: 'id_token',
      });
      if (!parsed.ok) return parsed;
      const jwt = parsed.jwt;

      const jwks = await this.oidcJwksCache.getGoogleJwks();
      const jwk = jwks.keysByKid.get(jwt.kid);
      if (!jwk) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_kid',
          message: 'Unknown Google key id (kid)',
        };
      }

      const signature = await verifyRs256JwtSignature({
        subtle,
        jwt,
        jwk,
        tokenLabel: 'id_token',
        invalidSignatureMessage: 'Invalid Google id_token signature',
      });
      if (!signature.ok) return signature;

      const claims = validateGoogleIdTokenClaims({ payload: jwt.payload, clientId });
      if (!claims.ok) return claims;
      const providerSubject = `google:${claims.sub}`;
      const linkedUserId = await this.linkGoogleIdentity(providerSubject);
      return {
        ok: true,
        verified: true,
        userId: linkedUserId,
        providerSubject,
        sub: claims.sub,
        ...(claims.email ? { email: claims.email } : {}),
        ...(claims.name ? { name: claims.name } : {}),
        ...(claims.givenName ? { given_name: claims.givenName } : {}),
        ...(claims.familyName ? { family_name: claims.familyName } : {}),
        ...(typeof claims.emailVerified === 'boolean'
          ? { emailVerified: claims.emailVerified }
          : {}),
        ...(claims.hostedDomain ? { hostedDomain: claims.hostedDomain } : {}),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(error) || 'Google OIDC verification failed',
      };
    }
  }

  private async linkGoogleIdentity(providerSubject: string): Promise<string> {
    let userId = providerSubject;
    const linked = await this.identityStore.getUserIdBySubject(providerSubject);
    if (linked) userId = linked;
    await this.linkIdentity({
      userId,
      subject: providerSubject,
      allowMoveIfSoleIdentity: false,
    });
    return userId;
  }
}
