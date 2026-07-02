import { toOptionalTrimmedString } from '@shared/utils/validation';
import { deriveHostedNearAccountId } from '../../core/hostedAccountIds';
import type { IdentityStore } from '../../core/IdentityStore';
import type { RouterApiAuthService } from '../authServicePort';
import { parseD1BoundaryWalletId } from './d1RouterApiAuthBoundary';
import { requireD1RouterApiAuthScopeString } from './d1RouterApiAuthConfig';

type ListIdentitiesInput = Parameters<RouterApiAuthService['listIdentities']>[0];
type ListIdentitiesResult = Awaited<ReturnType<RouterApiAuthService['listIdentities']>>;
type LinkIdentityInput = Parameters<RouterApiAuthService['linkIdentity']>[0];
type LinkIdentityResult = Awaited<ReturnType<RouterApiAuthService['linkIdentity']>>;
type UnlinkIdentityInput = Parameters<RouterApiAuthService['unlinkIdentity']>[0];
type UnlinkIdentityResult = Awaited<ReturnType<RouterApiAuthService['unlinkIdentity']>>;
type ResolveOidcWalletIdInput = Parameters<RouterApiAuthService['resolveOidcWalletId']>[0];
type ResolveOidcWalletIdResult = Awaited<
  ReturnType<RouterApiAuthService['resolveOidcWalletId']>
>;
type ResolveGoogleEmailOtpSessionInput = Parameters<
  RouterApiAuthService['resolveGoogleEmailOtpSession']
>[0];
type ResolveGoogleEmailOtpSessionResult = Awaited<
  ReturnType<RouterApiAuthService['resolveGoogleEmailOtpSession']>
>;
type ResolveGoogleEmailOtpSession = (
  input: ResolveGoogleEmailOtpSessionInput,
) => Promise<ResolveGoogleEmailOtpSessionResult>;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

function isRecord(input: unknown): input is Record<string, unknown> {
  return Boolean(input) && typeof input === 'object' && !Array.isArray(input);
}

function resolveHostedOidcWalletScope(input: unknown): {
  readonly projectId: string;
  readonly envId: string;
} {
  const scope = isRecord(input) ? input : {};
  const orgId = toOptionalTrimmedString(scope.orgId);
  const projectId = toOptionalTrimmedString(scope.projectId);
  const envId = toOptionalTrimmedString(scope.envId);
  if (orgId && projectId && envId) return { projectId, envId };
  throw new Error(
    'runtimePolicyScope.orgId, runtimePolicyScope.projectId, and runtimePolicyScope.envId are required for hosted wallet id derivation',
  );
}

function codedError(code: string, message: string): Error & { code: string } {
  const error = new Error(message) as Error & { code: string };
  error.code = code;
  return error;
}

export class CloudflareD1IdentityService {
  private readonly accountIdDerivationSecret: unknown;
  private readonly identityStore: IdentityStore;
  private readonly relayerAccount: unknown;
  private readonly resolveGoogleEmailOtpSession: ResolveGoogleEmailOtpSession;

  constructor(input: {
    readonly accountIdDerivationSecret: unknown;
    readonly identityStore: IdentityStore;
    readonly relayerAccount: unknown;
    readonly resolveGoogleEmailOtpSession: ResolveGoogleEmailOtpSession;
  }) {
    this.accountIdDerivationSecret = input.accountIdDerivationSecret;
    this.identityStore = input.identityStore;
    this.relayerAccount = input.relayerAccount;
    this.resolveGoogleEmailOtpSession = input.resolveGoogleEmailOtpSession;
  }

  async listIdentities(input: ListIdentitiesInput): Promise<ListIdentitiesResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const subjects = await this.identityStore.listSubjectsByUserId(userId);
      return { ok: true, subjects };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to list identities',
      };
    }
  }

  async linkIdentity(input: LinkIdentityInput): Promise<LinkIdentityResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const subject = toOptionalTrimmedString(input.subject);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      if (!subject) return { ok: false, code: 'invalid_args', message: 'Missing subject' };
      return await this.identityStore.linkSubjectToUserId({
        userId,
        subject,
        allowMoveIfSoleIdentity: Boolean(input.allowMoveIfSoleIdentity),
      });
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to link identity',
      };
    }
  }

  async unlinkIdentity(input: UnlinkIdentityInput): Promise<UnlinkIdentityResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const subject = toOptionalTrimmedString(input.subject);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      if (!subject) return { ok: false, code: 'invalid_args', message: 'Missing subject' };
      return await this.identityStore.unlinkSubjectFromUserId({ userId, subject });
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to unlink identity',
      };
    }
  }

  async resolveOidcWalletId(input: ResolveOidcWalletIdInput): Promise<ResolveOidcWalletIdResult> {
    const providerSubject = toOptionalTrimmedString(input.providerSubject ?? input.sub);
    if (!providerSubject) {
      throw new Error('Cannot resolve OIDC wallet id without provider subject');
    }
    if (providerSubject.startsWith('google:')) {
      const resolution = await this.resolveGoogleEmailOtpSession(input);
      if (resolution.ok) return resolution.walletId;
      throw codedError(resolution.code, resolution.message);
    }

    const linkedWalletId = await this.identityStore.getUserIdBySubject(`wallet:${providerSubject}`);
    const parsedLinkedWalletId = parseD1BoundaryWalletId(linkedWalletId);
    if (parsedLinkedWalletId) return parsedLinkedWalletId;

    const scope = resolveHostedOidcWalletScope(input.runtimePolicyScope);
    const verifiedEmail = toOptionalTrimmedString(input.email);
    return await deriveHostedNearAccountId({
      accountIdDerivationSecret: requireD1RouterApiAuthScopeString(
        this.accountIdDerivationSecret,
        'ACCOUNT_ID_DERIVATION_SECRET',
      ),
      relayerAccount: requireD1RouterApiAuthScopeString(this.relayerAccount, 'relayerAccount'),
      projectId: scope.projectId,
      envId: scope.envId,
      authProvider: 'oidc',
      providerSubject,
      ...(verifiedEmail ? { verifiedEmail } : {}),
    });
  }
}
