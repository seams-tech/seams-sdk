import type {
  ConsoleAppSettings,
  ConsoleSecuritySettings,
  GetConsoleSettingsRequest,
  UpdateConsoleAppSettingsRequest,
  UpdateConsoleSecuritySettingsRequest,
} from './types';

export interface ConsoleSettingsContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
}

export interface InMemoryConsoleSettingsServiceOptions {
  now?: () => Date;
}

export interface ConsoleSettingsService {
  getAppSettings(
    ctx: ConsoleSettingsContext,
    request: GetConsoleSettingsRequest,
  ): Promise<ConsoleAppSettings>;
  updateAppSettings(
    ctx: ConsoleSettingsContext,
    request: UpdateConsoleAppSettingsRequest,
  ): Promise<ConsoleAppSettings>;
  getSecuritySettings(
    ctx: ConsoleSettingsContext,
    request: GetConsoleSettingsRequest,
  ): Promise<ConsoleSecuritySettings>;
  updateSecuritySettings(
    ctx: ConsoleSettingsContext,
    request: UpdateConsoleSecuritySettingsRequest,
  ): Promise<ConsoleSecuritySettings>;
}

interface EnvironmentSettingsStore {
  app: ConsoleAppSettings;
  security: ConsoleSecuritySettings;
}

function toIso(date: Date): string {
  return date.toISOString();
}

function cloneAppSettings(input: ConsoleAppSettings): ConsoleAppSettings {
  return {
    ...input,
    allowedOrigins: [...input.allowedOrigins],
    cookie: { ...input.cookie },
    jwt: {
      ...input.jwt,
      audience: [...input.jwt.audience],
      keyIds: [...input.jwt.keyIds],
    },
  };
}

function cloneSecuritySettings(input: ConsoleSecuritySettings): ConsoleSecuritySettings {
  return {
    ...input,
    ipAllowlist: [...input.ipAllowlist],
    riskyChangeApproval: { ...input.riskyChangeApproval },
  };
}

function normalizeStringList(input: string[] | undefined): string[] | undefined {
  if (!Array.isArray(input)) return undefined;
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of input) {
    const value = String(raw || '').trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

function defaultEnvironmentSettings(args: {
  orgId: string;
  environmentId: string;
  actorUserId: string;
  now: Date;
}): EnvironmentSettingsStore {
  const iso = toIso(args.now);
  return {
    app: {
      orgId: args.orgId,
      environmentId: args.environmentId,
      allowedOrigins: [],
      cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'LAX',
        domain: null,
        path: '/',
        maxAgeSeconds: 86_400,
      },
      jwt: {
        issuer: `https://console.local/${args.orgId}/${args.environmentId}`,
        audience: [],
        keyIds: [],
        accessTokenTtlSeconds: 900,
        refreshTokenTtlSeconds: 2_592_000,
      },
      ssoMetadataUrl: null,
      updatedAt: iso,
      updatedBy: args.actorUserId,
    },
    security: {
      orgId: args.orgId,
      environmentId: args.environmentId,
      ipAllowlist: [],
      enforceIpAllowlist: false,
      requireMfaForRiskyChanges: true,
      riskyChangeApproval: {
        approvalsRequired: 1,
        requireAdmin: true,
        requireMfa: true,
      },
      updatedAt: iso,
      updatedBy: args.actorUserId,
    },
  };
}

export function createInMemoryConsoleSettingsService(
  opts: InMemoryConsoleSettingsServiceOptions = {},
): ConsoleSettingsService {
  const now = opts.now || (() => new Date());
  const stores = new Map<string, Map<string, EnvironmentSettingsStore>>();

  function requireOrgStore(orgId: string): Map<string, EnvironmentSettingsStore> {
    let store = stores.get(orgId);
    if (!store) {
      store = new Map<string, EnvironmentSettingsStore>();
      stores.set(orgId, store);
    }
    return store;
  }

  function requireEnvironmentStore(
    ctx: ConsoleSettingsContext,
    environmentId: string,
  ): EnvironmentSettingsStore {
    const store = requireOrgStore(ctx.orgId);
    let entry = store.get(environmentId);
    if (!entry) {
      entry = defaultEnvironmentSettings({
        orgId: ctx.orgId,
        environmentId,
        actorUserId: ctx.actorUserId,
        now: now(),
      });
      store.set(environmentId, entry);
    }
    return entry;
  }

  return {
    async getAppSettings(ctx, request): Promise<ConsoleAppSettings> {
      return cloneAppSettings(requireEnvironmentStore(ctx, request.environmentId).app);
    },

    async updateAppSettings(ctx, request): Promise<ConsoleAppSettings> {
      const store = requireEnvironmentStore(ctx, request.environmentId);
      const updatedAt = toIso(now());

      if (request.allowedOrigins !== undefined) {
        store.app.allowedOrigins = normalizeStringList(request.allowedOrigins) || [];
      }
      if (request.cookie) {
        store.app.cookie = {
          ...store.app.cookie,
          ...request.cookie,
        };
      }
      if (request.jwt) {
        store.app.jwt = {
          ...store.app.jwt,
          ...request.jwt,
          ...(request.jwt.audience ? { audience: normalizeStringList(request.jwt.audience) || [] } : {}),
          ...(request.jwt.keyIds ? { keyIds: normalizeStringList(request.jwt.keyIds) || [] } : {}),
        };
      }
      if (request.ssoMetadataUrl !== undefined) {
        store.app.ssoMetadataUrl = request.ssoMetadataUrl;
      }
      store.app.updatedAt = updatedAt;
      store.app.updatedBy = ctx.actorUserId;

      return cloneAppSettings(store.app);
    },

    async getSecuritySettings(ctx, request): Promise<ConsoleSecuritySettings> {
      return cloneSecuritySettings(requireEnvironmentStore(ctx, request.environmentId).security);
    },

    async updateSecuritySettings(ctx, request): Promise<ConsoleSecuritySettings> {
      const store = requireEnvironmentStore(ctx, request.environmentId);
      const updatedAt = toIso(now());

      if (request.ipAllowlist !== undefined) {
        store.security.ipAllowlist = normalizeStringList(request.ipAllowlist) || [];
      }
      if (request.enforceIpAllowlist !== undefined) {
        store.security.enforceIpAllowlist = request.enforceIpAllowlist;
      }
      if (request.requireMfaForRiskyChanges !== undefined) {
        store.security.requireMfaForRiskyChanges = request.requireMfaForRiskyChanges;
      }
      if (request.riskyChangeApproval) {
        store.security.riskyChangeApproval = {
          ...store.security.riskyChangeApproval,
          ...request.riskyChangeApproval,
        };
      }
      store.security.updatedAt = updatedAt;
      store.security.updatedBy = ctx.actorUserId;

      return cloneSecuritySettings(store.security);
    },
  };
}
