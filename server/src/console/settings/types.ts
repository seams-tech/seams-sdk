export type ConsoleCookieSameSite = 'LAX' | 'STRICT' | 'NONE';

export interface ConsoleCookieSettings {
  httpOnly: boolean;
  secure: boolean;
  sameSite: ConsoleCookieSameSite;
  domain: string | null;
  path: string;
  maxAgeSeconds: number;
}

export interface ConsoleJwtSettings {
  issuer: string;
  audience: string[];
  keyIds: string[];
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
}

export interface ConsoleAppSettings {
  orgId: string;
  environmentId: string;
  allowedOrigins: string[];
  allowedDomains: string[];
  cookie: ConsoleCookieSettings;
  jwt: ConsoleJwtSettings;
  ssoMetadataUrl: string | null;
  updatedAt: string;
  updatedBy: string;
}

export interface ConsoleSecurityApprovalPolicy {
  approvalsRequired: number;
  requireAdmin: boolean;
  requireMfa: boolean;
}

export interface ConsoleSecuritySettings {
  orgId: string;
  environmentId: string;
  ipAllowlist: string[];
  enforceIpAllowlist: boolean;
  requireMfaForRiskyChanges: boolean;
  riskyChangeApproval: ConsoleSecurityApprovalPolicy;
  updatedAt: string;
  updatedBy: string;
}

export interface GetConsoleSettingsRequest {
  environmentId: string;
}

export interface UpdateConsoleAppSettingsRequest {
  environmentId: string;
  allowedOrigins?: string[];
  allowedDomains?: string[];
  cookie?: Partial<ConsoleCookieSettings>;
  jwt?: Partial<ConsoleJwtSettings>;
  ssoMetadataUrl?: string | null;
}

export interface UpdateConsoleSecuritySettingsRequest {
  environmentId: string;
  ipAllowlist?: string[];
  enforceIpAllowlist?: boolean;
  requireMfaForRiskyChanges?: boolean;
  riskyChangeApproval?: Partial<ConsoleSecurityApprovalPolicy>;
}
