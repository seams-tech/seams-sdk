export type {
  ConsoleApiKeyAuthFailureCode,
  AuthenticateConsoleApiKeyRequest,
  AuthenticateConsoleApiKeySuccess,
  AuthenticateConsoleApiKeyFailure,
  AuthenticateConsoleApiKeyResult,
  ConsolePublishableKeyAuthFailureCode,
  AuthenticateConsolePublishableKeyRequest,
  AuthenticateConsolePublishableKeySuccess,
  AuthenticateConsolePublishableKeyFailure,
  AuthenticateConsolePublishableKeyResult,
  ConsoleApiKeyStatus,
  ConsoleApiKey,
  CreateConsoleApiKeyRequest,
  RevokeConsoleApiKeyRequest,
  RotateConsoleApiKeyRequest,
  UpdateConsoleApiKeyRequest,
  CreateConsoleApiKeyResult,
  RotateConsoleApiKeyResult,
} from './types';

export type {
  ConsoleApiKeysContext,
  ConsoleApiKeyService,
  InMemoryConsoleApiKeyServiceOptions,
} from './service';
export { createInMemoryConsoleApiKeyService } from './service';

export type {
  PostgresConsoleApiKeySchemaOptions,
  PostgresConsoleApiKeyServiceOptions,
} from './postgres';
export {
  ensureConsoleApiKeysPostgresSchema,
  createPostgresConsoleApiKeyService,
} from './postgres';

export type {
  ConsoleApiKeysD1Runtime,
  ConsoleApiKeysD1Service,
  D1ConsoleApiKeysSchemaOptions,
  D1ConsoleApiKeysServiceOptions,
} from './d1';
export {
  CONSOLE_API_KEYS_D1_RUNTIME,
  CONSOLE_API_KEYS_D1_SCHEMA_SQL,
  ensureConsoleApiKeysD1Schema,
  getConsoleApiKeysD1Runtime,
  createD1ConsoleApiKeyService,
} from './d1';

export {
  parseCreateConsoleApiKeyRequest,
  parseRevokeConsoleApiKeyRequest,
  parseRotateConsoleApiKeyRequest,
  parseUpdateConsoleApiKeyRequest,
} from './requests';

export { ConsoleApiKeyError, isConsoleApiKeyError } from './errors';
