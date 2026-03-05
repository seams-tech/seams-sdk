export type {
  ConsoleApiKeyAuthFailureCode,
  AuthenticateConsoleApiKeyRequest,
  AuthenticateConsoleApiKeySuccess,
  AuthenticateConsoleApiKeyFailure,
  AuthenticateConsoleApiKeyResult,
  ConsoleApiKeyStatus,
  ConsoleApiKey,
  CreateConsoleApiKeyRequest,
  RevokeConsoleApiKeyRequest,
  RotateConsoleApiKeyRequest,
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

export {
  parseCreateConsoleApiKeyRequest,
  parseRevokeConsoleApiKeyRequest,
  parseRotateConsoleApiKeyRequest,
} from './requests';

export { ConsoleApiKeyError, isConsoleApiKeyError } from './errors';
