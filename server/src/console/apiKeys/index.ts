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

export {
  parseCreateConsoleApiKeyRequest,
  parseRevokeConsoleApiKeyRequest,
  parseRotateConsoleApiKeyRequest,
  parseUpdateConsoleApiKeyRequest,
} from './requests';

export { ConsoleApiKeyError, isConsoleApiKeyError } from './errors';
