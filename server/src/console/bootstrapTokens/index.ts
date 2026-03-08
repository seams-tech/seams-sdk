export type {
  ConsoleBootstrapTokenStatus,
  ConsoleBootstrapTokenRecord,
  CreateConsoleBootstrapTokenRequest,
  CreateConsoleBootstrapTokenResult,
  CountConsoleBootstrapTokensRequest,
  RedeemConsoleBootstrapTokenFailureCode,
  RedeemConsoleBootstrapTokenRequest,
  RedeemConsoleBootstrapTokenResult,
} from './types';

export type {
  ConsoleBootstrapTokensContext,
  ConsoleBootstrapTokenService,
  InMemoryConsoleBootstrapTokenServiceOptions,
} from './service';
export { createInMemoryConsoleBootstrapTokenService } from './service';

export type {
  PostgresConsoleBootstrapTokenSchemaOptions,
  PostgresConsoleBootstrapTokenServiceOptions,
} from './postgres';
export {
  ensureConsoleBootstrapTokensPostgresSchema,
  createPostgresConsoleBootstrapTokenService,
} from './postgres';

export {
  hashBootstrapToken,
  makeBootstrapToken,
  makeBootstrapTokenLookupPrefix,
  parseBootstrapToken,
} from './secret';
