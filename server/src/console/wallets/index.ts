export type {
  ConsoleWalletChain,
  ConsoleWalletType,
  ConsoleWalletStatus,
  ConsoleWalletSortBy,
  ConsoleWalletSortOrder,
  ConsoleWallet,
  ListConsoleWalletsRequest,
  SearchConsoleWalletsRequest,
  ConsoleWalletPage,
} from './types';

export type {
  ConsoleWalletsContext,
  ConsoleWalletService,
  InMemoryConsoleWalletServiceOptions,
} from './service';
export { createInMemoryConsoleWalletService } from './service';

export type {
  PostgresConsoleWalletSchemaOptions,
  PostgresConsoleWalletServiceOptions,
} from './postgres';
export {
  ensureConsoleWalletsPostgresSchema,
  createPostgresConsoleWalletService,
} from './postgres';

export { parseListConsoleWalletsRequest, parseSearchConsoleWalletsRequest } from './requests';

export { ConsoleWalletError, isConsoleWalletError } from './errors';
