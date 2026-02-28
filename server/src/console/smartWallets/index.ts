export type {
  ConsoleSmartWalletScopeType,
  ConsoleSmartWalletMode,
  ConsoleSmartWalletAccountType,
  ConsoleSmartWalletPaymasterMode,
  ConsoleSmartWalletFallbackBehavior,
  ConsoleSmartWalletEntryPointVersion,
  ConsoleSmartWalletBundlerConfig,
  ConsoleSmartWalletConfig,
  ListConsoleSmartWalletRequest,
  CreateConsoleSmartWalletRequest,
  UpdateConsoleSmartWalletRequest,
} from './types';

export type {
  ConsoleSmartWalletContext,
  ConsoleSmartWalletService,
  InMemoryConsoleSmartWalletServiceOptions,
} from './service';
export { createInMemoryConsoleSmartWalletService } from './service';

export type {
  PostgresConsoleSmartWalletSchemaOptions,
  PostgresConsoleSmartWalletServiceOptions,
} from './postgres';
export {
  ensureConsoleSmartWalletsPostgresSchema,
  createPostgresConsoleSmartWalletService,
} from './postgres';

export {
  parseListConsoleSmartWalletRequest,
  parseCreateConsoleSmartWalletRequest,
  parseUpdateConsoleSmartWalletRequest,
} from './requests';

export { ConsoleSmartWalletError, isConsoleSmartWalletError } from './errors';
