export type {
  ConsoleAccountBackupEmailStatus,
  ConsoleAccountBackupEmail,
  ConsoleAccountProfile,
  PatchConsoleAccountProfileRequest,
  ConsoleAccountOrganizationAdminCandidate,
  ConsoleAccountOrganization,
  CreateConsoleAccountOrganizationRequest,
  UpdateConsoleAccountOrganizationRequest,
  TransferConsoleAccountOrganizationOwnerRequest,
  TransferConsoleAccountOrganizationOwnerResult,
  DeleteConsoleAccountOrganizationResult,
  SwitchConsoleAccountOrganizationContextResult,
} from './types';

export type {
  ConsoleAccountContext,
  ConsoleAccountService,
  InMemoryConsoleAccountServiceOptions,
} from './service';
export { createInMemoryConsoleAccountService } from './service';

export type {
  PostgresConsoleAccountSchemaOptions,
  PostgresConsoleAccountServiceOptions,
} from './postgres';
export { ensureConsoleAccountPostgresSchema, createPostgresConsoleAccountService } from './postgres';

export {
  parsePatchConsoleAccountProfileRequest,
  parseCreateConsoleAccountOrganizationRequest,
  parseUpdateConsoleAccountOrganizationRequest,
  parseTransferConsoleAccountOrganizationOwnerRequest,
} from './requests';

export { ConsoleAccountError, isConsoleAccountError } from './errors';
