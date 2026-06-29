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
  ConsoleAccountD1Runtime,
  ConsoleAccountD1Service,
  D1ConsoleAccountSchemaOptions,
  D1ConsoleAccountServiceOptions,
} from './d1';
export {
  CONSOLE_ACCOUNT_D1_RUNTIME,
  CONSOLE_ACCOUNT_D1_SCHEMA_SQL,
  ensureConsoleAccountD1Schema,
  createD1ConsoleAccountService,
  getConsoleAccountD1Runtime,
} from './d1';

export {
  parsePatchConsoleAccountProfileRequest,
  parseCreateConsoleAccountOrganizationRequest,
  parseUpdateConsoleAccountOrganizationRequest,
  parseTransferConsoleAccountOrganizationOwnerRequest,
} from './requests';

export { ConsoleAccountError, isConsoleAccountError } from './errors';
