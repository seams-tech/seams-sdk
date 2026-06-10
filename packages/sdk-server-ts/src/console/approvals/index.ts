export type {
  ConsoleApprovalOperationType,
  ConsoleApprovalStatus,
  ConsoleApprovalDecision,
  ConsoleApprovalDecisionRecord,
  ConsoleApprovalRequestRecord,
  ListConsoleApprovalsRequest,
  CreateConsoleApprovalRequest,
  ApproveConsoleApprovalRequest,
  RejectConsoleApprovalRequest,
} from './types';

export type {
  ConsoleApprovalsContext,
  ConsoleApprovalService,
  InMemoryConsoleApprovalServiceOptions,
} from './service';
export { createInMemoryConsoleApprovalService } from './service';

export type {
  PostgresConsoleApprovalSchemaOptions,
  PostgresConsoleApprovalServiceOptions,
} from './postgres';
export {
  ensureConsoleApprovalsPostgresSchema,
  createPostgresConsoleApprovalService,
} from './postgres';

export {
  parseListConsoleApprovalsRequest,
  parseCreateConsoleApprovalRequest,
  parseApproveConsoleApprovalRequest,
  parseRejectConsoleApprovalRequest,
} from './requests';

export { ConsoleApprovalsError, isConsoleApprovalsError } from './errors';
