export type {
  ConsoleAuditActorType,
  ConsoleAuditCategory,
  ConsoleAuditOutcome,
  ConsoleAuditEvidenceDomain,
  ConsoleAuditEvidenceReferenceKind,
  ConsoleAuditEvent,
  ConsoleAuditEvidenceReference,
  ConsoleAuditEvidenceRecord,
  ListConsoleAuditEventsRequest,
  ListConsoleAuditEvidenceRequest,
  AppendConsoleAuditEventRequest,
  AppendConsoleAuditEvidenceRequest,
} from './types';

export type {
  ConsoleAuditContext,
  ConsoleAuditService,
  InMemoryConsoleAuditServiceOptions,
} from './service';
export { createInMemoryConsoleAuditService } from './service';

export type {
  PostgresConsoleAuditSchemaOptions,
  PostgresConsoleAuditServiceOptions,
} from './postgres';
export {
  ensureConsoleAuditPostgresSchema,
  createPostgresConsoleAuditService,
} from './postgres';

export {
  parseListConsoleAuditEventsRequest,
  parseListConsoleAuditEvidenceRequest,
} from './requests';

export { ConsoleAuditError, isConsoleAuditError } from './errors';
