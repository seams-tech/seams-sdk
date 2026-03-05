export type {
  ConsoleObservabilityModuleState,
  ConsoleObservabilityModuleStatus,
  ConsoleObservabilityLevel,
  ConsoleObservabilitySource,
  ConsoleObservabilitySummary,
  ConsoleObservabilityEvent,
  ConsoleObservabilityEventEnvelope,
  ConsoleObservabilityEventsPage,
  ConsoleObservabilityTimeseriesBucket,
  ConsoleObservabilityTimeseries,
  ConsoleServiceHealthState,
  ConsoleObservabilityServiceHealth,
  ConsoleObservabilityServicesView,
  GetConsoleObservabilitySummaryRequest,
  ListConsoleObservabilityEventsRequest,
  GetConsoleObservabilityTimeseriesRequest,
  ListConsoleObservabilityServicesRequest,
  ConsoleObservabilityEventIngestResult,
  ConsoleObservabilityIngestionContext,
  ConsoleObservabilityMetadataRedactionPolicy,
  ConsoleObservabilityWebhookDeadLetterInput,
  ConsoleObservabilityBillingFailureInput,
  ConsoleObservabilityApprovalFailureInput,
  ConsoleObservabilityRouterTimingInput,
} from './types';

export type {
  ConsoleObservabilityContext,
  InMemoryConsoleObservabilityServiceOptions,
  ConsoleObservabilityService,
} from './service';
export { createInMemoryConsoleObservabilityService } from './service';

export type {
  PostgresConsoleObservabilitySchemaOptions,
  PostgresConsoleObservabilityServiceOptions,
  PostgresConsoleObservabilityRetentionCleanupOptions,
  PostgresConsoleObservabilityRetentionCleanupResult,
  ConsoleObservabilityIngestionService,
  PostgresConsoleObservabilityIngestionServiceOptions,
} from './postgres';
export {
  ensureConsoleObservabilityPostgresSchema,
  createPostgresConsoleObservabilityService,
  runPostgresConsoleObservabilityRetentionCleanup,
  createPostgresConsoleObservabilityIngestionService,
} from './postgres';

export type { ConsoleObservabilityRedactionResult } from './redaction';
export { redactConsoleObservabilityMetadata } from './redaction';

export {
  buildWebhookDeadLetterObservabilityEvent,
  buildBillingFailureObservabilityEvent,
  buildApprovalFailureObservabilityEvent,
  buildRouterTimingObservabilityEvent,
} from './adapters';

export {
  parseGetConsoleObservabilitySummaryRequest,
  parseListConsoleObservabilityEventsRequest,
  parseGetConsoleObservabilityTimeseriesRequest,
  parseListConsoleObservabilityServicesRequest,
} from './requests';

export { ConsoleObservabilityError, isConsoleObservabilityError } from './errors';
