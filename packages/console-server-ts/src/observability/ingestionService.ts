import type {
  ConsoleObservabilityEventEnvelope,
  ConsoleObservabilityEventIngestResult,
  ConsoleObservabilityIngestionContext,
  ConsoleObservabilityRequestMetricInput,
} from './types';

export interface ConsoleObservabilityIngestionService {
  appendEvent(
    ctx: ConsoleObservabilityIngestionContext,
    event: ConsoleObservabilityEventEnvelope,
  ): Promise<ConsoleObservabilityEventIngestResult>;
  appendEvents(
    ctx: ConsoleObservabilityIngestionContext,
    events: ConsoleObservabilityEventEnvelope[],
  ): Promise<ConsoleObservabilityEventIngestResult>;
  observeRequestMetric?(
    ctx: ConsoleObservabilityIngestionContext,
    metric: ConsoleObservabilityRequestMetricInput,
  ): Promise<void>;
}
