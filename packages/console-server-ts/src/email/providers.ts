import type {
  CapturedConsoleEmail,
  CaptureConsoleEmailProvider,
  ConsoleEmailProvider,
  ConsoleEmailProviderSendRequest,
  ConsoleEmailProviderSendResult,
} from './types';

const DEFAULT_RESEND_API_URL = 'https://api.resend.com/emails';
const DEFAULT_RESEND_TIMEOUT_MS = 10_000;

export interface ResendConsoleEmailProviderOptions {
  readonly apiKey: string;
  readonly from: string;
  readonly replyTo?: string;
  readonly apiUrl?: string;
  readonly timeoutMs?: number;
  readonly fetchImpl?: typeof fetch;
}

export type ConsoleEmailProviderConfiguration =
  | {
      readonly mode: 'CAPTURE';
    }
  | {
      readonly mode: 'RESEND';
      readonly resend: ResendConsoleEmailProviderOptions;
    };

export function createCaptureConsoleEmailProvider(): CaptureConsoleEmailProvider {
  return new CaptureConsoleEmailProviderImpl();
}

export function createResendConsoleEmailProvider(
  options: ResendConsoleEmailProviderOptions,
): ConsoleEmailProvider {
  return new ResendConsoleEmailProvider(options);
}

export function createConfiguredConsoleEmailProvider(
  configuration: ConsoleEmailProviderConfiguration,
): ConsoleEmailProvider {
  switch (configuration.mode) {
    case 'CAPTURE':
      return createCaptureConsoleEmailProvider();
    case 'RESEND':
      return createResendConsoleEmailProvider(configuration.resend);
    default:
      return assertNever(configuration);
  }
}

class CaptureConsoleEmailProviderImpl implements CaptureConsoleEmailProvider {
  readonly provider = 'capture' as const;
  private readonly messagesByOutboxId = new Map<string, CapturedConsoleEmail>();

  async send(request: ConsoleEmailProviderSendRequest): Promise<ConsoleEmailProviderSendResult> {
    const existing = this.messagesByOutboxId.get(request.outboxId);
    if (existing) {
      return {
        kind: 'SENT',
        providerMessageId: existing.providerMessageId,
        statusCode: null,
      };
    }
    const captured: CapturedConsoleEmail = {
      outboxId: request.outboxId,
      recipient: {
        email: request.recipient.email,
        displayName: request.recipient.displayName,
      },
      subject: request.subject,
      text: request.text,
      html: request.html,
      providerMessageId: `capture_${request.outboxId}`,
    };
    this.messagesByOutboxId.set(request.outboxId, captured);
    return {
      kind: 'SENT',
      providerMessageId: captured.providerMessageId,
      statusCode: null,
    };
  }

  listCaptured(): readonly CapturedConsoleEmail[] {
    const captured: CapturedConsoleEmail[] = [];
    for (const message of this.messagesByOutboxId.values()) {
      captured.push(cloneCapturedEmail(message));
    }
    return captured;
  }

  clearCaptured(): void {
    this.messagesByOutboxId.clear();
  }
}

class ResendConsoleEmailProvider implements ConsoleEmailProvider {
  readonly provider = 'resend' as const;
  private readonly apiKey: string;
  private readonly from: string;
  private readonly replyTo: string | null;
  private readonly apiUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: ResendConsoleEmailProviderOptions) {
    this.apiKey = normalizeResendApiKey(options.apiKey);
    this.from = requiredText(options.from, 'Resend from');
    this.replyTo = optionalText(options.replyTo);
    this.apiUrl = httpUrl(options.apiUrl || DEFAULT_RESEND_API_URL, 'Resend API URL');
    this.timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_RESEND_TIMEOUT_MS);
    this.fetchImpl = options.fetchImpl || globalThis.fetch.bind(globalThis);
    if (typeof this.fetchImpl !== 'function') {
      throw new Error('Resend email provider requires fetch');
    }
  }

  async send(request: ConsoleEmailProviderSendRequest): Promise<ConsoleEmailProviderSendResult> {
    const controller = new AbortController();
    const timeout = setTimeout(controller.abort.bind(controller), this.timeoutMs);
    try {
      const response = await this.fetchImpl(this.apiUrl, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': request.outboxId,
        },
        body: JSON.stringify(resendBody(this.from, this.replyTo, request)),
        signal: controller.signal,
      });
      if (!response.ok) return resendFailureResult(response.status);
      const providerMessageId = await readResendMessageId(response);
      if (!providerMessageId) {
        return {
          kind: 'FINAL_FAILURE',
          errorCode: 'resend_missing_message_id',
          statusCode: response.status,
        };
      }
      return {
        kind: 'SENT',
        providerMessageId,
        statusCode: response.status,
      };
    } catch {
      return {
        kind: 'RETRYABLE_FAILURE',
        errorCode: 'resend_transport_error',
        statusCode: null,
      };
    } finally {
      clearTimeout(timeout);
    }
  }
}

function resendBody(
  from: string,
  replyTo: string | null,
  request: ConsoleEmailProviderSendRequest,
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    from,
    to: [request.recipient.email],
    subject: request.subject,
    text: request.text,
    html: request.html,
  };
  if (replyTo) body.reply_to = replyTo;
  return body;
}

function resendFailureResult(status: number): ConsoleEmailProviderSendResult {
  const errorCode = `resend_http_${status}`;
  if (status === 408 || status === 425 || status === 429 || status >= 500) {
    return {
      kind: 'RETRYABLE_FAILURE',
      errorCode,
      statusCode: status,
    };
  }
  return {
    kind: 'FINAL_FAILURE',
    errorCode,
    statusCode: status,
  };
}

async function readResendMessageId(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json();
    if (!body || typeof body !== 'object' || Array.isArray(body)) return '';
    if (!('id' in body)) return '';
    return typeof body.id === 'string' ? body.id.trim() : '';
  } catch {
    return '';
  }
}

function cloneCapturedEmail(message: CapturedConsoleEmail): CapturedConsoleEmail {
  return {
    outboxId: message.outboxId,
    recipient: {
      email: message.recipient.email,
      displayName: message.recipient.displayName,
    },
    subject: message.subject,
    text: message.text,
    html: message.html,
    providerMessageId: message.providerMessageId,
  };
}

function normalizeResendApiKey(value: string): string {
  const normalized = requiredText(value, 'Resend API key');
  if (!normalized.startsWith('re_')) {
    throw new Error('Resend API key must start with re_');
  }
  return normalized;
}

function requiredText(value: string, field: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error(`${field} is required`);
  return normalized;
}

function optionalText(value: string | undefined): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  return normalized || null;
}

function httpUrl(value: string, field: string): string {
  const url = new URL(requiredText(value, field));
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`${field} must use http or https`);
  }
  return url.toString();
}

function positiveInteger(value: number | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error('Resend timeoutMs must be a positive integer');
  }
  return value;
}

function assertNever(value: never): never {
  throw new Error(`Unhandled console email provider mode: ${JSON.stringify(value)}`);
}
