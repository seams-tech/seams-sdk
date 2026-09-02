import type { D1DatabaseLike } from '../boundary';
import { createConsoleEmailOutboxInsertStatement } from '../email/d1';
import { buildAccountWelcomeEmailV1 } from '../email/templates';

export interface ConsoleOnboardingWelcomeEmail {
  readonly orgId: string;
  readonly userId: string;
  readonly recipientEmail: string;
  readonly recipientDisplayName: string;
  readonly organizationName: string;
  readonly projectName: string;
}

export interface ConsoleOnboardingWelcomeEmailPort {
  enqueue(email: ConsoleOnboardingWelcomeEmail): Promise<void>;
}

export interface D1ConsoleOnboardingWelcomeEmailOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly consoleBaseUrl: string;
  readonly docsBaseUrl: string;
  readonly now?: () => Date;
}

class D1ConsoleOnboardingWelcomeEmail implements ConsoleOnboardingWelcomeEmailPort {
  readonly #database: D1DatabaseLike;
  readonly #namespace: string;
  readonly #consoleBaseUrl: string;
  readonly #docsBaseUrl: string;
  readonly #now: () => Date;

  constructor(options: D1ConsoleOnboardingWelcomeEmailOptions) {
    this.#database = options.database;
    this.#namespace = requiredText(options.namespace, 'namespace');
    this.#consoleBaseUrl = requiredHttpBaseUrl(options.consoleBaseUrl, 'consoleBaseUrl');
    this.#docsBaseUrl = requiredHttpBaseUrl(options.docsBaseUrl, 'docsBaseUrl');
    this.#now = options.now || defaultNow;
  }

  async enqueue(email: ConsoleOnboardingWelcomeEmail): Promise<void> {
    const userId = requiredText(email.userId, 'userId');
    const dedupeKey = `account-welcome:${userId}`;
    const now = this.#now();
    const statement = await createConsoleEmailOutboxInsertStatement({
      database: this.#database,
      namespace: this.#namespace,
      conflictPolicy: 'IGNORE_DEDUPE',
      email: {
        outboxId: dedupeKey,
        dedupeKey,
        orgId: requiredText(email.orgId, 'orgId'),
        recipient: {
          email: requiredEmail(email.recipientEmail),
          displayName: requiredText(email.recipientDisplayName, 'recipientDisplayName'),
        },
        template: buildAccountWelcomeEmailV1({
          recipientDisplayName: email.recipientDisplayName,
          organizationName: email.organizationName,
          projectName: email.projectName,
          consoleBaseUrl: this.#consoleBaseUrl,
          docsBaseUrl: this.#docsBaseUrl,
        }),
        createdAt: now,
        availableAt: now,
      },
    });
    await statement.run();
  }
}

export function createD1ConsoleOnboardingWelcomeEmail(
  options: D1ConsoleOnboardingWelcomeEmailOptions,
): ConsoleOnboardingWelcomeEmailPort {
  return new D1ConsoleOnboardingWelcomeEmail(options);
}

function requiredText(value: string, field: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(`${field} is required`);
  return normalized;
}

function requiredEmail(value: string): string {
  const normalized = requiredText(value, 'recipientEmail').toLowerCase();
  if (!normalized.includes('@')) throw new Error('recipientEmail must be an email address');
  return normalized;
}

function requiredHttpBaseUrl(value: string, field: string): string {
  const parsed = new URL(requiredText(value, field));
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error(`${field} must use http or https`);
  }
  return parsed.toString();
}

function defaultNow(): Date {
  return new Date();
}
