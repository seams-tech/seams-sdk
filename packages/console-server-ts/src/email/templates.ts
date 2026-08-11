import type {
  AccountWelcomeEmailV1,
  BillingRefundResultEmailV1,
  ConsoleEmailInvitationRole,
  ConsoleEmailNonInvitationTemplateV1,
  ConsoleEmailTemplateV1,
  LowBalanceWarningEmailV1,
  MembershipAccessChangedEmailV1,
  OrganizationInvitationEmailV1,
  OwnerMembershipChangedEmailV1,
  PrepaidTopUpReceiptEmailV1,
  RenderedConsoleEmail,
} from './types';

type UnknownRecord = Readonly<Record<string, unknown>>;

export interface AccountWelcomeEmailV1Input {
  readonly recipientDisplayName: string;
  readonly organizationName: string;
  readonly projectName: string;
  readonly consoleBaseUrl: string;
  readonly docsBaseUrl: string;
}

export interface OrganizationInvitationEmailV1Input {
  readonly invitationId: string;
  readonly organizationName: string;
  readonly inviterDisplayName: string;
  readonly invitedRole: ConsoleEmailInvitationRole;
  readonly consoleBaseUrl: string;
  readonly expiresAt: string;
}

export type OwnerMembershipChangedEmailV1Input =
  | {
      readonly change: 'ADDED';
      readonly organizationName: string;
      readonly ownerDisplayName: string;
      readonly changedByDisplayName: string;
    }
  | {
      readonly change: 'REMOVED';
      readonly organizationName: string;
      readonly ownerDisplayName: string;
      readonly changedByDisplayName: string;
    };

export type MembershipAccessChangedEmailV1Input =
  | {
      readonly change: 'SUSPENDED';
      readonly organizationName: string;
      readonly memberDisplayName: string;
      readonly changedByDisplayName: string;
    }
  | {
      readonly change: 'REMOVED';
      readonly organizationName: string;
      readonly memberDisplayName: string;
      readonly changedByDisplayName: string;
    };

export interface PrepaidTopUpReceiptEmailV1Input {
  readonly organizationName: string;
  readonly purchaseId: string;
  readonly amountMinor: number;
  readonly balanceAfterMinor: number;
  readonly purchasedAt: string;
  readonly consoleBaseUrl: string;
}

export type BillingRefundResultEmailV1Input =
  | {
      readonly outcome: 'SUCCEEDED';
      readonly organizationName: string;
      readonly refundId: string;
      readonly amountMinor: number;
      readonly balanceAfterMinor: number;
      readonly consoleBaseUrl: string;
      readonly failureCode?: never;
    }
  | {
      readonly outcome: 'FAILED';
      readonly organizationName: string;
      readonly refundId: string;
      readonly amountMinor: number;
      readonly consoleBaseUrl: string;
      readonly failureCode: string;
      readonly balanceAfterMinor?: never;
    };

export interface LowBalanceWarningEmailV1Input {
  readonly organizationName: string;
  readonly balanceMinor: number;
  readonly thresholdMinor: number;
  readonly consoleBaseUrl: string;
}

export function buildAccountWelcomeEmailV1(
  input: AccountWelcomeEmailV1Input,
): AccountWelcomeEmailV1 {
  return {
    family: 'ACCOUNT_WELCOME',
    version: 1,
    recipientDisplayName: requiredText(input.recipientDisplayName, 'recipientDisplayName'),
    organizationName: requiredText(input.organizationName, 'organizationName'),
    projectName: requiredText(input.projectName, 'projectName'),
    consoleBaseUrl: httpBaseUrl(input.consoleBaseUrl, 'consoleBaseUrl'),
    docsBaseUrl: httpBaseUrl(input.docsBaseUrl, 'docsBaseUrl'),
  };
}

export function buildOrganizationInvitationEmailV1(
  input: OrganizationInvitationEmailV1Input,
): OrganizationInvitationEmailV1 {
  return {
    family: 'ORGANIZATION_INVITATION',
    version: 1,
    invitationId: requiredText(input.invitationId, 'invitationId'),
    organizationName: requiredText(input.organizationName, 'organizationName'),
    inviterDisplayName: requiredText(input.inviterDisplayName, 'inviterDisplayName'),
    invitedRole: invitationRole(input.invitedRole),
    consoleBaseUrl: httpBaseUrl(input.consoleBaseUrl, 'consoleBaseUrl'),
    expiresAt: isoTimestamp(input.expiresAt, 'expiresAt'),
  };
}

export function buildOwnerMembershipChangedEmailV1(
  input: OwnerMembershipChangedEmailV1Input,
): OwnerMembershipChangedEmailV1 {
  const common = {
    family: 'OWNER_MEMBERSHIP_CHANGED' as const,
    version: 1 as const,
    organizationName: requiredText(input.organizationName, 'organizationName'),
    ownerDisplayName: requiredText(input.ownerDisplayName, 'ownerDisplayName'),
    changedByDisplayName: requiredText(input.changedByDisplayName, 'changedByDisplayName'),
  };
  switch (input.change) {
    case 'ADDED':
      return { ...common, change: 'ADDED' };
    case 'REMOVED':
      return { ...common, change: 'REMOVED' };
    default:
      return assertNever(input);
  }
}

export function buildMembershipAccessChangedEmailV1(
  input: MembershipAccessChangedEmailV1Input,
): MembershipAccessChangedEmailV1 {
  const common = {
    family: 'MEMBERSHIP_ACCESS_CHANGED' as const,
    version: 1 as const,
    organizationName: requiredText(input.organizationName, 'organizationName'),
    memberDisplayName: requiredText(input.memberDisplayName, 'memberDisplayName'),
    changedByDisplayName: requiredText(input.changedByDisplayName, 'changedByDisplayName'),
  };
  switch (input.change) {
    case 'SUSPENDED':
      return { ...common, change: 'SUSPENDED' };
    case 'REMOVED':
      return { ...common, change: 'REMOVED' };
    default:
      return assertNever(input);
  }
}

export function buildPrepaidTopUpReceiptEmailV1(
  input: PrepaidTopUpReceiptEmailV1Input,
): PrepaidTopUpReceiptEmailV1 {
  return {
    family: 'PREPAID_TOP_UP_RECEIPT',
    version: 1,
    organizationName: requiredText(input.organizationName, 'organizationName'),
    purchaseId: requiredText(input.purchaseId, 'purchaseId'),
    amountMinor: positiveMinorAmount(input.amountMinor, 'amountMinor'),
    balanceAfterMinor: integerMinorAmount(input.balanceAfterMinor, 'balanceAfterMinor'),
    currency: 'USD',
    purchasedAt: isoTimestamp(input.purchasedAt, 'purchasedAt'),
    consoleBaseUrl: httpBaseUrl(input.consoleBaseUrl, 'consoleBaseUrl'),
  };
}

export function buildBillingRefundResultEmailV1(
  input: BillingRefundResultEmailV1Input,
): BillingRefundResultEmailV1 {
  const common = {
    family: 'BILLING_REFUND_RESULT' as const,
    version: 1 as const,
    organizationName: requiredText(input.organizationName, 'organizationName'),
    refundId: requiredText(input.refundId, 'refundId'),
    amountMinor: positiveMinorAmount(input.amountMinor, 'amountMinor'),
    currency: 'USD' as const,
    consoleBaseUrl: httpBaseUrl(input.consoleBaseUrl, 'consoleBaseUrl'),
  };
  switch (input.outcome) {
    case 'SUCCEEDED':
      return {
        ...common,
        outcome: 'SUCCEEDED',
        balanceAfterMinor: integerMinorAmount(input.balanceAfterMinor, 'balanceAfterMinor'),
      };
    case 'FAILED':
      return {
        ...common,
        outcome: 'FAILED',
        failureCode: requiredText(input.failureCode, 'failureCode'),
      };
    default:
      return assertNever(input);
  }
}

export function buildLowBalanceWarningEmailV1(
  input: LowBalanceWarningEmailV1Input,
): LowBalanceWarningEmailV1 {
  return {
    family: 'LOW_BALANCE_WARNING',
    version: 1,
    organizationName: requiredText(input.organizationName, 'organizationName'),
    balanceMinor: integerMinorAmount(input.balanceMinor, 'balanceMinor'),
    thresholdMinor: nonNegativeMinorAmount(input.thresholdMinor, 'thresholdMinor'),
    currency: 'USD',
    consoleBaseUrl: httpBaseUrl(input.consoleBaseUrl, 'consoleBaseUrl'),
  };
}

export function parseConsoleEmailTemplate(raw: unknown): ConsoleEmailTemplateV1 {
  const record = unknownRecord(raw, 'template');
  if (record.version !== 1) {
    throw new Error('Unsupported console email template version');
  }
  switch (record.family) {
    case 'ACCOUNT_WELCOME':
      return parseAccountWelcome(record);
    case 'ORGANIZATION_INVITATION':
      return parseOrganizationInvitation(record);
    case 'OWNER_MEMBERSHIP_CHANGED':
      return parseOwnerMembershipChanged(record);
    case 'MEMBERSHIP_ACCESS_CHANGED':
      return parseMembershipAccessChanged(record);
    case 'PREPAID_TOP_UP_RECEIPT':
      return parsePrepaidTopUpReceipt(record);
    case 'BILLING_REFUND_RESULT':
      return parseBillingRefundResult(record);
    case 'LOW_BALANCE_WARNING':
      return parseLowBalanceWarning(record);
    default:
      throw new Error('Unsupported console email template family');
  }
}

export function renderOrganizationInvitationEmailV1(
  template: OrganizationInvitationEmailV1,
  invitationSecret: string,
): RenderedConsoleEmail {
  const secret = requiredText(invitationSecret, 'invitationSecret');
  const invitationUrl = new URL('/dashboard/invitations/accept', template.consoleBaseUrl);
  invitationUrl.searchParams.set('invitation_id', template.invitationId);
  invitationUrl.searchParams.set('token', secret);
  const subject = `Invitation to join ${template.organizationName}`;
  const role = invitationRoleLabel(template.invitedRole);
  const text = [
    `${template.inviterDisplayName} invited you to join ${template.organizationName} as ${role}.`,
    `Accept the invitation: ${invitationUrl.toString()}`,
    `This invitation expires ${template.expiresAt}.`,
  ].join('\n\n');
  return {
    subject,
    text,
    html: htmlMessage({
      heading: subject,
      paragraphs: [
        `${template.inviterDisplayName} invited you to join ${template.organizationName} as ${role}.`,
        `This invitation expires ${template.expiresAt}.`,
      ],
      actionLabel: 'Accept invitation',
      actionUrl: invitationUrl.toString(),
    }),
  };
}

export function renderConsoleEmailV1(
  template: ConsoleEmailNonInvitationTemplateV1,
): RenderedConsoleEmail {
  switch (template.family) {
    case 'ACCOUNT_WELCOME':
      return renderAccountWelcome(template);
    case 'OWNER_MEMBERSHIP_CHANGED':
      return renderOwnerMembershipChanged(template);
    case 'MEMBERSHIP_ACCESS_CHANGED':
      return renderMembershipAccessChanged(template);
    case 'PREPAID_TOP_UP_RECEIPT':
      return renderPrepaidTopUpReceipt(template);
    case 'BILLING_REFUND_RESULT':
      return renderBillingRefundResult(template);
    case 'LOW_BALANCE_WARNING':
      return renderLowBalanceWarning(template);
    default:
      return assertNever(template);
  }
}

function parseAccountWelcome(record: UnknownRecord): AccountWelcomeEmailV1 {
  return buildAccountWelcomeEmailV1({
    recipientDisplayName: requiredRawString(record.recipientDisplayName, 'recipientDisplayName'),
    organizationName: requiredRawString(record.organizationName, 'organizationName'),
    projectName: requiredRawString(record.projectName, 'projectName'),
    consoleBaseUrl: requiredRawString(record.consoleBaseUrl, 'consoleBaseUrl'),
    docsBaseUrl: requiredRawString(record.docsBaseUrl, 'docsBaseUrl'),
  });
}

function parseOrganizationInvitation(record: UnknownRecord): OrganizationInvitationEmailV1 {
  rejectPresent(record, 'invitationSecret');
  rejectPresent(record, 'token');
  return buildOrganizationInvitationEmailV1({
    invitationId: requiredRawString(record.invitationId, 'invitationId'),
    organizationName: requiredRawString(record.organizationName, 'organizationName'),
    inviterDisplayName: requiredRawString(record.inviterDisplayName, 'inviterDisplayName'),
    invitedRole: parseInvitationRole(record.invitedRole),
    consoleBaseUrl: requiredRawString(record.consoleBaseUrl, 'consoleBaseUrl'),
    expiresAt: requiredRawString(record.expiresAt, 'expiresAt'),
  });
}

function parseOwnerMembershipChanged(record: UnknownRecord): OwnerMembershipChangedEmailV1 {
  const common = {
    organizationName: requiredRawString(record.organizationName, 'organizationName'),
    ownerDisplayName: requiredRawString(record.ownerDisplayName, 'ownerDisplayName'),
    changedByDisplayName: requiredRawString(record.changedByDisplayName, 'changedByDisplayName'),
  };
  switch (record.change) {
    case 'ADDED':
      return buildOwnerMembershipChangedEmailV1({ ...common, change: 'ADDED' });
    case 'REMOVED':
      return buildOwnerMembershipChangedEmailV1({ ...common, change: 'REMOVED' });
    default:
      throw new Error('Invalid owner membership email change');
  }
}

function parseMembershipAccessChanged(record: UnknownRecord): MembershipAccessChangedEmailV1 {
  const common = {
    organizationName: requiredRawString(record.organizationName, 'organizationName'),
    memberDisplayName: requiredRawString(record.memberDisplayName, 'memberDisplayName'),
    changedByDisplayName: requiredRawString(record.changedByDisplayName, 'changedByDisplayName'),
  };
  switch (record.change) {
    case 'SUSPENDED':
      return buildMembershipAccessChangedEmailV1({ ...common, change: 'SUSPENDED' });
    case 'REMOVED':
      return buildMembershipAccessChangedEmailV1({ ...common, change: 'REMOVED' });
    default:
      throw new Error('Invalid membership access email change');
  }
}

function parsePrepaidTopUpReceipt(record: UnknownRecord): PrepaidTopUpReceiptEmailV1 {
  requireUsd(record.currency);
  return buildPrepaidTopUpReceiptEmailV1({
    organizationName: requiredRawString(record.organizationName, 'organizationName'),
    purchaseId: requiredRawString(record.purchaseId, 'purchaseId'),
    amountMinor: requiredRawNumber(record.amountMinor, 'amountMinor'),
    balanceAfterMinor: requiredRawNumber(record.balanceAfterMinor, 'balanceAfterMinor'),
    purchasedAt: requiredRawString(record.purchasedAt, 'purchasedAt'),
    consoleBaseUrl: requiredRawString(record.consoleBaseUrl, 'consoleBaseUrl'),
  });
}

function parseBillingRefundResult(record: UnknownRecord): BillingRefundResultEmailV1 {
  requireUsd(record.currency);
  const common = {
    organizationName: requiredRawString(record.organizationName, 'organizationName'),
    refundId: requiredRawString(record.refundId, 'refundId'),
    amountMinor: requiredRawNumber(record.amountMinor, 'amountMinor'),
    consoleBaseUrl: requiredRawString(record.consoleBaseUrl, 'consoleBaseUrl'),
  };
  switch (record.outcome) {
    case 'SUCCEEDED':
      rejectPresent(record, 'failureCode');
      return buildBillingRefundResultEmailV1({
        ...common,
        outcome: 'SUCCEEDED',
        balanceAfterMinor: requiredRawNumber(record.balanceAfterMinor, 'balanceAfterMinor'),
      });
    case 'FAILED':
      rejectPresent(record, 'balanceAfterMinor');
      return buildBillingRefundResultEmailV1({
        ...common,
        outcome: 'FAILED',
        failureCode: requiredRawString(record.failureCode, 'failureCode'),
      });
    default:
      throw new Error('Invalid billing refund email outcome');
  }
}

function parseLowBalanceWarning(record: UnknownRecord): LowBalanceWarningEmailV1 {
  requireUsd(record.currency);
  return buildLowBalanceWarningEmailV1({
    organizationName: requiredRawString(record.organizationName, 'organizationName'),
    balanceMinor: requiredRawNumber(record.balanceMinor, 'balanceMinor'),
    thresholdMinor: requiredRawNumber(record.thresholdMinor, 'thresholdMinor'),
    consoleBaseUrl: requiredRawString(record.consoleBaseUrl, 'consoleBaseUrl'),
  });
}

function renderOwnerMembershipChanged(
  template: OwnerMembershipChangedEmailV1,
): RenderedConsoleEmail {
  const added = template.change === 'ADDED';
  const subject = added
    ? `Owner added to ${template.organizationName}`
    : `Owner removed from ${template.organizationName}`;
  const sentence = added
    ? `${template.ownerDisplayName} is now an owner of ${template.organizationName}.`
    : `${template.ownerDisplayName} is no longer an owner of ${template.organizationName}.`;
  const changedBy = `This change was made by ${template.changedByDisplayName}.`;
  return {
    subject,
    text: `${sentence}\n\n${changedBy}`,
    html: htmlMessage({
      heading: subject,
      paragraphs: [sentence, changedBy],
      actionLabel: null,
      actionUrl: null,
    }),
  };
}

function renderAccountWelcome(template: AccountWelcomeEmailV1): RenderedConsoleEmail {
  const consoleUrl = new URL('/dashboard', template.consoleBaseUrl).toString();
  const quickstartUrl = new URL('/getting-started/', template.docsBaseUrl).toString();
  const architectureUrl = new URL('/concepts/architecture', template.docsBaseUrl).toString();
  const subject = 'Welcome to Seams';
  const greeting = `Hey ${template.recipientDisplayName},`;
  const setup = `Your ${template.organizationName} organization and ${template.projectName} project are ready.`;
  const purpose =
    'We built Seams to make keys, credentials, and policies easier to ship without giving up control of your infrastructure.';
  const question = 'P.S. What are you building? Reply and tell us. We read every response.';
  const text = [
    greeting,
    'Welcome to Seams.',
    setup,
    purpose,
    'Here are three good places to start:',
    `1. Open your console: ${consoleUrl}`,
    `2. Follow the quickstart: ${quickstartUrl}`,
    `3. See how Seams works: ${architectureUrl}`,
    question,
    'Cheers,\nThe Seams team',
  ].join('\n\n');
  const html = `<!doctype html><html><body style="margin:0;background:#ffffff;color:#151515;font-family:Arial,Helvetica,sans-serif"><div style="max-width:600px;margin:0 auto;padding:40px 24px;font-size:17px;line-height:1.6"><p>${escapeHtml(greeting)}</p><p>Welcome to Seams.</p><p>${escapeHtml(setup)}</p><p>${escapeHtml(purpose)}</p><p>Here are three good places to start:</p><ol><li><a href="${escapeHtml(consoleUrl)}">Open your console</a></li><li><a href="${escapeHtml(quickstartUrl)}">Follow the quickstart</a></li><li><a href="${escapeHtml(architectureUrl)}">See how Seams works</a></li></ol><p><strong>${escapeHtml(question)}</strong></p><p>Cheers,<br>The Seams team</p></div></body></html>`;
  return { subject, text, html };
}

function renderMembershipAccessChanged(
  template: MembershipAccessChangedEmailV1,
): RenderedConsoleEmail {
  const suspended = template.change === 'SUSPENDED';
  const subject = suspended
    ? `Membership suspended for ${template.organizationName}`
    : `Membership removed from ${template.organizationName}`;
  const sentence = suspended
    ? `${template.memberDisplayName}'s access to ${template.organizationName} has been suspended.`
    : `${template.memberDisplayName}'s access to ${template.organizationName} has been removed.`;
  const changedBy = `This change was made by ${template.changedByDisplayName}.`;
  return {
    subject,
    text: `${sentence}\n\n${changedBy}`,
    html: htmlMessage({
      heading: subject,
      paragraphs: [sentence, changedBy],
      actionLabel: null,
      actionUrl: null,
    }),
  };
}

function renderPrepaidTopUpReceipt(template: PrepaidTopUpReceiptEmailV1): RenderedConsoleEmail {
  const subject = `Top-up receipt for ${template.organizationName}`;
  const amount = usd(template.amountMinor);
  const balance = usd(template.balanceAfterMinor);
  const details = `We received your ${amount} prepaid top-up. Your balance is ${balance}.`;
  const reference = `Purchase ${template.purchaseId} on ${template.purchasedAt}.`;
  return {
    subject,
    text: `${details}\n\n${reference}\n\nView billing: ${billingUrl(template.consoleBaseUrl)}`,
    html: htmlMessage({
      heading: subject,
      paragraphs: [details, reference],
      actionLabel: 'View billing',
      actionUrl: billingUrl(template.consoleBaseUrl),
    }),
  };
}

function renderBillingRefundResult(template: BillingRefundResultEmailV1): RenderedConsoleEmail {
  switch (template.outcome) {
    case 'SUCCEEDED':
      return renderSucceededRefund(template);
    case 'FAILED':
      return renderFailedRefund(template);
    default:
      return assertNever(template);
  }
}

function renderSucceededRefund(
  template: Extract<BillingRefundResultEmailV1, { readonly outcome: 'SUCCEEDED' }>,
): RenderedConsoleEmail {
  const subject = `Refund completed for ${template.organizationName}`;
  const details = `${usd(template.amountMinor)} was refunded. Your prepaid balance is ${usd(
    template.balanceAfterMinor,
  )}.`;
  const reference = `Refund reference: ${template.refundId}.`;
  return {
    subject,
    text: `${details}\n\n${reference}\n\nView billing: ${billingUrl(template.consoleBaseUrl)}`,
    html: htmlMessage({
      heading: subject,
      paragraphs: [details, reference],
      actionLabel: 'View billing',
      actionUrl: billingUrl(template.consoleBaseUrl),
    }),
  };
}

function renderFailedRefund(
  template: Extract<BillingRefundResultEmailV1, { readonly outcome: 'FAILED' }>,
): RenderedConsoleEmail {
  const subject = `Refund failed for ${template.organizationName}`;
  const details = `${usd(template.amountMinor)} could not be refunded. No refund was applied.`;
  const reference = `Refund reference: ${template.refundId}. Error code: ${template.failureCode}.`;
  return {
    subject,
    text: `${details}\n\n${reference}\n\nView billing: ${billingUrl(template.consoleBaseUrl)}`,
    html: htmlMessage({
      heading: subject,
      paragraphs: [details, reference],
      actionLabel: 'View billing',
      actionUrl: billingUrl(template.consoleBaseUrl),
    }),
  };
}

function renderLowBalanceWarning(template: LowBalanceWarningEmailV1): RenderedConsoleEmail {
  const subject = `Low prepaid balance for ${template.organizationName}`;
  const details = `Your prepaid balance is ${usd(
    template.balanceMinor,
  )}, below your ${usd(template.thresholdMinor)} warning threshold.`;
  return {
    subject,
    text: `${details}\n\nTop up: ${billingUrl(template.consoleBaseUrl)}`,
    html: htmlMessage({
      heading: subject,
      paragraphs: [details],
      actionLabel: 'Top up balance',
      actionUrl: billingUrl(template.consoleBaseUrl),
    }),
  };
}

function htmlMessage(input: {
  readonly heading: string;
  readonly paragraphs: readonly string[];
  readonly actionLabel: string | null;
  readonly actionUrl: string | null;
}): string {
  let body = `<h1>${escapeHtml(input.heading)}</h1>`;
  for (const paragraph of input.paragraphs) {
    body += `<p>${escapeHtml(paragraph)}</p>`;
  }
  if (input.actionLabel && input.actionUrl) {
    body += `<p><a href="${escapeHtml(input.actionUrl)}">${escapeHtml(input.actionLabel)}</a></p>`;
  }
  return `<!doctype html><html><body>${body}<p>Seams</p></body></html>`;
}

function billingUrl(consoleBaseUrl: string): string {
  return new URL('/dashboard/billing', consoleBaseUrl).toString();
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function invitationRoleLabel(role: ConsoleEmailInvitationRole): string {
  switch (role) {
    case 'OWNER':
      return 'an owner';
    case 'ADMIN':
      return 'an administrator';
    case 'MEMBER':
      return 'a member';
    default:
      return assertNever(role);
  }
}

function parseInvitationRole(value: unknown): ConsoleEmailInvitationRole {
  switch (value) {
    case 'OWNER':
    case 'ADMIN':
    case 'MEMBER':
      return value;
    default:
      throw new Error('Invalid invitedRole');
  }
}

function invitationRole(value: ConsoleEmailInvitationRole): ConsoleEmailInvitationRole {
  return parseInvitationRole(value);
}

function usd(minor: number): string {
  const negative = minor < 0;
  const absolute = Math.abs(minor);
  const major = Math.floor(absolute / 100);
  const cents = String(absolute % 100).padStart(2, '0');
  return `${negative ? '-' : ''}$${major}.${cents}`;
}

function requiredText(value: string, field: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error(`${field} is required`);
  return normalized;
}

function requiredRawString(value: unknown, field: string): string {
  if (typeof value !== 'string') throw new Error(`${field} must be a string`);
  return requiredText(value, field);
}

function requiredRawNumber(value: unknown, field: string): number {
  if (typeof value !== 'number') throw new Error(`${field} must be a number`);
  return value;
}

function integerMinorAmount(value: number, field: string): number {
  if (!Number.isSafeInteger(value)) throw new Error(`${field} must be a safe integer`);
  return value;
}

function positiveMinorAmount(value: number, field: string): number {
  const amount = integerMinorAmount(value, field);
  if (amount <= 0) throw new Error(`${field} must be positive`);
  return amount;
}

function nonNegativeMinorAmount(value: number, field: string): number {
  const amount = integerMinorAmount(value, field);
  if (amount < 0) throw new Error(`${field} must be non-negative`);
  return amount;
}

function isoTimestamp(value: string, field: string): string {
  const normalized = requiredText(value, field);
  const date = new Date(normalized);
  if (!Number.isFinite(date.getTime())) throw new Error(`${field} must be an ISO timestamp`);
  return date.toISOString();
}

function httpBaseUrl(value: string, field: string): string {
  const url = new URL(requiredText(value, field));
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`${field} must use http or https`);
  }
  url.pathname = '/';
  url.search = '';
  url.hash = '';
  return url.toString();
}

function unknownRecord(value: unknown, field: string): UnknownRecord {
  if (!isUnknownRecord(value)) {
    throw new Error(`${field} must be an object`);
  }
  return value;
}

function isUnknownRecord(value: unknown): value is UnknownRecord {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function requireUsd(value: unknown): void {
  if (value !== 'USD') throw new Error('currency must be USD');
}

function rejectPresent(record: UnknownRecord, field: string): void {
  if (field in record) throw new Error(`${field} is not allowed for this email template`);
}

function assertNever(value: never): never {
  throw new Error(`Unhandled console email branch: ${JSON.stringify(value)}`);
}
