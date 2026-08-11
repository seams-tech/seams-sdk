export type ConsoleEmailTemplateVersion = 1;

export type ConsoleEmailTemplateFamily =
  | 'ACCOUNT_WELCOME'
  | 'ORGANIZATION_INVITATION'
  | 'OWNER_MEMBERSHIP_CHANGED'
  | 'MEMBERSHIP_ACCESS_CHANGED'
  | 'PREPAID_TOP_UP_RECEIPT'
  | 'BILLING_REFUND_RESULT'
  | 'LOW_BALANCE_WARNING';

export type ConsoleEmailInvitationRole = 'OWNER' | 'ADMIN' | 'MEMBER';

export interface ConsoleEmailRecipient {
  readonly email: string;
  readonly displayName: string;
}

export interface OrganizationInvitationEmailV1 {
  readonly family: 'ORGANIZATION_INVITATION';
  readonly version: 1;
  readonly invitationId: string;
  readonly organizationName: string;
  readonly inviterDisplayName: string;
  readonly invitedRole: ConsoleEmailInvitationRole;
  readonly consoleBaseUrl: string;
  readonly expiresAt: string;
}

export interface AccountWelcomeEmailV1 {
  readonly family: 'ACCOUNT_WELCOME';
  readonly version: 1;
  readonly recipientDisplayName: string;
  readonly organizationName: string;
  readonly projectName: string;
  readonly consoleBaseUrl: string;
  readonly docsBaseUrl: string;
}

export type OwnerMembershipChangedEmailV1 =
  | {
      readonly family: 'OWNER_MEMBERSHIP_CHANGED';
      readonly version: 1;
      readonly change: 'ADDED';
      readonly organizationName: string;
      readonly ownerDisplayName: string;
      readonly changedByDisplayName: string;
    }
  | {
      readonly family: 'OWNER_MEMBERSHIP_CHANGED';
      readonly version: 1;
      readonly change: 'REMOVED';
      readonly organizationName: string;
      readonly ownerDisplayName: string;
      readonly changedByDisplayName: string;
    };

export type MembershipAccessChangedEmailV1 =
  | {
      readonly family: 'MEMBERSHIP_ACCESS_CHANGED';
      readonly version: 1;
      readonly change: 'SUSPENDED';
      readonly organizationName: string;
      readonly memberDisplayName: string;
      readonly changedByDisplayName: string;
    }
  | {
      readonly family: 'MEMBERSHIP_ACCESS_CHANGED';
      readonly version: 1;
      readonly change: 'REMOVED';
      readonly organizationName: string;
      readonly memberDisplayName: string;
      readonly changedByDisplayName: string;
    };

export interface PrepaidTopUpReceiptEmailV1 {
  readonly family: 'PREPAID_TOP_UP_RECEIPT';
  readonly version: 1;
  readonly organizationName: string;
  readonly purchaseId: string;
  readonly amountMinor: number;
  readonly balanceAfterMinor: number;
  readonly currency: 'USD';
  readonly purchasedAt: string;
  readonly consoleBaseUrl: string;
}

export type BillingRefundResultEmailV1 =
  | {
      readonly family: 'BILLING_REFUND_RESULT';
      readonly version: 1;
      readonly outcome: 'SUCCEEDED';
      readonly organizationName: string;
      readonly refundId: string;
      readonly amountMinor: number;
      readonly currency: 'USD';
      readonly balanceAfterMinor: number;
      readonly consoleBaseUrl: string;
      readonly failureCode?: never;
    }
  | {
      readonly family: 'BILLING_REFUND_RESULT';
      readonly version: 1;
      readonly outcome: 'FAILED';
      readonly organizationName: string;
      readonly refundId: string;
      readonly amountMinor: number;
      readonly currency: 'USD';
      readonly consoleBaseUrl: string;
      readonly failureCode: string;
      readonly balanceAfterMinor?: never;
    };

export interface LowBalanceWarningEmailV1 {
  readonly family: 'LOW_BALANCE_WARNING';
  readonly version: 1;
  readonly organizationName: string;
  readonly balanceMinor: number;
  readonly thresholdMinor: number;
  readonly currency: 'USD';
  readonly consoleBaseUrl: string;
}

export type ConsoleEmailTemplateV1 =
  | AccountWelcomeEmailV1
  | OrganizationInvitationEmailV1
  | OwnerMembershipChangedEmailV1
  | MembershipAccessChangedEmailV1
  | PrepaidTopUpReceiptEmailV1
  | BillingRefundResultEmailV1
  | LowBalanceWarningEmailV1;

export type ConsoleEmailNonInvitationTemplateV1 = Exclude<
  ConsoleEmailTemplateV1,
  OrganizationInvitationEmailV1
>;

interface ConsoleEmailOutboxInsertCommon {
  readonly outboxId: string;
  readonly dedupeKey: string;
  readonly orgId: string;
  readonly recipient: ConsoleEmailRecipient;
  readonly createdAt: Date;
  readonly availableAt: Date;
}

export type ConsoleEmailOutboxInsert =
  | (ConsoleEmailOutboxInsertCommon & {
      readonly template: OrganizationInvitationEmailV1;
      readonly invitationSecret: string;
    })
  | (ConsoleEmailOutboxInsertCommon & {
      readonly template: ConsoleEmailNonInvitationTemplateV1;
      readonly invitationSecret?: never;
    });

export type ConsoleEmailOutboxStatus = 'PENDING' | 'SENT' | 'FINAL_FAILED' | 'CANCELED';

interface ConsoleEmailOutboxRecordCommon {
  readonly id: string;
  readonly orgId: string;
  readonly recipient: ConsoleEmailRecipient;
  readonly templateFamily: ConsoleEmailTemplateFamily;
  readonly templateVersion: ConsoleEmailTemplateVersion;
  readonly totalAttemptCount: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export type ConsoleEmailOutboxRecord =
  | (ConsoleEmailOutboxRecordCommon & {
      readonly status: 'PENDING';
      readonly availableAt: string;
      readonly sentAt: null;
      readonly canceledAt: null;
      readonly lastErrorCode: string | null;
    })
  | (ConsoleEmailOutboxRecordCommon & {
      readonly status: 'SENT';
      readonly availableAt: null;
      readonly sentAt: string;
      readonly canceledAt: null;
      readonly lastErrorCode: null;
    })
  | (ConsoleEmailOutboxRecordCommon & {
      readonly status: 'FINAL_FAILED';
      readonly availableAt: null;
      readonly sentAt: null;
      readonly canceledAt: null;
      readonly lastErrorCode: string;
    })
  | (ConsoleEmailOutboxRecordCommon & {
      readonly status: 'CANCELED';
      readonly availableAt: null;
      readonly sentAt: null;
      readonly canceledAt: string;
      readonly lastErrorCode: null;
    });

export type ConsoleEmailDeliveryOutcome = 'SENT' | 'RETRYABLE_FAILED' | 'FINAL_FAILED';

export interface ConsoleEmailDelivery {
  readonly id: string;
  readonly outboxId: string;
  readonly orgId: string;
  readonly attemptNumber: number;
  readonly outcome: ConsoleEmailDeliveryOutcome;
  readonly provider: 'capture' | 'resend';
  readonly providerMessageId: string | null;
  readonly providerStatusCode: number | null;
  readonly errorCode: string | null;
  readonly attemptedAt: string;
}

export interface ConsoleEmailFinalFailure {
  readonly outboxId: string;
  readonly orgId: string;
  readonly recipient: ConsoleEmailRecipient;
  readonly templateFamily: ConsoleEmailTemplateFamily;
  readonly totalAttemptCount: number;
  readonly lastErrorCode: string;
  readonly failedAt: string;
}

export interface RenderedConsoleEmail {
  readonly subject: string;
  readonly text: string;
  readonly html: string;
}

export interface ConsoleEmailProviderSendRequest extends RenderedConsoleEmail {
  readonly outboxId: string;
  readonly recipient: ConsoleEmailRecipient;
}

export type ConsoleEmailProviderSendResult =
  | {
      readonly kind: 'SENT';
      readonly providerMessageId: string;
      readonly statusCode: number | null;
    }
  | {
      readonly kind: 'RETRYABLE_FAILURE';
      readonly errorCode: string;
      readonly statusCode: number | null;
    }
  | {
      readonly kind: 'FINAL_FAILURE';
      readonly errorCode: string;
      readonly statusCode: number | null;
    };

export interface ConsoleEmailProvider {
  readonly provider: 'capture' | 'resend';
  send(request: ConsoleEmailProviderSendRequest): Promise<ConsoleEmailProviderSendResult>;
}

export interface CapturedConsoleEmail extends ConsoleEmailProviderSendRequest {
  readonly providerMessageId: string;
}

export interface CaptureConsoleEmailProvider extends ConsoleEmailProvider {
  readonly provider: 'capture';
  listCaptured(): readonly CapturedConsoleEmail[];
  clearCaptured(): void;
}

export interface ConsoleEmailDispatchFailure {
  readonly outboxId: string;
  readonly orgId: string;
  readonly code: string;
}

export interface ConsoleEmailDispatchResult {
  readonly claimedCount: number;
  readonly sentCount: number;
  readonly retryScheduledCount: number;
  readonly finalFailureCount: number;
  readonly canceledCount: number;
  readonly failures: readonly ConsoleEmailDispatchFailure[];
}
