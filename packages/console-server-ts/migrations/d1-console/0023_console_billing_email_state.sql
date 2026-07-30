ALTER TABLE billing_accounts
ADD COLUMN low_balance_warning_active INTEGER NOT NULL DEFAULT 1
CHECK (low_balance_warning_active IN (0, 1));

UPDATE billing_accounts
SET low_balance_warning_active = CASE
  WHEN (
    SELECT COALESCE(
      SUM(
        CASE posting.direction
          WHEN 'CREDIT' THEN posting.amount_minor
          ELSE -posting.amount_minor
        END
      ),
      0
    )
    FROM billing_ledger_postings AS posting
    WHERE posting.namespace = billing_accounts.namespace
      AND posting.org_id = billing_accounts.org_id
      AND posting.account_code = 'org_prepaid_liability'
  ) < low_balance_threshold_minor
  THEN 1
  ELSE 0
END;
