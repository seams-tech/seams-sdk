-- R103E gives every linked device its own Email OTP auth method. Multiple
-- devices may share the wallet's verified delivery address.
DROP INDEX IF EXISTS wallet_auth_methods_v2_email_uidx;
