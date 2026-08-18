export type SessionParseFailureReason =
  | 'missing'
  | 'signature_invalid'
  | 'claims_invalid'
  | 'expired'
  | 'not_active';

export type SessionParseResult<TClaims extends Record<string, unknown>> =
  | {
      readonly ok: true;
      readonly claims: TClaims;
    }
  | {
      readonly ok: false;
      readonly reason: SessionParseFailureReason;
    };
