ALTER TABLE linked_device_authority_installations
  ADD COLUMN delivery_recipient_public_key_b64u TEXT
  CHECK (
    delivery_recipient_public_key_b64u IS NULL
    OR length(delivery_recipient_public_key_b64u) > 0
  );
