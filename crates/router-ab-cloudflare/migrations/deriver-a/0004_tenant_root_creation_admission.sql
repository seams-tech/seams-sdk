ALTER TABLE tenant_root_command_replays
    ADD COLUMN admission_digest_hex TEXT CHECK (
        admission_digest_hex IS NULL OR (
            length(admission_digest_hex) = 64
            AND admission_digest_hex NOT GLOB '*[^0-9a-f]*'
        )
    );
