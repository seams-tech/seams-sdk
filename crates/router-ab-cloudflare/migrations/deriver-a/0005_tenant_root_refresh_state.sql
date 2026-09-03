ALTER TABLE tenant_root_command_replays
    ADD COLUMN refresh_state_b64u TEXT CHECK (
        refresh_state_b64u IS NULL OR (
            length(refresh_state_b64u) > 0
            AND length(refresh_state_b64u) <= 174764
            AND refresh_state_b64u NOT GLOB '*[^A-Za-z0-9_-]*'
        )
    );
ALTER TABLE tenant_root_command_replays
    ADD COLUMN refresh_state_digest_hex TEXT CHECK (
        refresh_state_digest_hex IS NULL OR (
            length(refresh_state_digest_hex) = 64
            AND refresh_state_digest_hex NOT GLOB '*[^0-9a-f]*'
        )
    );
