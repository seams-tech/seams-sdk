CREATE TABLE tenant_root_role_shares (
    tenant_identity_digest_hex TEXT NOT NULL CHECK (
        length(tenant_identity_digest_hex) = 64
        AND tenant_identity_digest_hex NOT GLOB '*[^0-9a-f]*'
    ),
    custody_lineage_b64u TEXT NOT NULL CHECK (length(custody_lineage_b64u) = 22),
    tenant_root_share_epoch INTEGER NOT NULL CHECK (tenant_root_share_epoch > 0),
    role TEXT NOT NULL CHECK (role = 'deriver_b'),
    lifecycle TEXT NOT NULL CHECK (lifecycle IN ('pending', 'active', 'retired')),
    ciphertext_json TEXT NOT NULL CHECK (json_valid(ciphertext_json)),
    revision INTEGER NOT NULL CHECK (revision > 0),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms > 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    PRIMARY KEY (
        tenant_identity_digest_hex,
        custody_lineage_b64u,
        tenant_root_share_epoch,
        role
    )
);

CREATE UNIQUE INDEX tenant_root_role_shares_active
    ON tenant_root_role_shares (tenant_identity_digest_hex, role)
    WHERE lifecycle = 'active';

CREATE INDEX tenant_root_role_shares_lifecycle
    ON tenant_root_role_shares (
        tenant_identity_digest_hex,
        role,
        lifecycle,
        tenant_root_share_epoch
    );
