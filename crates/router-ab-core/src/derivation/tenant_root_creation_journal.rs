use sha2::{Digest, Sha256};

use super::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
    TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1, TenantRootCreationStateV1,
    TenantRootCustodyLineageId, TenantRootEmptyCreationV1, TenantRootIdentityDigestV1,
    TenantRootIdentityV1, TenantRootProtocolDigestV1,
};

const TENANT_ROOT_CREATION_EVENT_DOMAIN_V1: &[u8] = b"seams/tenant-root-creation-event/v1";
const TENANT_ROOT_CREATION_STARTED_TAG_V1: &[u8] = b"started";
const TENANT_ROOT_CREATION_STARTED_REVISION_V1: u64 = 1;
const TENANT_ROOT_CREATION_GENESIS_PREVIOUS_EVENT_DIGEST_V1: [u8; 32] = [0; 32];

/// Maximum canonical wire size for the first tenant-root creation journal blob.
pub const TENANT_ROOT_CREATION_JOURNAL_MAX_BYTES_V1: usize = 16 * 1024;

/// The first immutable event in a tenant-root creation journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootCreationStartedEventV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    identity_canonical_bytes: Vec<u8>,
    ceremony_context_canonical_bytes: Vec<u8>,
}

impl TenantRootCreationStartedEventV1 {
    /// Creates one exact Started event from the resolved identity and creation ceremony.
    pub fn new(
        identity: TenantRootIdentityV1,
        custody_lineage: TenantRootCustodyLineageId,
        context: TenantRootCeremonyContextV1,
    ) -> RouterAbDerivationResult<Self> {
        let event = Self::from_parts(
            identity.digest()?,
            custody_lineage,
            identity.canonical_bytes()?,
            context.canonical_bytes()?,
        )?;
        event.canonical_bytes()?;
        Ok(event)
    }

    /// Returns the fixed Started revision.
    pub const fn revision(&self) -> u64 {
        TENANT_ROOT_CREATION_STARTED_REVISION_V1
    }

    /// Returns the immutable tenant-root identity digest in this event.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the immutable custody lineage in this event.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the exact canonical identity bytes retained by this event.
    pub fn identity_canonical_bytes(&self) -> &[u8] {
        &self.identity_canonical_bytes
    }

    /// Returns the exact canonical creation-only ceremony context bytes retained by this event.
    pub fn ceremony_context_canonical_bytes(&self) -> &[u8] {
        &self.ceremony_context_canonical_bytes
    }

    /// Returns the canonical event envelope.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate()?;
        let payload = self.payload_bytes()?;
        let mut bytes = Vec::new();
        push_field(&mut bytes, TENANT_ROOT_CREATION_EVENT_DOMAIN_V1)?;
        push_field(
            &mut bytes,
            &TENANT_ROOT_CREATION_STARTED_REVISION_V1.to_be_bytes(),
        )?;
        push_field(
            &mut bytes,
            &TENANT_ROOT_CREATION_GENESIS_PREVIOUS_EVENT_DIGEST_V1,
        )?;
        push_field(&mut bytes, self.identity_digest.as_bytes())?;
        push_field(&mut bytes, self.custody_lineage.as_bytes())?;
        push_field(&mut bytes, TENANT_ROOT_CREATION_STARTED_TAG_V1)?;
        push_field(&mut bytes, &payload)?;
        Ok(bytes)
    }

    /// Returns the digest of the complete canonical event envelope.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        TenantRootProtocolDigestV1::from_bytes(Sha256::digest(self.canonical_bytes()?).into())
    }

    /// Rebuilds the Preparing lifecycle state from the retained identity and context bytes.
    pub fn rebuild(
        &self,
        identity: TenantRootIdentityV1,
        custody_lineage: TenantRootCustodyLineageId,
    ) -> RouterAbDerivationResult<TenantRootCreationStateV1> {
        self.validate()?;
        if self.identity_digest != identity.digest()? {
            return Err(malformed(
                "tenant-root Started event identity does not match replay scope",
            ));
        }
        if self.custody_lineage != custody_lineage {
            return Err(malformed(
                "tenant-root Started event custody lineage does not match replay scope",
            ));
        }
        if self.identity_canonical_bytes != identity.canonical_bytes()? {
            return Err(malformed(
                "tenant-root Started event identity bytes do not match replay scope",
            ));
        }

        let replayed_identity =
            TenantRootIdentityV1::decode_canonical_bytes(&self.identity_canonical_bytes)?;
        let context = TenantRootCeremonyContextV1::decode_canonical_bytes(
            &self.ceremony_context_canonical_bytes,
        )?;
        if replayed_identity != identity {
            return Err(malformed(
                "tenant-root Started event replay identity is not canonical",
            ));
        }
        let preparing =
            TenantRootEmptyCreationV1::new(identity, custody_lineage).start(&context)?;
        let state = TenantRootCreationStateV1::Preparing(preparing);
        if state.revision() != self.revision() {
            return Err(malformed(
                "tenant-root Started event replay did not reproduce its exact state",
            ));
        }
        Ok(state)
    }

    fn from_parts(
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        identity_canonical_bytes: Vec<u8>,
        ceremony_context_canonical_bytes: Vec<u8>,
    ) -> RouterAbDerivationResult<Self> {
        let event = Self {
            identity_digest,
            custody_lineage,
            identity_canonical_bytes,
            ceremony_context_canonical_bytes,
        };
        event.validate()?;
        Ok(event)
    }

    fn payload_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        let mut payload = Vec::new();
        push_field(&mut payload, &self.identity_canonical_bytes)?;
        push_field(&mut payload, &self.ceremony_context_canonical_bytes)?;
        Ok(payload)
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        let identity =
            TenantRootIdentityV1::decode_canonical_bytes(&self.identity_canonical_bytes)?;
        if identity.digest()? != self.identity_digest {
            return Err(malformed(
                "tenant-root Started event identity digest does not match identity bytes",
            ));
        }
        let context = TenantRootCeremonyContextV1::decode_canonical_bytes(
            &self.ceremony_context_canonical_bytes,
        )?;
        require_creation_context(&context)?;
        if context.identity_digest() != self.identity_digest {
            return Err(malformed(
                "tenant-root Started event context identity does not match event identity",
            ));
        }
        if context.custody_lineage() != self.custody_lineage {
            return Err(malformed(
                "tenant-root Started event context lineage does not match event lineage",
            ));
        }
        Ok(())
    }
}

/// Canonical tenant-root creation journal containing the Started event only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantRootCreationJournalV1 {
    /// Initial creation was started for one identity and custody lineage.
    Started(TenantRootCreationStartedEventV1),
}

impl TenantRootCreationJournalV1 {
    /// Creates the first event in a tenant-root creation journal.
    pub fn started(
        identity: TenantRootIdentityV1,
        custody_lineage: TenantRootCustodyLineageId,
        context: TenantRootCeremonyContextV1,
    ) -> RouterAbDerivationResult<Self> {
        TenantRootCreationStartedEventV1::new(identity, custody_lineage, context).map(Self::Started)
    }

    /// Decodes exactly one canonical Started journal blob.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty() || bytes.len() > TENANT_ROOT_CREATION_JOURNAL_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant-root creation journal wire length is invalid",
            ));
        }
        let mut decoder = CreationJournalWireDecoderV1::new(bytes);
        decoder.require_field(TENANT_ROOT_CREATION_EVENT_DOMAIN_V1)?;
        let revision = decoder.u64_field("tenant-root creation journal revision")?;
        if revision != TENANT_ROOT_CREATION_STARTED_REVISION_V1 {
            return Err(malformed(
                "tenant-root creation journal revision is invalid",
            ));
        }
        if decoder.fixed_field::<32>("tenant-root creation journal previous event digest")?
            != TENANT_ROOT_CREATION_GENESIS_PREVIOUS_EVENT_DIGEST_V1
        {
            return Err(malformed(
                "tenant-root creation journal previous event digest is not genesis",
            ));
        }
        let identity_digest = TenantRootIdentityDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root creation journal identity digest")?,
        );
        let custody_lineage = TenantRootCustodyLineageId::from_bytes(
            decoder.fixed_field::<16>("tenant-root creation journal custody lineage")?,
        )?;
        if decoder.field("tenant-root creation journal event tag")?
            != TENANT_ROOT_CREATION_STARTED_TAG_V1
        {
            return Err(malformed(
                "tenant-root creation journal event tag is invalid",
            ));
        }
        let payload = decoder
            .field("tenant-root creation journal payload")?
            .to_vec();
        decoder.finish()?;

        let mut payload_decoder = CreationJournalWireDecoderV1::new(&payload);
        let identity_canonical_bytes = payload_decoder
            .field("tenant-root Started identity bytes")?
            .to_vec();
        let ceremony_context_canonical_bytes = payload_decoder
            .field("tenant-root Started ceremony context bytes")?
            .to_vec();
        payload_decoder.finish()?;

        let event = TenantRootCreationStartedEventV1::from_parts(
            identity_digest,
            custody_lineage,
            identity_canonical_bytes,
            ceremony_context_canonical_bytes,
        )?;
        let journal = Self::Started(event);
        if journal.canonical_bytes()? != bytes {
            return Err(malformed(
                "tenant-root creation journal wire is not canonical",
            ));
        }
        Ok(journal)
    }

    /// Returns the canonical journal blob.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        match self {
            Self::Started(event) => event.canonical_bytes(),
        }
    }

    /// Returns the digest of the complete canonical journal blob.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        match self {
            Self::Started(event) => event.digest(),
        }
    }

    /// Returns the journal revision.
    pub const fn revision(&self) -> u64 {
        match self {
            Self::Started(event) => event.revision(),
        }
    }

    /// Returns the immutable identity digest in the journal.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        match self {
            Self::Started(event) => event.identity_digest(),
        }
    }

    /// Returns the immutable custody lineage in the journal.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        match self {
            Self::Started(event) => event.custody_lineage(),
        }
    }

    /// Rebuilds the Preparing lifecycle state from the canonical journal blob.
    pub fn rebuild(
        &self,
        identity: TenantRootIdentityV1,
        custody_lineage: TenantRootCustodyLineageId,
    ) -> RouterAbDerivationResult<TenantRootCreationStateV1> {
        match self {
            Self::Started(event) => event.rebuild(identity, custody_lineage),
        }
    }
}

/// Decodes one canonical tenant-root creation journal blob.
pub fn decode_tenant_root_creation_journal_v1(
    bytes: &[u8],
) -> RouterAbDerivationResult<TenantRootCreationJournalV1> {
    TenantRootCreationJournalV1::decode_canonical_bytes(bytes)
}

/// Rebuilds one tenant-root creation state from its canonical journal blob.
pub fn rebuild_tenant_root_creation_state_v1(
    bytes: &[u8],
    identity: TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
) -> RouterAbDerivationResult<TenantRootCreationStateV1> {
    TenantRootCreationJournalV1::decode_canonical_bytes(bytes)?.rebuild(identity, custody_lineage)
}

fn require_creation_context(context: &TenantRootCeremonyContextV1) -> RouterAbDerivationResult<()> {
    if matches!(context.epochs(), TenantRootCeremonyEpochsV1::Create { .. }) {
        Ok(())
    } else {
        Err(malformed(
            "tenant-root Started event requires a creation ceremony context",
        ))
    }
}

fn push_field(out: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            "tenant-root creation journal field is required",
        ));
    }
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root creation journal field is too long"))?;
    let new_len = out
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(value.len()))
        .ok_or_else(|| malformed("tenant-root creation journal wire length overflows"))?;
    if new_len > TENANT_ROOT_CREATION_JOURNAL_MAX_BYTES_V1 {
        return Err(malformed("tenant-root creation journal wire is too long"));
    }
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn malformed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}

struct CreationJournalWireDecoderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CreationJournalWireDecoderV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn field(&mut self, name: &'static str) -> RouterAbDerivationResult<&'a [u8]> {
        let length_end = self
            .offset
            .checked_add(4)
            .ok_or_else(|| malformed("tenant-root creation journal offset overflows"))?;
        let length_bytes = self
            .bytes
            .get(self.offset..length_end)
            .ok_or_else(|| malformed("tenant-root creation journal field length is truncated"))?;
        let length = u32::from_be_bytes(
            length_bytes
                .try_into()
                .expect("fixed four-byte creation journal field length"),
        ) as usize;
        let value_end = length_end
            .checked_add(length)
            .ok_or_else(|| malformed("tenant-root creation journal field length overflows"))?;
        let value = self
            .bytes
            .get(length_end..value_end)
            .ok_or_else(|| malformed("tenant-root creation journal field is truncated"))?;
        self.offset = value_end;
        if value.is_empty() {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::EmptyField,
                format!("{name} is required"),
            ));
        }
        Ok(value)
    }

    fn require_field(&mut self, expected: &[u8]) -> RouterAbDerivationResult<()> {
        if self.field("tenant-root creation journal domain")? != expected {
            return Err(malformed("tenant-root creation journal domain is invalid"));
        }
        Ok(())
    }

    fn fixed_field<const N: usize>(
        &mut self,
        name: &'static str,
    ) -> RouterAbDerivationResult<[u8; N]> {
        self.field(name)?
            .try_into()
            .map_err(|_| malformed("tenant-root creation journal fixed field length is invalid"))
    }

    fn u64_field(&mut self, name: &'static str) -> RouterAbDerivationResult<u64> {
        Ok(u64::from_be_bytes(self.fixed_field::<8>(name)?))
    }

    fn finish(self) -> RouterAbDerivationResult<()> {
        if self.offset != self.bytes.len() {
            return Err(malformed("tenant-root creation journal has trailing bytes"));
        }
        Ok(())
    }
}
