use super::*;

/// Deterministic in-memory Durable Object storage used by tests and local checks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CloudflareDurableObjectMemoryStorageV1 {
    root_share_metadata: BTreeMap<String, CloudflareRootShareStartupMetadataV1>,
    replay_by_request_id: BTreeMap<String, CloudflareReplayReserveRequestV1>,
    replay_by_storage_key: BTreeMap<String, CloudflareReplayReserveRequestV1>,
    lifecycle_states: BTreeMap<String, RouterAbLifecycleStateV1>,
    derivation_ceremonies: BTreeMap<String, CloudflareDerivationCeremonyV1>,
    project_policies: BTreeMap<String, CloudflareRouterProjectPolicyRecordV1>,
    abuse_records: BTreeMap<String, CloudflareRouterAbuseRecordV1>,
    quota_reservations: BTreeMap<String, CloudflareRouterQuotaReservationV1>,
    wallet_budget_grants: BTreeMap<String, CloudflareRouterWalletBudgetGrantRecordV1>,
    signing_worker_activations: BTreeMap<String, CloudflareSigningWorkerOutputActivationRecordV1>,
    signing_worker_direct_activations: BTreeMap<
        String,
        CloudflareSigningWorkerDirectRecipientProofBundleActivationPendingRecordV1,
    >,
    active_signing_worker_states: BTreeMap<String, ActiveSigningWorkerStateV1>,
    signing_worker_round1_records: BTreeMap<String, CloudflareSigningWorkerRound1RecordV1>,
    signing_worker_ed25519_presign_pool_records:
        BTreeMap<String, CloudflareSigningWorkerEd25519PresignPoolRecordV1>,
    signing_worker_ecdsa_presignature_records:
        BTreeMap<String, CloudflareSigningWorkerEcdsaPresignatureRecordV1>,
    signing_worker_ecdsa_presignature_pool_records:
        BTreeMap<String, CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1>,
}

impl CloudflareDurableObjectMemoryStorageV1 {
    /// Creates empty in-memory Durable Object storage.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seeds root-share startup metadata at a precomputed storage key.
    pub fn seed_root_share_startup_metadata(
        &mut self,
        storage_key: impl Into<String>,
        metadata: CloudflareRootShareStartupMetadataV1,
    ) -> RouterAbProtocolResult<()> {
        let storage_key = storage_key.into();
        require_non_empty("storage_key", &storage_key)?;
        metadata.validate()?;
        self.root_share_metadata.insert(storage_key, metadata);
        Ok(())
    }

    /// Seeds project-policy state at a precomputed storage key.
    pub fn seed_router_project_policy(
        &mut self,
        storage_key: impl Into<String>,
        policy: CloudflareRouterProjectPolicyRecordV1,
    ) -> RouterAbProtocolResult<()> {
        let storage_key = storage_key.into();
        require_non_empty("storage_key", &storage_key)?;
        policy.validate()?;
        self.project_policies.insert(storage_key, policy);
        Ok(())
    }

    /// Seeds abuse-control state at a precomputed storage key.
    pub fn seed_router_abuse(
        &mut self,
        storage_key: impl Into<String>,
        abuse: CloudflareRouterAbuseRecordV1,
    ) -> RouterAbProtocolResult<()> {
        let storage_key = storage_key.into();
        require_non_empty("storage_key", &storage_key)?;
        abuse.validate()?;
        self.abuse_records.insert(storage_key, abuse);
        Ok(())
    }

    /// Reads a stored lifecycle state for tests and local smoke checks.
    pub fn lifecycle_state(&self, storage_key: &str) -> Option<&RouterAbLifecycleStateV1> {
        self.lifecycle_states.get(storage_key)
    }

    /// Reads a stored derivation ceremony for tests and local smoke checks.
    pub fn derivation_ceremony(
        &self,
        storage_key: &str,
    ) -> Option<&CloudflareDerivationCeremonyV1> {
        self.derivation_ceremonies.get(storage_key)
    }

    /// Reads a stored SigningWorker activation for tests and local smoke checks.
    pub fn signing_worker_activation(
        &self,
        storage_key: &str,
    ) -> Option<&CloudflareSigningWorkerOutputActivationRecordV1> {
        self.signing_worker_activations.get(storage_key)
    }

    /// Reads a pending direct activation delivery for tests and local smoke checks.
    pub fn signing_worker_direct_activation(
        &self,
        storage_key: &str,
    ) -> Option<&CloudflareSigningWorkerDirectRecipientProofBundleActivationPendingRecordV1> {
        self.signing_worker_direct_activations.get(storage_key)
    }

    /// Reads indexed active SigningWorker state for tests and local smoke checks.
    pub fn active_signing_worker_state(
        &self,
        storage_key: &str,
    ) -> Option<&ActiveSigningWorkerStateV1> {
        self.active_signing_worker_states.get(storage_key)
    }

    /// Reads a transcript-bound replay reservation for tests and local smoke checks.
    pub fn replay_reservation(
        &self,
        storage_key: &str,
    ) -> Option<&CloudflareReplayReserveRequestV1> {
        self.replay_by_storage_key.get(storage_key)
    }

    /// Reads an active quota reservation for tests and local smoke checks.
    pub fn quota_reservation(
        &self,
        storage_key: &str,
    ) -> Option<&CloudflareRouterQuotaReservationV1> {
        self.quota_reservations.get(storage_key)
    }

    /// Reads a Wallet Session budget grant for tests and local smoke checks.
    pub fn wallet_budget_grant(
        &self,
        storage_key: &str,
    ) -> Option<&CloudflareRouterWalletBudgetGrantRecordV1> {
        self.wallet_budget_grants.get(storage_key)
    }

    /// Reads a stored ECDSA presignature for tests and local smoke checks.
    pub fn signing_worker_ecdsa_presignature(
        &self,
        storage_key: &str,
    ) -> Option<&CloudflareSigningWorkerEcdsaPresignatureRecordV1> {
        self.signing_worker_ecdsa_presignature_records
            .get(storage_key)
    }

    /// Reads a stored unbound Ed25519 presign-pool record for tests and local checks.
    pub fn signing_worker_ed25519_presign_pool(
        &self,
        storage_key: &str,
    ) -> Option<&CloudflareSigningWorkerEd25519PresignPoolRecordV1> {
        self.signing_worker_ed25519_presign_pool_records
            .get(storage_key)
    }

    /// Reads a stored unbound ECDSA presignature pool record for tests and local smoke checks.
    pub fn signing_worker_ecdsa_presignature_pool(
        &self,
        storage_key: &str,
    ) -> Option<&CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1> {
        self.signing_worker_ecdsa_presignature_pool_records
            .get(storage_key)
    }
}

impl CloudflareDurableObjectStorageV1 for CloudflareDurableObjectMemoryStorageV1 {
    fn root_share_startup_metadata(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareRootShareStartupMetadataV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.root_share_metadata.get(storage_key).cloned())
    }

    fn put_root_share_startup_metadata(
        &mut self,
        storage_key: &str,
        metadata: CloudflareRootShareStartupMetadataV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("storage_key", storage_key)?;
        metadata.validate()?;
        self.root_share_metadata
            .insert(storage_key.to_owned(), metadata);
        Ok(())
    }

    fn replay_reservation_by_request_id(
        &self,
        request_index_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareReplayReserveRequestV1>> {
        require_non_empty("request_index_key", request_index_key)?;
        Ok(self.replay_by_request_id.get(request_index_key).cloned())
    }

    fn put_replay_reservation(
        &mut self,
        request_index_key: &str,
        storage_key: &str,
        request: CloudflareReplayReserveRequestV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("request_index_key", request_index_key)?;
        require_non_empty("storage_key", storage_key)?;
        request.validate()?;
        self.replay_by_request_id
            .insert(request_index_key.to_owned(), request.clone());
        self.replay_by_storage_key
            .insert(storage_key.to_owned(), request);
        Ok(())
    }

    fn cleanup_expired_replay_reservations(
        &mut self,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareExpiredStateCleanupReportV1> {
        require_positive_ms("cleanup now_unix_ms", now_unix_ms)?;
        let storage_before = self.replay_by_storage_key.len();
        self.replay_by_storage_key
            .retain(|_, request| request.expires_at_ms > now_unix_ms);
        let index_before = self.replay_by_request_id.len();
        self.replay_by_request_id
            .retain(|_, request| request.expires_at_ms > now_unix_ms);
        CloudflareExpiredStateCleanupReportV1::new(
            now_unix_ms,
            (storage_before - self.replay_by_storage_key.len()) as u64,
            (index_before - self.replay_by_request_id.len()) as u64,
        )
    }

    fn put_router_lifecycle_state(
        &mut self,
        storage_key: &str,
        state: RouterAbLifecycleStateV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("storage_key", storage_key)?;
        validate_lifecycle_state(&state)?;
        self.lifecycle_states.insert(storage_key.to_owned(), state);
        Ok(())
    }

    fn router_lifecycle_state(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<RouterAbLifecycleStateV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.lifecycle_states.get(storage_key).cloned())
    }

    fn put_derivation_ceremony(
        &mut self,
        storage_key: &str,
        ceremony: CloudflareDerivationCeremonyV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("storage_key", storage_key)?;
        ceremony.validate()?;
        self.derivation_ceremonies
            .insert(storage_key.to_owned(), ceremony);
        Ok(())
    }

    fn derivation_ceremony(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareDerivationCeremonyV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.derivation_ceremonies.get(storage_key).cloned())
    }

    fn router_project_policy(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareRouterProjectPolicyRecordV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.project_policies.get(storage_key).cloned())
    }

    fn router_abuse(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareRouterAbuseRecordV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.abuse_records.get(storage_key).cloned())
    }

    fn router_quota(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareRouterQuotaReservationV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.quota_reservations.get(storage_key).cloned())
    }

    fn put_router_quota(
        &mut self,
        storage_key: &str,
        reservation: CloudflareRouterQuotaReservationV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("storage_key", storage_key)?;
        reservation.validate()?;
        self.quota_reservations
            .insert(storage_key.to_owned(), reservation);
        Ok(())
    }

    fn router_wallet_budget(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareRouterWalletBudgetGrantRecordV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.wallet_budget_grants.get(storage_key).cloned())
    }

    fn put_router_wallet_budget(
        &mut self,
        storage_key: &str,
        record: CloudflareRouterWalletBudgetGrantRecordV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("storage_key", storage_key)?;
        record.validate()?;
        self.wallet_budget_grants
            .insert(storage_key.to_owned(), record);
        Ok(())
    }

    fn cleanup_expired_router_quota_reservations(
        &mut self,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareExpiredStateCleanupReportV1> {
        require_positive_ms("cleanup now_unix_ms", now_unix_ms)?;
        let before = self.quota_reservations.len();
        self.quota_reservations
            .retain(|_, reservation| reservation.is_active_at(now_unix_ms));
        CloudflareExpiredStateCleanupReportV1::new(
            now_unix_ms,
            (before - self.quota_reservations.len()) as u64,
            0,
        )
    }

    fn signing_worker_output_activation(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerOutputActivationRecordV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.signing_worker_activations.get(storage_key).cloned())
    }

    fn put_signing_worker_output_activation(
        &mut self,
        storage_key: &str,
        active_state_index_key: &str,
        record: CloudflareSigningWorkerOutputActivationRecordV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("storage_key", storage_key)?;
        require_non_empty("active_state_index_key", active_state_index_key)?;
        record.validate()?;
        self.active_signing_worker_states.insert(
            active_state_index_key.to_owned(),
            record.active_signing_worker_state.clone(),
        );
        self.signing_worker_activations
            .insert(storage_key.to_owned(), record);
        Ok(())
    }

    fn signing_worker_direct_activation(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<
        Option<CloudflareSigningWorkerDirectRecipientProofBundleActivationPendingRecordV1>,
    > {
        require_non_empty("storage_key", storage_key)?;
        Ok(self
            .signing_worker_direct_activations
            .get(storage_key)
            .cloned())
    }

    fn put_signing_worker_direct_activation(
        &mut self,
        storage_key: &str,
        record: CloudflareSigningWorkerDirectRecipientProofBundleActivationPendingRecordV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("storage_key", storage_key)?;
        record.validate()?;
        self.signing_worker_direct_activations
            .insert(storage_key.to_owned(), record);
        Ok(())
    }

    fn active_signing_worker_state(
        &self,
        active_state_index_key: &str,
    ) -> RouterAbProtocolResult<Option<ActiveSigningWorkerStateV1>> {
        require_non_empty("active_state_index_key", active_state_index_key)?;
        Ok(self
            .active_signing_worker_states
            .get(active_state_index_key)
            .cloned())
    }

    fn signing_worker_round1(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerRound1RecordV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.signing_worker_round1_records.get(storage_key).cloned())
    }

    fn put_signing_worker_round1(
        &mut self,
        storage_key: &str,
        record: CloudflareSigningWorkerRound1RecordV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("storage_key", storage_key)?;
        record.validate()?;
        self.signing_worker_round1_records
            .insert(storage_key.to_owned(), record);
        Ok(())
    }

    fn take_signing_worker_round1(
        &mut self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerRound1RecordV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.signing_worker_round1_records.remove(storage_key))
    }

    fn cleanup_expired_signing_worker_round1_records(
        &mut self,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareExpiredStateCleanupReportV1> {
        require_positive_ms("cleanup now_unix_ms", now_unix_ms)?;
        let before = self.signing_worker_round1_records.len();
        self.signing_worker_round1_records
            .retain(|_, record| record.expires_at_ms > now_unix_ms);
        CloudflareExpiredStateCleanupReportV1::new(
            now_unix_ms,
            (before - self.signing_worker_round1_records.len()) as u64,
            0,
        )
    }

    fn signing_worker_ed25519_presign_pool(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerEd25519PresignPoolRecordV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self
            .signing_worker_ed25519_presign_pool_records
            .get(storage_key)
            .cloned())
    }

    fn put_signing_worker_ed25519_presign_pool(
        &mut self,
        storage_key: &str,
        record: CloudflareSigningWorkerEd25519PresignPoolRecordV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("storage_key", storage_key)?;
        record.validate()?;
        self.signing_worker_ed25519_presign_pool_records
            .insert(storage_key.to_owned(), record);
        Ok(())
    }

    fn take_signing_worker_ed25519_presign_pool(
        &mut self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerEd25519PresignPoolRecordV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self
            .signing_worker_ed25519_presign_pool_records
            .remove(storage_key))
    }

    fn cleanup_expired_signing_worker_ed25519_presign_pool_records(
        &mut self,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareExpiredStateCleanupReportV1> {
        require_positive_ms("cleanup now_unix_ms", now_unix_ms)?;
        let before = self.signing_worker_ed25519_presign_pool_records.len();
        self.signing_worker_ed25519_presign_pool_records
            .retain(|_, record| record.expires_at_ms > now_unix_ms);
        CloudflareExpiredStateCleanupReportV1::new(
            now_unix_ms,
            (before - self.signing_worker_ed25519_presign_pool_records.len()) as u64,
            0,
        )
    }

    fn signing_worker_ecdsa_presignature(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerEcdsaPresignatureRecordV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self
            .signing_worker_ecdsa_presignature_records
            .get(storage_key)
            .cloned())
    }

    fn put_signing_worker_ecdsa_presignature(
        &mut self,
        storage_key: &str,
        record: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("storage_key", storage_key)?;
        record.validate()?;
        self.signing_worker_ecdsa_presignature_records
            .insert(storage_key.to_owned(), record);
        Ok(())
    }

    fn take_signing_worker_ecdsa_presignature(
        &mut self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerEcdsaPresignatureRecordV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self
            .signing_worker_ecdsa_presignature_records
            .remove(storage_key))
    }

    fn cleanup_expired_signing_worker_ecdsa_presignature_records(
        &mut self,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareExpiredStateCleanupReportV1> {
        require_positive_ms("cleanup now_unix_ms", now_unix_ms)?;
        let before = self.signing_worker_ecdsa_presignature_records.len();
        self.signing_worker_ecdsa_presignature_records
            .retain(|_, record| record.expires_at_ms > now_unix_ms);
        CloudflareExpiredStateCleanupReportV1::new(
            now_unix_ms,
            (before - self.signing_worker_ecdsa_presignature_records.len()) as u64,
            0,
        )
    }

    fn signing_worker_ecdsa_presignature_pool(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self
            .signing_worker_ecdsa_presignature_pool_records
            .get(storage_key)
            .cloned())
    }

    fn put_signing_worker_ecdsa_presignature_pool(
        &mut self,
        storage_key: &str,
        record: CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("storage_key", storage_key)?;
        record.validate()?;
        self.signing_worker_ecdsa_presignature_pool_records
            .insert(storage_key.to_owned(), record);
        Ok(())
    }

    fn take_signing_worker_ecdsa_presignature_pool(
        &mut self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self
            .signing_worker_ecdsa_presignature_pool_records
            .remove(storage_key))
    }

    fn cleanup_expired_signing_worker_ecdsa_presignature_pool_records(
        &mut self,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareExpiredStateCleanupReportV1> {
        require_positive_ms("cleanup now_unix_ms", now_unix_ms)?;
        let before = self.signing_worker_ecdsa_presignature_pool_records.len();
        self.signing_worker_ecdsa_presignature_pool_records
            .retain(|_, record| record.expires_at_ms > now_unix_ms);
        CloudflareExpiredStateCleanupReportV1::new(
            now_unix_ms,
            (before - self.signing_worker_ecdsa_presignature_pool_records.len()) as u64,
            0,
        )
    }
}
