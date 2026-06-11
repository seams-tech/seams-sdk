use crate::client::{ClientDriverState, OutputOpeners};
use crate::protocol::report::runtime_output_openers;
use crate::protocol::PreparedSession;
use crate::runtime::{SharedRuntime, SharedRuntimeState};
use crate::server::ServerDriverState;
use crate::shared::CanonicalContext;
use crate::wire::{
    ArtifactSummary, DeliveryMaterial, HiddenCoreMaterialization,
    PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION,
};

impl PreparedSession {
    pub fn artifact_summary(&self) -> ArtifactSummary {
        crate::runtime::shared::build_artifact_summary(self.candidate(), self.artifact())
    }

    pub fn prepared_context(&self) -> CanonicalContext {
        CanonicalContext {
            org_id: self.candidate().context_descriptor.org_id.clone(),
            account_id: self.candidate().context_descriptor.account_id.clone(),
            key_purpose: self.candidate().context_descriptor.key_purpose.clone(),
            key_version: self.candidate().context_descriptor.key_version.clone(),
            participant_ids: self.candidate().context_descriptor.participant_ids.clone(),
            derivation_version: self.candidate().context_descriptor.derivation_version,
        }
    }

    pub fn delivery_material(&self) -> DeliveryMaterial {
        DeliveryMaterial {
            report_version: PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION.to_string(),
            backend_version: self.ddh_backend().evaluation_key().backend_version,
            fixed_function_id: self.candidate().fixed_function_id.clone(),
            projection_mode: self.output_projection_mode().clone(),
            hidden_core_materialization: HiddenCoreMaterialization::DdhPrimitiveBaseline,
            artifact: self.artifact_summary(),
            evaluation_key: self.ddh_backend().evaluation_key().clone(),
        }
    }

    pub fn shared_runtime_state(&self) -> SharedRuntimeState {
        SharedRuntimeState {
            prepared_context: self.prepared_context(),
            projection_mode: self.output_projection_mode().clone(),
        }
    }

    pub fn garbler_driver_state(&self) -> ServerDriverState {
        let garbler_session = self.garbler_session();
        ServerDriverState {
            runtime: self.shared_runtime_state(),
            garbler_session: crate::server::ServerSessionState {
                backend_version: garbler_session.ddh_garbler.evaluation_key().backend_version,
                context_binding: garbler_session.context_binding,
                ddh_garbler: garbler_session.ddh_garbler,
                client_ot_offer: garbler_session.client_ot_offer,
                garbler_ot_state: garbler_session.garbler_ot_state,
            },
        }
    }

    pub fn evaluator_driver_state(&self) -> ClientDriverState {
        let evaluator_session = self.evaluator_session();
        ClientDriverState {
            runtime: self.shared_runtime_state(),
            evaluator_session: crate::client::ClientSessionState {
                backend_version: evaluator_session
                    .ddh_evaluator
                    .evaluation_key()
                    .backend_version,
                context_binding: evaluator_session.context_binding,
                ddh_evaluator: evaluator_session.ddh_evaluator,
            },
        }
    }

    pub fn split_runtime(
        &self,
    ) -> (
        SharedRuntime,
        crate::server::ServerSession,
        crate::client::ClientSession,
    ) {
        (
            self.shared_runtime(),
            self.garbler_session(),
            self.evaluator_session(),
        )
    }

    pub fn output_openers(&self) -> OutputOpeners {
        runtime_output_openers(&self.garbler_session(), &self.evaluator_session())
    }
}
