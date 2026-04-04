use serde::{Deserialize, Serialize};

use crate::client::{ClientDriverState, ClientSession, ClientSessionState};
use crate::protocol::PreparedSession;
use crate::runtime::{SharedRuntime, SharedRuntimeState};
use crate::shared::ProtoResult;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRuntimeState {
    pub runtime: SharedRuntimeState,
    pub evaluator_session: ClientSessionState,
}

#[derive(Clone)]
pub struct ClientRuntime {
    pub shared_runtime: SharedRuntime,
    pub evaluator_session: ClientSession,
}

impl ClientRuntimeState {
    pub fn materialize(&self) -> ProtoResult<ClientRuntime> {
        Ok(ClientRuntime {
            shared_runtime: self.runtime.materialize()?,
            evaluator_session: self.evaluator_session.materialize(),
        })
    }
}

impl ClientRuntime {
    pub fn from_driver_state(driver_state: &ClientDriverState) -> ProtoResult<Self> {
        Ok(Self {
            shared_runtime: driver_state.runtime.materialize()?,
            evaluator_session: driver_state.evaluator_session.materialize(),
        })
    }
}

impl From<ClientDriverState> for ClientRuntimeState {
    fn from(value: ClientDriverState) -> Self {
        Self {
            runtime: value.runtime,
            evaluator_session: value.evaluator_session,
        }
    }
}

impl PreparedSession {
    pub fn client_runtime_state(&self) -> ClientRuntimeState {
        self.evaluator_driver_state().into()
    }
}
