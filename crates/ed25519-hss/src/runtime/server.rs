use serde::{Deserialize, Serialize};

use crate::protocol::PreparedSession;
use crate::runtime::{SharedRuntime, SharedRuntimeState};
use crate::server::{ServerDriverState, ServerSession, ServerSessionState};
use crate::shared::ProtoResult;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerRuntimeState {
    pub runtime: SharedRuntimeState,
    pub garbler_session: ServerSessionState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerRuntime {
    pub shared_runtime: SharedRuntime,
    pub garbler_session: ServerSession,
}

impl ServerRuntimeState {
    pub fn materialize(&self) -> ProtoResult<ServerRuntime> {
        Ok(ServerRuntime {
            shared_runtime: self.runtime.materialize()?,
            garbler_session: self.garbler_session.materialize()?,
        })
    }
}

impl ServerRuntime {
    pub fn from_driver_state(driver_state: &ServerDriverState) -> ProtoResult<Self> {
        Ok(Self {
            shared_runtime: driver_state.runtime.materialize()?,
            garbler_session: driver_state.garbler_session.materialize()?,
        })
    }
}

impl From<ServerDriverState> for ServerRuntimeState {
    fn from(value: ServerDriverState) -> Self {
        Self {
            runtime: value.runtime,
            garbler_session: value.garbler_session,
        }
    }
}

impl PreparedSession {
    pub fn server_runtime_state(&self) -> ServerRuntimeState {
        self.garbler_driver_state().into()
    }
}
