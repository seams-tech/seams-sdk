#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerEvalOperation {
    RegistrationBootstrap,
    SessionBootstrap,
    NonExportSign,
    ExplicitKeyExport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowedOutputKind {
    ThresholdMaterialOnly,
    ThresholdMaterialAndRelayerExportShare,
}

impl ServerEvalOperation {
    pub fn allowed_output_kind(self) -> AllowedOutputKind {
        match self {
            ServerEvalOperation::ExplicitKeyExport => {
                AllowedOutputKind::ThresholdMaterialAndRelayerExportShare
            }
            ServerEvalOperation::RegistrationBootstrap
            | ServerEvalOperation::SessionBootstrap
            | ServerEvalOperation::NonExportSign => AllowedOutputKind::ThresholdMaterialOnly,
        }
    }
}
