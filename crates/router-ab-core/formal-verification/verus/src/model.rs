use vstd::prelude::*;

verus! {
    pub enum RoleModel {
        Router,
        DeriverA,
        DeriverB,
        Client,
        SigningWorker,
    }

    pub enum OpenedValueKindModel {
        XClientBase,
        XRelayerBase,
    }

    pub enum MpcPrfPartialOwnerModel {
        DeriverA,
        DeriverB,
    }

    pub enum ForbiddenJoinedStateModel {
        JoinedD,
        JoinedA,
        JoinedXClientBase,
        JoinedYRelayer,
        JoinedTauRelayer,
    }

    pub enum RoleViewEventModel {
        PublicMetadata,
        Ciphertext,
        DeriverAMpcPrfPartialXClientBase,
        DeriverAMpcPrfPartialXRelayerBase,
        DeriverBMpcPrfPartialXClientBase,
        DeriverBMpcPrfPartialXRelayerBase,
        ClientOpenedXClientBase,
        SigningWorkerOpenedXRelayerBase,
        JoinedD,
        JoinedA,
        JoinedXClientBase,
        JoinedYRelayer,
        JoinedTauRelayer,
    }

    pub open spec fn role_may_open(role: RoleModel, opened: OpenedValueKindModel) -> bool {
        match (role, opened) {
            (RoleModel::Client, OpenedValueKindModel::XClientBase) => true,
            (RoleModel::SigningWorker, OpenedValueKindModel::XRelayerBase) => true,
            _ => false,
        }
    }

    pub open spec fn role_may_observe_mpc_prf_partial(
        role: RoleModel,
        owner: MpcPrfPartialOwnerModel,
        opened: OpenedValueKindModel,
    ) -> bool {
        match (role, owner, opened) {
            (RoleModel::DeriverA, MpcPrfPartialOwnerModel::DeriverA, _) => true,
            (RoleModel::DeriverB, MpcPrfPartialOwnerModel::DeriverB, _) => true,
            (RoleModel::Client, _, OpenedValueKindModel::XClientBase) => true,
            (RoleModel::SigningWorker, _, OpenedValueKindModel::XRelayerBase) => true,
            _ => false,
        }
    }

    pub open spec fn event_contains_forbidden_joined_state(
        event: RoleViewEventModel,
        state: ForbiddenJoinedStateModel,
    ) -> bool {
        match (event, state) {
            (RoleViewEventModel::JoinedD, ForbiddenJoinedStateModel::JoinedD) => true,
            (RoleViewEventModel::JoinedA, ForbiddenJoinedStateModel::JoinedA) => true,
            (
                RoleViewEventModel::JoinedXClientBase,
                ForbiddenJoinedStateModel::JoinedXClientBase,
            ) => true,
            (
                RoleViewEventModel::JoinedYRelayer,
                ForbiddenJoinedStateModel::JoinedYRelayer,
            ) => true,
            (
                RoleViewEventModel::JoinedTauRelayer,
                ForbiddenJoinedStateModel::JoinedTauRelayer,
            ) => true,
            _ => false,
        }
    }

    pub open spec fn role_may_observe_event(
        role: RoleModel,
        event: RoleViewEventModel,
    ) -> bool {
        match (role, event) {
            (_, RoleViewEventModel::PublicMetadata) => true,
            (_, RoleViewEventModel::Ciphertext) => true,
            (RoleModel::DeriverA, RoleViewEventModel::DeriverAMpcPrfPartialXClientBase) => true,
            (RoleModel::DeriverA, RoleViewEventModel::DeriverAMpcPrfPartialXRelayerBase) => true,
            (RoleModel::DeriverB, RoleViewEventModel::DeriverBMpcPrfPartialXClientBase) => true,
            (RoleModel::DeriverB, RoleViewEventModel::DeriverBMpcPrfPartialXRelayerBase) => true,
            (RoleModel::Client, RoleViewEventModel::ClientOpenedXClientBase) => true,
            (
                RoleModel::SigningWorker,
                RoleViewEventModel::SigningWorkerOpenedXRelayerBase,
            ) => true,
            _ => false,
        }
    }

    pub open spec fn single_role_view_contains_forbidden_joined_state(
        role: RoleModel,
        state: ForbiddenJoinedStateModel,
        event: RoleViewEventModel,
    ) -> bool {
        role_may_observe_event(role, event) && event_contains_forbidden_joined_state(event, state)
    }

    proof fn client_opens_only_x_client_base(opened: OpenedValueKindModel)
        requires role_may_open(RoleModel::Client, opened)
        ensures opened == OpenedValueKindModel::XClientBase
    {
    }

    proof fn signing_worker_opens_only_x_relayer_base(opened: OpenedValueKindModel)
        requires role_may_open(RoleModel::SigningWorker, opened)
        ensures opened == OpenedValueKindModel::XRelayerBase
    {
    }

    proof fn router_observes_no_mpc_prf_plaintext_partial(
        owner: MpcPrfPartialOwnerModel,
        opened: OpenedValueKindModel,
    )
        ensures !role_may_observe_mpc_prf_partial(RoleModel::Router, owner, opened)
    {
    }

    proof fn client_observes_only_x_client_base_partials(
        owner: MpcPrfPartialOwnerModel,
        opened: OpenedValueKindModel,
    )
        requires role_may_observe_mpc_prf_partial(RoleModel::Client, owner, opened)
        ensures opened == OpenedValueKindModel::XClientBase
    {
    }

    proof fn signing_worker_observes_only_x_relayer_base_partials(
        owner: MpcPrfPartialOwnerModel,
        opened: OpenedValueKindModel,
    )
        requires role_may_observe_mpc_prf_partial(RoleModel::SigningWorker, owner, opened)
        ensures opened == OpenedValueKindModel::XRelayerBase
    {
    }

    proof fn forbidden_joined_state_events_are_unobservable(
        role: RoleModel,
        state: ForbiddenJoinedStateModel,
        event: RoleViewEventModel,
    )
        requires event_contains_forbidden_joined_state(event, state)
        ensures !role_may_observe_event(role, event)
    {
    }

    proof fn server_side_role_event_excludes_forbidden_joined_state(
        role: RoleModel,
        state: ForbiddenJoinedStateModel,
        event: RoleViewEventModel,
    )
        requires
            role == RoleModel::Router || role == RoleModel::DeriverA ||
                role == RoleModel::DeriverB || role == RoleModel::SigningWorker
        ensures !single_role_view_contains_forbidden_joined_state(role, state, event)
    {
    }

    proof fn client_view_excludes_forbidden_joined_material(
        state: ForbiddenJoinedStateModel,
        event: RoleViewEventModel,
    )
        requires
            state == ForbiddenJoinedStateModel::JoinedD ||
                state == ForbiddenJoinedStateModel::JoinedA ||
            state == ForbiddenJoinedStateModel::JoinedYRelayer ||
                state == ForbiddenJoinedStateModel::JoinedTauRelayer
        ensures !single_role_view_contains_forbidden_joined_state(RoleModel::Client, state, event)
    {
    }
}
