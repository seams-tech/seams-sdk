use vstd::prelude::*;

verus! {
    pub enum RoleModel {
        Router,
        SignerA,
        SignerB,
        Client,
        Relayer,
    }

    pub enum OpenedValueKindModel {
        XClientBase,
        XRelayerBase,
    }

    pub enum MpcPrfPartialOwnerModel {
        SignerA,
        SignerB,
    }

    pub enum SplitRootShareOwnerModel {
        SignerA,
        SignerB,
    }

    pub enum ForbiddenJoinedStateModel {
        JoinedD,
        JoinedA,
        JoinedXClientBase,
        JoinedYRelayer,
        JoinedTauRelayer,
    }

    pub open spec fn role_may_open(role: RoleModel, opened: OpenedValueKindModel) -> bool {
        match (role, opened) {
            (RoleModel::Client, OpenedValueKindModel::XClientBase) => true,
            (RoleModel::Relayer, OpenedValueKindModel::XRelayerBase) => true,
            _ => false,
        }
    }

    pub open spec fn role_may_observe_mpc_prf_partial(
        role: RoleModel,
        owner: MpcPrfPartialOwnerModel,
        opened: OpenedValueKindModel,
    ) -> bool {
        match (role, owner, opened) {
            (RoleModel::SignerA, MpcPrfPartialOwnerModel::SignerA, _) => true,
            (RoleModel::SignerB, MpcPrfPartialOwnerModel::SignerB, _) => true,
            (RoleModel::Client, _, OpenedValueKindModel::XClientBase) => true,
            (RoleModel::Relayer, _, OpenedValueKindModel::XRelayerBase) => true,
            _ => false,
        }
    }

    pub open spec fn role_may_observe_split_root_output_share(
        role: RoleModel,
        owner: SplitRootShareOwnerModel,
        opened: OpenedValueKindModel,
    ) -> bool {
        match (role, owner, opened) {
            (RoleModel::SignerA, SplitRootShareOwnerModel::SignerA, _) => true,
            (RoleModel::SignerB, SplitRootShareOwnerModel::SignerB, _) => true,
            (RoleModel::Client, _, OpenedValueKindModel::XClientBase) => true,
            (RoleModel::Relayer, _, OpenedValueKindModel::XRelayerBase) => true,
            _ => false,
        }
    }

    pub open spec fn role_may_observe_split_root_secret(
        role: RoleModel,
        owner: SplitRootShareOwnerModel,
    ) -> bool {
        match (role, owner) {
            (RoleModel::SignerA, SplitRootShareOwnerModel::SignerA) => true,
            (RoleModel::SignerB, SplitRootShareOwnerModel::SignerB) => true,
            _ => false,
        }
    }

    pub open spec fn single_role_view_contains_forbidden_joined_state(
        role: RoleModel,
        state: ForbiddenJoinedStateModel,
    ) -> bool {
        match (role, state) {
            (RoleModel::Client, ForbiddenJoinedStateModel::JoinedYRelayer) => false,
            (RoleModel::Client, ForbiddenJoinedStateModel::JoinedTauRelayer) => false,
            (RoleModel::Router, _) => false,
            (RoleModel::SignerA, _) => false,
            (RoleModel::SignerB, _) => false,
            (RoleModel::Relayer, ForbiddenJoinedStateModel::JoinedD) => false,
            (RoleModel::Relayer, ForbiddenJoinedStateModel::JoinedA) => false,
            (RoleModel::Relayer, ForbiddenJoinedStateModel::JoinedXClientBase) => false,
            _ => false,
        }
    }

    proof fn client_opens_only_x_client_base(opened: OpenedValueKindModel)
        requires role_may_open(RoleModel::Client, opened)
        ensures opened == OpenedValueKindModel::XClientBase
    {
    }

    proof fn relayer_opens_only_x_relayer_base(opened: OpenedValueKindModel)
        requires role_may_open(RoleModel::Relayer, opened)
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

    proof fn relayer_observes_only_x_relayer_base_partials(
        owner: MpcPrfPartialOwnerModel,
        opened: OpenedValueKindModel,
    )
        requires role_may_observe_mpc_prf_partial(RoleModel::Relayer, owner, opened)
        ensures opened == OpenedValueKindModel::XRelayerBase
    {
    }

    proof fn router_observes_no_split_root_secret(owner: SplitRootShareOwnerModel)
        ensures !role_may_observe_split_root_secret(RoleModel::Router, owner)
    {
    }

    proof fn router_observes_no_split_root_plaintext_output_share(
        owner: SplitRootShareOwnerModel,
        opened: OpenedValueKindModel,
    )
        ensures !role_may_observe_split_root_output_share(RoleModel::Router, owner, opened)
    {
    }

    proof fn client_observes_only_x_client_base_split_root_shares(
        owner: SplitRootShareOwnerModel,
        opened: OpenedValueKindModel,
    )
        requires role_may_observe_split_root_output_share(RoleModel::Client, owner, opened)
        ensures opened == OpenedValueKindModel::XClientBase
    {
    }

    proof fn relayer_observes_only_x_relayer_base_split_root_shares(
        owner: SplitRootShareOwnerModel,
        opened: OpenedValueKindModel,
    )
        requires role_may_observe_split_root_output_share(RoleModel::Relayer, owner, opened)
        ensures opened == OpenedValueKindModel::XRelayerBase
    {
    }
}
