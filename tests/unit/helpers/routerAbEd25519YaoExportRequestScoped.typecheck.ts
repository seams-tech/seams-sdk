import type {
  RouterAbEd25519YaoExportAdmissionClaimV1,
  RouterAbEd25519YaoExportAdmissionCommitInputV1,
  RouterAbEd25519YaoExportAuthorizationClaimV1,
  RouterAbEd25519YaoExportAuthorizationCommitInputV1,
  RouterAbEd25519YaoExportExecuteClaimV1,
  RouterAbEd25519YaoExportExecuteCommitInputV1,
} from '../../../packages/wallet-server/src/router/domains/ed25519Yao/export/routerAbEd25519YaoExport';

type AssertNever<T extends never> = T;

export type ExportAdmissionUncertaintyCannotCommit = AssertNever<
  Extract<
    RouterAbEd25519YaoExportAdmissionCommitInputV1['outcome'],
    { readonly kind: 'backend_uncertain' }
  >
>;

export type ExportExecutionUncertaintyCannotCommit = AssertNever<
  Extract<
    RouterAbEd25519YaoExportExecuteCommitInputV1['outcome'],
    { readonly kind: 'backend_uncertain' }
  >
>;

declare const authorizationClaim: RouterAbEd25519YaoExportAuthorizationClaimV1;
declare const admissionClaim: RouterAbEd25519YaoExportAdmissionClaimV1;
declare const executionClaim: RouterAbEd25519YaoExportExecuteClaimV1;

declare function acceptAuthorizationClaim(
  claim: RouterAbEd25519YaoExportAuthorizationCommitInputV1['claim'],
): void;
declare function acceptAdmissionClaim(
  claim: RouterAbEd25519YaoExportAdmissionCommitInputV1['claim'],
): void;
declare function acceptExecutionClaim(
  claim: RouterAbEd25519YaoExportExecuteCommitInputV1['claim'],
): void;

acceptAuthorizationClaim(authorizationClaim);
acceptAdmissionClaim(admissionClaim);
acceptExecutionClaim(executionClaim);

// @ts-expect-error authorization claims cannot complete Router admission
acceptAdmissionClaim(authorizationClaim);
// @ts-expect-error admission claims cannot complete export execution
acceptExecutionClaim(admissionClaim);
// @ts-expect-error execution claims cannot commit WebAuthn authorization
acceptAuthorizationClaim(executionClaim);
