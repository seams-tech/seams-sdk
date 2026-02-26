From Coq Require Import ZArith Lia.

Open Scope Z_scope.

(* Starter theorem to keep CI wired while protocol-specific proofs are added. *)
Theorem z_add_sub_cancel : forall a b : Z, a + b - b = a.
Proof.
  intros a b.
  lia.
Qed.
