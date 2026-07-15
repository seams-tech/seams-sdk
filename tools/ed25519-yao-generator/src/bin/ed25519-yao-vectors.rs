use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_yao_generator::{
    canonical_activation_delivery_vector_corpus_json_bytes_v1,
    canonical_activation_delivery_vector_corpus_v1,
    canonical_activation_recipient_party_view_vector_corpus_json_bytes_v1,
    canonical_activation_recipient_party_view_vector_corpus_v1,
    canonical_ceremony_context_vector_corpus_v1,
    canonical_evaluation_input_party_view_vector_corpus_json_bytes_v1,
    canonical_evaluation_input_party_view_vector_corpus_v1,
    canonical_evaluator_abort_view_vector_corpus_json_bytes_v1,
    canonical_evaluator_abort_view_vector_corpus_v1,
    canonical_export_delivery_vector_corpus_json_bytes_v1,
    canonical_export_delivery_vector_corpus_v1,
    canonical_export_evaluator_authorization_vector_corpus_json_bytes_v1,
    canonical_export_evaluator_authorization_vector_corpus_v1, canonical_kdf_vector_corpus_v1,
    canonical_lifecycle_continuity_corpus_v1,
    canonical_output_party_view_vector_corpus_json_bytes_v1,
    canonical_output_party_view_vector_corpus_v1,
    canonical_output_sharing_vector_corpus_json_bytes_v1,
    canonical_output_sharing_vector_corpus_v1,
    canonical_phase2b_core_reconciliation_corpus_json_bytes_v1,
    canonical_phase2b_core_reconciliation_corpus_v1, canonical_provenance_vector_corpus_v1,
    canonical_recovery_credential_transition_vector_corpus_json_bytes_v1,
    canonical_recovery_credential_transition_vector_corpus_v1,
    canonical_recovery_evaluator_admission_vector_corpus_json_bytes_v1,
    canonical_recovery_evaluator_admission_vector_corpus_v1,
    canonical_refresh_evaluator_admission_vector_corpus_json_bytes_v1,
    canonical_refresh_evaluator_admission_vector_corpus_v1,
    canonical_registration_evaluator_admission_vector_corpus_json_bytes_v1,
    canonical_registration_evaluator_admission_vector_corpus_v1,
    canonical_semantic_frame_party_view_vector_corpus_json_bytes_v1,
    canonical_semantic_frame_party_view_vector_corpus_v1,
    canonical_semantic_lifecycle_vector_corpus_json_bytes_v1,
    canonical_semantic_lifecycle_vector_corpus_v1,
    canonical_uniform_abort_vector_corpus_json_bytes_v1, canonical_uniform_abort_vector_corpus_v1,
    canonical_vector_corpus_v1, differential_vector_corpus_v1,
    parse_canonical_activation_delivery_vector_corpus_json_v1,
    parse_canonical_activation_recipient_party_view_vector_corpus_json_v1,
    parse_canonical_evaluation_input_party_view_vector_corpus_json_v1,
    parse_canonical_evaluator_abort_view_vector_corpus_json_v1,
    parse_canonical_export_delivery_vector_corpus_json_v1,
    parse_canonical_export_evaluator_authorization_vector_corpus_json_v1,
    parse_canonical_output_party_view_vector_corpus_json_v1,
    parse_canonical_output_sharing_vector_corpus_json_v1,
    parse_canonical_phase2b_core_reconciliation_corpus_json_v1,
    parse_canonical_recovery_credential_transition_vector_corpus_json_v1,
    parse_canonical_recovery_evaluator_admission_vector_corpus_json_v1,
    parse_canonical_refresh_evaluator_admission_vector_corpus_json_v1,
    parse_canonical_registration_evaluator_admission_vector_corpus_json_v1,
    parse_canonical_semantic_frame_party_view_vector_corpus_json_v1,
    parse_canonical_semantic_lifecycle_vector_corpus_json_v1,
    parse_canonical_uniform_abort_vector_corpus_json_v1, CeremonyContextVectorCorpusV1,
    KdfVectorCorpusV1, LifecycleContinuityCorpusV1, ProvenanceVectorCorpusV1, VectorCorpusV1,
};
use serde::Serialize;

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

enum Command {
    Emit {
        output: PathBuf,
    },
    EmitDifferential {
        public_test_seed: [u8; 32],
        cases: usize,
        output: PathBuf,
    },
    EmitLifecycleContinuity {
        output: PathBuf,
    },
    EmitKdf {
        output: PathBuf,
    },
    EmitCeremonyContext {
        output: PathBuf,
    },
    EmitProvenance {
        output: PathBuf,
    },
    EmitOutputSharing {
        output: PathBuf,
    },
    EmitOutputPartyViews {
        output: PathBuf,
    },
    EmitExportDelivery {
        output: PathBuf,
    },
    EmitActivationDelivery {
        output: PathBuf,
    },
    EmitActivationRecipientPartyViews {
        output: PathBuf,
    },
    EmitEvaluationInputPartyViews {
        output: PathBuf,
    },
    EmitSemanticLifecycle {
        output: PathBuf,
    },
    EmitUniformAbort {
        output: PathBuf,
    },
    EmitEvaluatorAbortViews {
        output: PathBuf,
    },
    EmitRecoveryCredentialTransition {
        output: PathBuf,
    },
    EmitExportEvaluatorAuthorization {
        output: PathBuf,
    },
    EmitRegistrationEvaluatorAdmission {
        output: PathBuf,
    },
    EmitRecoveryEvaluatorAdmission {
        output: PathBuf,
    },
    EmitRefreshEvaluatorAdmission {
        output: PathBuf,
    },
    EmitSemanticFramePartyViews {
        output: PathBuf,
    },
    EmitPhase2bCoreReconciliation {
        output: PathBuf,
    },
    Check {
        input: PathBuf,
    },
    CheckKdf {
        input: PathBuf,
    },
    CheckCeremonyContext {
        input: PathBuf,
    },
    CheckProvenance {
        input: PathBuf,
    },
    CheckOutputSharing {
        input: PathBuf,
    },
    CheckOutputPartyViews {
        input: PathBuf,
    },
    CheckExportDelivery {
        input: PathBuf,
    },
    CheckActivationDelivery {
        input: PathBuf,
    },
    CheckActivationRecipientPartyViews {
        input: PathBuf,
    },
    CheckEvaluationInputPartyViews {
        input: PathBuf,
    },
    CheckSemanticLifecycle {
        input: PathBuf,
    },
    CheckUniformAbort {
        input: PathBuf,
    },
    CheckEvaluatorAbortViews {
        input: PathBuf,
    },
    CheckRecoveryCredentialTransition {
        input: PathBuf,
    },
    CheckExportEvaluatorAuthorization {
        input: PathBuf,
    },
    CheckRegistrationEvaluatorAdmission {
        input: PathBuf,
    },
    CheckRecoveryEvaluatorAdmission {
        input: PathBuf,
    },
    CheckRefreshEvaluatorAdmission {
        input: PathBuf,
    },
    CheckSemanticFramePartyViews {
        input: PathBuf,
    },
    CheckPhase2bCoreReconciliation {
        input: PathBuf,
    },
    CheckLifecycleContinuity {
        input: PathBuf,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ed25519-yao-vectors: {error}");
        std::process::exit(1);
    }
}

fn run() -> CliResult<()> {
    match parse_command()? {
        Command::Emit { output } => emit(&output),
        Command::EmitDifferential {
            public_test_seed,
            cases,
            output,
        } => emit_differential(public_test_seed, cases, &output),
        Command::EmitLifecycleContinuity { output } => emit_lifecycle_continuity(&output),
        Command::EmitKdf { output } => emit_kdf(&output),
        Command::EmitCeremonyContext { output } => emit_ceremony_context(&output),
        Command::EmitProvenance { output } => emit_provenance(&output),
        Command::EmitOutputSharing { output } => emit_output_sharing(&output),
        Command::EmitOutputPartyViews { output } => emit_output_party_views(&output),
        Command::EmitExportDelivery { output } => emit_export_delivery(&output),
        Command::EmitActivationDelivery { output } => emit_activation_delivery(&output),
        Command::EmitActivationRecipientPartyViews { output } => {
            emit_activation_recipient_party_views(&output)
        }
        Command::EmitEvaluationInputPartyViews { output } => {
            emit_evaluation_input_party_views(&output)
        }
        Command::EmitSemanticLifecycle { output } => emit_semantic_lifecycle(&output),
        Command::EmitUniformAbort { output } => emit_uniform_abort(&output),
        Command::EmitEvaluatorAbortViews { output } => emit_evaluator_abort_views(&output),
        Command::EmitRecoveryCredentialTransition { output } => {
            emit_recovery_credential_transition(&output)
        }
        Command::EmitExportEvaluatorAuthorization { output } => {
            emit_export_evaluator_authorization(&output)
        }
        Command::EmitRegistrationEvaluatorAdmission { output } => {
            emit_registration_evaluator_admission(&output)
        }
        Command::EmitRecoveryEvaluatorAdmission { output } => {
            emit_recovery_evaluator_admission(&output)
        }
        Command::EmitRefreshEvaluatorAdmission { output } => {
            emit_refresh_evaluator_admission(&output)
        }
        Command::EmitSemanticFramePartyViews { output } => emit_semantic_frame_party_views(&output),
        Command::EmitPhase2bCoreReconciliation { output } => {
            emit_phase2b_core_reconciliation(&output)
        }
        Command::Check { input } => check(&input),
        Command::CheckKdf { input } => check_kdf(&input),
        Command::CheckCeremonyContext { input } => check_ceremony_context(&input),
        Command::CheckProvenance { input } => check_provenance(&input),
        Command::CheckOutputSharing { input } => check_output_sharing(&input),
        Command::CheckOutputPartyViews { input } => check_output_party_views(&input),
        Command::CheckExportDelivery { input } => check_export_delivery(&input),
        Command::CheckActivationDelivery { input } => check_activation_delivery(&input),
        Command::CheckActivationRecipientPartyViews { input } => {
            check_activation_recipient_party_views(&input)
        }
        Command::CheckEvaluationInputPartyViews { input } => {
            check_evaluation_input_party_views(&input)
        }
        Command::CheckSemanticLifecycle { input } => check_semantic_lifecycle(&input),
        Command::CheckUniformAbort { input } => check_uniform_abort(&input),
        Command::CheckEvaluatorAbortViews { input } => check_evaluator_abort_views(&input),
        Command::CheckRecoveryCredentialTransition { input } => {
            check_recovery_credential_transition(&input)
        }
        Command::CheckExportEvaluatorAuthorization { input } => {
            check_export_evaluator_authorization(&input)
        }
        Command::CheckRegistrationEvaluatorAdmission { input } => {
            check_registration_evaluator_admission(&input)
        }
        Command::CheckRecoveryEvaluatorAdmission { input } => {
            check_recovery_evaluator_admission(&input)
        }
        Command::CheckRefreshEvaluatorAdmission { input } => {
            check_refresh_evaluator_admission(&input)
        }
        Command::CheckSemanticFramePartyViews { input } => check_semantic_frame_party_views(&input),
        Command::CheckPhase2bCoreReconciliation { input } => {
            check_phase2b_core_reconciliation(&input)
        }
        Command::CheckLifecycleContinuity { input } => check_lifecycle_continuity(&input),
    }
}

fn parse_command() -> CliResult<Command> {
    let arguments: Vec<_> = env::args().skip(1).collect();
    match arguments.as_slice() {
        [action, flag, path] if action == "emit" && flag == "--output" => Ok(Command::Emit {
            output: PathBuf::from(path),
        }),
        [action, flag, path] if action == "check" && flag == "--input" => Ok(Command::Check {
            input: PathBuf::from(path),
        }),
        [action, flag, path] if action == "emit-kdf" && flag == "--output" => {
            Ok(Command::EmitKdf {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "check-kdf" && flag == "--input" => {
            Ok(Command::CheckKdf {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "emit-ceremony-context" && flag == "--output" => {
            Ok(Command::EmitCeremonyContext {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "check-ceremony-context" && flag == "--input" => {
            Ok(Command::CheckCeremonyContext {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "emit-provenance" && flag == "--output" => {
            Ok(Command::EmitProvenance {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "check-provenance" && flag == "--input" => {
            Ok(Command::CheckProvenance {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "emit-output-sharing" && flag == "--output" => {
            Ok(Command::EmitOutputSharing {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "emit-output-party-views" && flag == "--output" => {
            Ok(Command::EmitOutputPartyViews {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "emit-export-delivery" && flag == "--output" => {
            Ok(Command::EmitExportDelivery {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "emit-activation-delivery" && flag == "--output" => {
            Ok(Command::EmitActivationDelivery {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path]
            if action == "emit-activation-recipient-party-views" && flag == "--output" =>
        {
            Ok(Command::EmitActivationRecipientPartyViews {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path]
            if action == "emit-evaluation-input-party-views" && flag == "--output" =>
        {
            Ok(Command::EmitEvaluationInputPartyViews {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "check-output-sharing" && flag == "--input" => {
            Ok(Command::CheckOutputSharing {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "check-output-party-views" && flag == "--input" => {
            Ok(Command::CheckOutputPartyViews {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "check-export-delivery" && flag == "--input" => {
            Ok(Command::CheckExportDelivery {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "check-activation-delivery" && flag == "--input" => {
            Ok(Command::CheckActivationDelivery {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path]
            if action == "check-activation-recipient-party-views" && flag == "--input" =>
        {
            Ok(Command::CheckActivationRecipientPartyViews {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path]
            if action == "check-evaluation-input-party-views" && flag == "--input" =>
        {
            Ok(Command::CheckEvaluationInputPartyViews {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "emit-semantic-lifecycle" && flag == "--output" => {
            Ok(Command::EmitSemanticLifecycle {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "check-semantic-lifecycle" && flag == "--input" => {
            Ok(Command::CheckSemanticLifecycle {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "emit-uniform-abort" && flag == "--output" => {
            Ok(Command::EmitUniformAbort {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "check-uniform-abort" && flag == "--input" => {
            Ok(Command::CheckUniformAbort {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "emit-evaluator-abort-views" && flag == "--output" => {
            Ok(Command::EmitEvaluatorAbortViews {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "check-evaluator-abort-views" && flag == "--input" => {
            Ok(Command::CheckEvaluatorAbortViews {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path]
            if action == "emit-recovery-credential-transition" && flag == "--output" =>
        {
            Ok(Command::EmitRecoveryCredentialTransition {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path]
            if action == "check-recovery-credential-transition" && flag == "--input" =>
        {
            Ok(Command::CheckRecoveryCredentialTransition {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path]
            if action == "emit-export-evaluator-authorization" && flag == "--output" =>
        {
            Ok(Command::EmitExportEvaluatorAuthorization {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path]
            if action == "check-export-evaluator-authorization" && flag == "--input" =>
        {
            Ok(Command::CheckExportEvaluatorAuthorization {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path]
            if action == "emit-registration-evaluator-admission" && flag == "--output" =>
        {
            Ok(Command::EmitRegistrationEvaluatorAdmission {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path]
            if action == "check-registration-evaluator-admission" && flag == "--input" =>
        {
            Ok(Command::CheckRegistrationEvaluatorAdmission {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path]
            if action == "emit-recovery-evaluator-admission" && flag == "--output" =>
        {
            Ok(Command::EmitRecoveryEvaluatorAdmission {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path]
            if action == "check-recovery-evaluator-admission" && flag == "--input" =>
        {
            Ok(Command::CheckRecoveryEvaluatorAdmission {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path]
            if action == "emit-refresh-evaluator-admission" && flag == "--output" =>
        {
            Ok(Command::EmitRefreshEvaluatorAdmission {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path]
            if action == "check-refresh-evaluator-admission" && flag == "--input" =>
        {
            Ok(Command::CheckRefreshEvaluatorAdmission {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path]
            if action == "emit-semantic-frame-party-views" && flag == "--output" =>
        {
            Ok(Command::EmitSemanticFramePartyViews {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path]
            if action == "check-semantic-frame-party-views" && flag == "--input" =>
        {
            Ok(Command::CheckSemanticFramePartyViews {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path]
            if action == "emit-phase2b-core-reconciliation" && flag == "--output" =>
        {
            Ok(Command::EmitPhase2bCoreReconciliation {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path]
            if action == "check-phase2b-core-reconciliation" && flag == "--input" =>
        {
            Ok(Command::CheckPhase2bCoreReconciliation {
                input: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "emit-lifecycle-continuity" && flag == "--output" => {
            Ok(Command::EmitLifecycleContinuity {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "check-lifecycle-continuity" && flag == "--input" => {
            Ok(Command::CheckLifecycleContinuity {
                input: PathBuf::from(path),
            })
        }
        [action, seed_flag, seed, cases_flag, cases, output_flag, output]
            if action == "emit-differential"
                && seed_flag == "--seed-hex"
                && cases_flag == "--cases"
                && output_flag == "--output" =>
        {
            Ok(Command::EmitDifferential {
                public_test_seed: decode_hex_32(seed)?,
                cases: cases.parse()?,
                output: PathBuf::from(output),
            })
        }
        _ => Err(usage_error()),
    }
}

fn usage_error() -> Box<dyn std::error::Error> {
    "usage: ed25519-yao-vectors emit --output <path> | emit-differential --seed-hex <64-hex-chars> --cases <count> --output <path> | emit-kdf --output <path> | emit-ceremony-context --output <path> | emit-lifecycle-continuity --output <path> | emit-provenance --output <path> | emit-output-sharing --output <path> | emit-output-party-views --output <path> | emit-export-delivery --output <path> | emit-export-evaluator-authorization --output <path> | emit-registration-evaluator-admission --output <path> | emit-recovery-evaluator-admission --output <path> | emit-refresh-evaluator-admission --output <path> | emit-semantic-frame-party-views --output <path> | emit-phase2b-core-reconciliation --output <path> | emit-activation-delivery --output <path> | emit-activation-recipient-party-views --output <path> | emit-evaluation-input-party-views --output <path> | emit-semantic-lifecycle --output <path> | emit-uniform-abort --output <path> | emit-evaluator-abort-views --output <path> | emit-recovery-credential-transition --output <path> | check --input <path> | check-kdf --input <path> | check-ceremony-context --input <path> | check-lifecycle-continuity --input <path> | check-provenance --input <path> | check-output-sharing --input <path> | check-output-party-views --input <path> | check-export-delivery --input <path> | check-export-evaluator-authorization --input <path> | check-registration-evaluator-admission --input <path> | check-recovery-evaluator-admission --input <path> | check-refresh-evaluator-admission --input <path> | check-semantic-frame-party-views --input <path> | check-phase2b-core-reconciliation --input <path> | check-activation-delivery --input <path> | check-activation-recipient-party-views --input <path> | check-evaluation-input-party-views --input <path> | check-semantic-lifecycle --input <path> | check-uniform-abort --input <path> | check-evaluator-abort-views --input <path> | check-recovery-credential-transition --input <path>".into()
}

fn emit(output: &Path) -> CliResult<()> {
    let corpus = canonical_vector_corpus_v1();
    write_corpus(output, &corpus)?;
    println!(
        "wrote {} canonical cases to {}",
        corpus.cases.len(),
        output.display()
    );
    Ok(())
}

fn emit_differential(public_test_seed: [u8; 32], cases: usize, output: &Path) -> CliResult<()> {
    let corpus = differential_vector_corpus_v1(public_test_seed, cases)?;
    write_corpus(output, &corpus)?;
    println!(
        "wrote {} deterministic differential cases to {}",
        corpus.cases.len(),
        output.display()
    );
    Ok(())
}

fn emit_lifecycle_continuity(output: &Path) -> CliResult<()> {
    let corpus = canonical_lifecycle_continuity_corpus_v1();
    write_corpus(output, &corpus)?;
    println!(
        "wrote {} lifecycle-continuity cases to {}",
        corpus.cases.len(),
        output.display()
    );
    Ok(())
}

fn emit_kdf(output: &Path) -> CliResult<()> {
    let corpus = canonical_kdf_vector_corpus_v1();
    write_corpus(output, &corpus)?;
    println!(
        "wrote {} KDF-continuity cases to {}",
        corpus.cases.len(),
        output.display()
    );
    Ok(())
}

fn emit_ceremony_context(output: &Path) -> CliResult<()> {
    let corpus = canonical_ceremony_context_vector_corpus_v1();
    write_corpus(output, &corpus)?;
    println!(
        "wrote {} ceremony-context cases to {}",
        corpus.cases.len(),
        output.display()
    );
    Ok(())
}

fn emit_provenance(output: &Path) -> CliResult<()> {
    let corpus = canonical_provenance_vector_corpus_v1();
    write_corpus(output, &corpus)?;
    println!(
        "wrote {} provenance outer-contract cases to {}",
        corpus.cases.len(),
        output.display()
    );
    Ok(())
}

fn emit_output_sharing(output: &Path) -> CliResult<()> {
    let corpus = canonical_output_sharing_vector_corpus_v1();
    write_bytes(
        output,
        &canonical_output_sharing_vector_corpus_json_bytes_v1(),
    )?;
    println!(
        "wrote {} output-sharing cases to {}",
        corpus.case_count(),
        output.display()
    );
    Ok(())
}

fn emit_output_party_views(output: &Path) -> CliResult<()> {
    let corpus = canonical_output_party_view_vector_corpus_v1();
    write_bytes(
        output,
        &canonical_output_party_view_vector_corpus_json_bytes_v1(),
    )?;
    println!(
        "wrote {} output-party-view cases to {}",
        corpus.case_count(),
        output.display()
    );
    Ok(())
}

fn emit_export_delivery(output: &Path) -> CliResult<()> {
    let corpus = canonical_export_delivery_vector_corpus_v1();
    write_bytes(
        output,
        &canonical_export_delivery_vector_corpus_json_bytes_v1(),
    )?;
    println!(
        "wrote {} export-delivery cases to {}",
        corpus.case_count(),
        output.display()
    );
    Ok(())
}

fn emit_activation_delivery(output: &Path) -> CliResult<()> {
    let corpus = canonical_activation_delivery_vector_corpus_v1();
    write_bytes(
        output,
        &canonical_activation_delivery_vector_corpus_json_bytes_v1(),
    )?;
    println!(
        "wrote {} activation-delivery cases to {}",
        corpus.case_count(),
        output.display()
    );
    Ok(())
}

fn emit_activation_recipient_party_views(output: &Path) -> CliResult<()> {
    let corpus = canonical_activation_recipient_party_view_vector_corpus_v1();
    write_bytes(
        output,
        &canonical_activation_recipient_party_view_vector_corpus_json_bytes_v1(),
    )?;
    println!(
        "wrote {} activation recipient-party-view cases to {}",
        corpus.case_count(),
        output.display()
    );
    Ok(())
}

fn emit_evaluation_input_party_views(output: &Path) -> CliResult<()> {
    let corpus = canonical_evaluation_input_party_view_vector_corpus_v1();
    write_bytes(
        output,
        &canonical_evaluation_input_party_view_vector_corpus_json_bytes_v1(),
    )?;
    println!(
        "wrote {} evaluation-input party-view cases to {}",
        corpus.case_count(),
        output.display()
    );
    Ok(())
}

fn emit_semantic_lifecycle(output: &Path) -> CliResult<()> {
    let corpus = canonical_semantic_lifecycle_vector_corpus_v1();
    write_bytes(
        output,
        &canonical_semantic_lifecycle_vector_corpus_json_bytes_v1(),
    )?;
    println!(
        "wrote {} semantic-lifecycle cases to {}",
        corpus.case_count(),
        output.display()
    );
    Ok(())
}

fn emit_uniform_abort(output: &Path) -> CliResult<()> {
    let corpus = canonical_uniform_abort_vector_corpus_v1();
    write_bytes(
        output,
        &canonical_uniform_abort_vector_corpus_json_bytes_v1(),
    )?;
    println!(
        "wrote {} uniform-abort cases to {}",
        corpus.case_count(),
        output.display()
    );
    Ok(())
}

fn emit_evaluator_abort_views(output: &Path) -> CliResult<()> {
    let corpus = canonical_evaluator_abort_view_vector_corpus_v1();
    write_bytes(
        output,
        &canonical_evaluator_abort_view_vector_corpus_json_bytes_v1(),
    )?;
    println!(
        "wrote {} evaluator-abort state/party-view cases to {}",
        corpus.case_count(),
        output.display()
    );
    Ok(())
}

fn emit_recovery_credential_transition(output: &Path) -> CliResult<()> {
    let corpus = canonical_recovery_credential_transition_vector_corpus_v1();
    write_bytes(
        output,
        &canonical_recovery_credential_transition_vector_corpus_json_bytes_v1(),
    )?;
    println!(
        "wrote {} recovery credential-transition cases to {}",
        corpus.case_count(),
        output.display()
    );
    Ok(())
}

fn emit_export_evaluator_authorization(output: &Path) -> CliResult<()> {
    let corpus = canonical_export_evaluator_authorization_vector_corpus_v1();
    write_bytes(
        output,
        &canonical_export_evaluator_authorization_vector_corpus_json_bytes_v1(),
    )?;
    println!(
        "wrote {} export evaluator-authorization cases to {}",
        corpus.case_count(),
        output.display()
    );
    Ok(())
}

fn emit_registration_evaluator_admission(output: &Path) -> CliResult<()> {
    let corpus = canonical_registration_evaluator_admission_vector_corpus_v1();
    write_bytes(
        output,
        &canonical_registration_evaluator_admission_vector_corpus_json_bytes_v1(),
    )?;
    println!(
        "wrote {} registration evaluator-admission cases to {}",
        corpus.case_count(),
        output.display()
    );
    Ok(())
}

fn emit_recovery_evaluator_admission(output: &Path) -> CliResult<()> {
    let corpus = canonical_recovery_evaluator_admission_vector_corpus_v1();
    write_bytes(
        output,
        &canonical_recovery_evaluator_admission_vector_corpus_json_bytes_v1(),
    )?;
    println!(
        "wrote {} recovery evaluator-admission cases to {}",
        corpus.case_count(),
        output.display()
    );
    Ok(())
}

fn emit_refresh_evaluator_admission(output: &Path) -> CliResult<()> {
    let corpus = canonical_refresh_evaluator_admission_vector_corpus_v1();
    write_bytes(
        output,
        &canonical_refresh_evaluator_admission_vector_corpus_json_bytes_v1(),
    )?;
    println!(
        "wrote {} refresh evaluator-admission cases to {}",
        corpus.case_count(),
        output.display()
    );
    Ok(())
}

fn emit_semantic_frame_party_views(output: &Path) -> CliResult<()> {
    let corpus = canonical_semantic_frame_party_view_vector_corpus_v1();
    write_bytes(
        output,
        &canonical_semantic_frame_party_view_vector_corpus_json_bytes_v1(),
    )?;
    println!(
        "wrote {} semantic-frame party-view cases to {}",
        corpus.case_count(),
        output.display()
    );
    Ok(())
}

fn emit_phase2b_core_reconciliation(output: &Path) -> CliResult<()> {
    let corpus = canonical_phase2b_core_reconciliation_corpus_v1();
    write_bytes(
        output,
        &canonical_phase2b_core_reconciliation_corpus_json_bytes_v1(),
    )?;
    println!(
        "wrote {} Phase 2B core-reconciliation cases to {}",
        corpus.case_count(),
        output.display()
    );
    Ok(())
}

fn write_bytes(output: &Path, encoded: &[u8]) -> CliResult<()> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, encoded)?;
    Ok(())
}

fn write_corpus<T: Serialize>(output: &Path, corpus: &T) -> CliResult<()> {
    let mut encoded = serde_json::to_string_pretty(corpus)?;
    encoded.push('\n');
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, encoded)?;
    Ok(())
}

fn check(input: &Path) -> CliResult<()> {
    let encoded = fs::read_to_string(input)?;
    let parsed: VectorCorpusV1 = serde_json::from_str(&encoded)?;
    let expected = canonical_vector_corpus_v1();
    if parsed != expected {
        return Err(format!("vector corpus drifted: {}", input.display()).into());
    }
    let expected_encoding = format!("{}\n", serde_json::to_string_pretty(&expected)?);
    if encoded != expected_encoding {
        return Err(format!(
            "vector corpus encoding is noncanonical: {}",
            input.display()
        )
        .into());
    }
    println!(
        "checked {} canonical cases in {}",
        parsed.cases.len(),
        input.display()
    );
    Ok(())
}

fn check_kdf(input: &Path) -> CliResult<()> {
    let encoded = fs::read_to_string(input)?;
    let parsed: KdfVectorCorpusV1 = serde_json::from_str(&encoded)?;
    let expected = canonical_kdf_vector_corpus_v1();
    if parsed != expected {
        return Err(format!("KDF-continuity corpus drifted: {}", input.display()).into());
    }
    let expected_encoding = format!("{}\n", serde_json::to_string_pretty(&expected)?);
    if encoded != expected_encoding {
        return Err(format!(
            "KDF-continuity corpus encoding is noncanonical: {}",
            input.display()
        )
        .into());
    }
    println!(
        "checked {} KDF-continuity cases in {}",
        parsed.cases.len(),
        input.display()
    );
    Ok(())
}

fn check_ceremony_context(input: &Path) -> CliResult<()> {
    let encoded = fs::read_to_string(input)?;
    let parsed: CeremonyContextVectorCorpusV1 = serde_json::from_str(&encoded)?;
    let expected = canonical_ceremony_context_vector_corpus_v1();
    if parsed != expected {
        return Err(format!("ceremony-context corpus drifted: {}", input.display()).into());
    }
    let expected_encoding = format!("{}\n", serde_json::to_string_pretty(&expected)?);
    if encoded != expected_encoding {
        return Err(format!(
            "ceremony-context corpus encoding is noncanonical: {}",
            input.display()
        )
        .into());
    }
    println!(
        "checked {} ceremony-context cases in {}",
        parsed.cases.len(),
        input.display()
    );
    Ok(())
}

fn check_provenance(input: &Path) -> CliResult<()> {
    let encoded = fs::read_to_string(input)?;
    let parsed: ProvenanceVectorCorpusV1 = serde_json::from_str(&encoded)?;
    let expected = canonical_provenance_vector_corpus_v1();
    if parsed != expected {
        return Err(format!(
            "provenance outer-contract corpus drifted: {}",
            input.display()
        )
        .into());
    }
    let expected_encoding = format!("{}\n", serde_json::to_string_pretty(&expected)?);
    if encoded != expected_encoding {
        return Err(format!(
            "provenance outer-contract corpus encoding is noncanonical: {}",
            input.display()
        )
        .into());
    }
    println!(
        "checked {} provenance outer-contract cases in {}",
        parsed.cases.len(),
        input.display()
    );
    Ok(())
}

fn check_output_sharing(input: &Path) -> CliResult<()> {
    let encoded = fs::read(input)?;
    let parsed = parse_canonical_output_sharing_vector_corpus_json_v1(&encoded)?;
    println!(
        "checked {} output-sharing cases in {}",
        parsed.case_count(),
        input.display()
    );
    Ok(())
}

fn check_output_party_views(input: &Path) -> CliResult<()> {
    let encoded = fs::read(input)?;
    let parsed = parse_canonical_output_party_view_vector_corpus_json_v1(&encoded)?;
    println!(
        "checked {} output-party-view cases in {}",
        parsed.case_count(),
        input.display()
    );
    Ok(())
}

fn check_export_delivery(input: &Path) -> CliResult<()> {
    let encoded = fs::read(input)?;
    let parsed = parse_canonical_export_delivery_vector_corpus_json_v1(&encoded)?;
    println!(
        "checked {} export-delivery cases in {}",
        parsed.case_count(),
        input.display()
    );
    Ok(())
}

fn check_activation_delivery(input: &Path) -> CliResult<()> {
    let encoded = fs::read(input)?;
    let parsed = parse_canonical_activation_delivery_vector_corpus_json_v1(&encoded)?;
    println!(
        "checked {} activation-delivery cases in {}",
        parsed.case_count(),
        input.display()
    );
    Ok(())
}

fn check_activation_recipient_party_views(input: &Path) -> CliResult<()> {
    let encoded = fs::read(input)?;
    let parsed = parse_canonical_activation_recipient_party_view_vector_corpus_json_v1(&encoded)?;
    println!(
        "checked {} activation recipient-party-view cases in {}",
        parsed.case_count(),
        input.display()
    );
    Ok(())
}

fn check_evaluation_input_party_views(input: &Path) -> CliResult<()> {
    let encoded = fs::read(input)?;
    let parsed = parse_canonical_evaluation_input_party_view_vector_corpus_json_v1(&encoded)?;
    println!(
        "checked {} evaluation-input party-view cases in {}",
        parsed.case_count(),
        input.display()
    );
    Ok(())
}

fn check_semantic_lifecycle(input: &Path) -> CliResult<()> {
    let encoded = fs::read(input)?;
    let parsed = parse_canonical_semantic_lifecycle_vector_corpus_json_v1(&encoded)?;
    println!(
        "checked {} semantic-lifecycle cases in {}",
        parsed.case_count(),
        input.display()
    );
    Ok(())
}

fn check_uniform_abort(input: &Path) -> CliResult<()> {
    let encoded = fs::read(input)?;
    let parsed = parse_canonical_uniform_abort_vector_corpus_json_v1(&encoded)?;
    println!(
        "checked {} uniform-abort cases in {}",
        parsed.case_count(),
        input.display()
    );
    Ok(())
}

fn check_evaluator_abort_views(input: &Path) -> CliResult<()> {
    let encoded = fs::read(input)?;
    let parsed = parse_canonical_evaluator_abort_view_vector_corpus_json_v1(&encoded)?;
    println!(
        "checked {} evaluator-abort state/party-view cases in {}",
        parsed.case_count(),
        input.display()
    );
    Ok(())
}

fn check_recovery_credential_transition(input: &Path) -> CliResult<()> {
    let encoded = fs::read(input)?;
    let parsed = parse_canonical_recovery_credential_transition_vector_corpus_json_v1(&encoded)?;
    println!(
        "checked {} recovery credential-transition cases in {}",
        parsed.case_count(),
        input.display()
    );
    Ok(())
}

fn check_export_evaluator_authorization(input: &Path) -> CliResult<()> {
    let encoded = fs::read(input)?;
    let parsed = parse_canonical_export_evaluator_authorization_vector_corpus_json_v1(&encoded)?;
    println!(
        "checked {} export evaluator-authorization cases in {}",
        parsed.case_count(),
        input.display()
    );
    Ok(())
}

fn check_registration_evaluator_admission(input: &Path) -> CliResult<()> {
    let encoded = fs::read(input)?;
    let parsed = parse_canonical_registration_evaluator_admission_vector_corpus_json_v1(&encoded)?;
    println!(
        "checked {} registration evaluator-admission cases in {}",
        parsed.case_count(),
        input.display()
    );
    Ok(())
}

fn check_recovery_evaluator_admission(input: &Path) -> CliResult<()> {
    let encoded = fs::read(input)?;
    let parsed = parse_canonical_recovery_evaluator_admission_vector_corpus_json_v1(&encoded)?;
    println!(
        "checked {} recovery evaluator-admission cases in {}",
        parsed.case_count(),
        input.display()
    );
    Ok(())
}

fn check_refresh_evaluator_admission(input: &Path) -> CliResult<()> {
    let encoded = fs::read(input)?;
    let parsed = parse_canonical_refresh_evaluator_admission_vector_corpus_json_v1(&encoded)?;
    println!(
        "checked {} refresh evaluator-admission cases in {}",
        parsed.case_count(),
        input.display()
    );
    Ok(())
}

fn check_semantic_frame_party_views(input: &Path) -> CliResult<()> {
    let encoded = fs::read(input)?;
    let parsed = parse_canonical_semantic_frame_party_view_vector_corpus_json_v1(&encoded)?;
    println!(
        "checked {} semantic-frame party-view cases in {}",
        parsed.case_count(),
        input.display()
    );
    Ok(())
}

fn check_phase2b_core_reconciliation(input: &Path) -> CliResult<()> {
    let encoded = fs::read(input)?;
    let parsed = parse_canonical_phase2b_core_reconciliation_corpus_json_v1(&encoded)?;
    println!(
        "checked {} Phase 2B core-reconciliation cases in {}",
        parsed.case_count(),
        input.display()
    );
    Ok(())
}

fn check_lifecycle_continuity(input: &Path) -> CliResult<()> {
    let encoded = fs::read_to_string(input)?;
    let parsed: LifecycleContinuityCorpusV1 = serde_json::from_str(&encoded)?;
    parsed.validate()?;
    let expected = canonical_lifecycle_continuity_corpus_v1();
    let expected_encoding = format!("{}\n", serde_json::to_string_pretty(&expected)?);
    if encoded != expected_encoding {
        return Err(format!(
            "lifecycle-continuity corpus encoding is noncanonical: {}",
            input.display()
        )
        .into());
    }
    println!(
        "checked {} lifecycle-continuity cases in {}",
        parsed.cases.len(),
        input.display()
    );
    Ok(())
}

fn decode_hex_32(value: &str) -> CliResult<[u8; 32]> {
    if value.len() != 64 {
        return Err("public differential seed must contain exactly 64 hex characters".into());
    }

    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| "public differential seed contains invalid hex")?;
    }
    Ok(output)
}
