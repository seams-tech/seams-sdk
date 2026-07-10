use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output};

use serde::Deserialize;

type DynError = Box<dyn std::error::Error>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationBaseline {
    verus: VerusPin,
    aeneas: SourcePin,
    charon: SourcePin,
    lean: LeanPin,
    extraction: ExtractionBaseline,
    evidence: EvidenceCounts,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerusPin {
    release: String,
    vstd: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcePin {
    repo: String,
    rev: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanPin {
    toolchain: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtractionBaseline {
    #[serde(rename = "crate")]
    crate_path: String,
    functions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceCounts {
    vector_cases: usize,
    production_rust_tests: usize,
    generator_rust_tests: usize,
    anti_drift_tests: usize,
    verus_obligations: usize,
    lean_model_theorems: usize,
    aeneas_extracted_functions: usize,
}

struct ArtifactSnapshot {
    path: PathBuf,
    bytes: Vec<u8>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Ed25519 Yao formal-verification task failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), DynError> {
    let task = env::args().nth(1).unwrap_or_else(|| "all".to_owned());
    match task.as_str() {
        "all" | "check" => run_all(),
        "vectors-check" => run_vectors_check(),
        "parity" => run_parity(),
        "anti-drift" => run_anti_drift(),
        "lean-check" => run_lean_check(),
        "aeneas-check" => run_aeneas_check(),
        "verus-check" => run_verus_check(),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        unknown => Err(format!(
            "unknown task `{unknown}`; expected all, check, vectors-check, parity, anti-drift, lean-check, aeneas-check, or verus-check"
        )
        .into()),
    }
}

fn run_all() -> Result<(), DynError> {
    run_vectors_check()?;
    run_parity()?;
    run_anti_drift()?;
    run_aeneas_check()?;
    run_lean_check()?;
    run_verus_check()?;
    println!("all ok: 6 nonempty Ed25519 Yao verification tracks executed");
    Ok(())
}

fn print_help() {
    println!(
        "usage: cargo yao-fv [all|check|vectors-check|parity|anti-drift|lean-check|aeneas-check|verus-check]"
    );
}

fn run_vectors_check() -> Result<(), DynError> {
    let baseline = load_baseline()?;
    let vector_file = generator_dir(&baseline).join("vectors/ed25519-yao-v1.json");
    let generator_manifest = generator_manifest(&baseline);
    require_file(&vector_file, "committed Ed25519 Yao vector corpus")?;
    let generator_manifest_string = path_string(&generator_manifest)?;
    let vector_file_string = path_string(&vector_file)?;
    let output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check",
            "--input",
            vector_file_string,
        ],
        "vectors-check canonical corpus",
    )?;
    let expected_summary = format!("checked {} canonical cases", baseline.evidence.vector_cases);
    if !output.contains(&expected_summary) {
        return Err(format!(
            "vector command did not report expected nonzero case count `{expected_summary}`"
        )
        .into());
    }
    println!(
        "vectors-check ok: {} canonical cases in {}",
        baseline.evidence.vector_cases,
        vector_file.display()
    );
    Ok(())
}

fn run_parity() -> Result<(), DynError> {
    let baseline = load_baseline()?;
    let production_count = run_cargo_test_suite(
        &production_manifest(),
        &[],
        baseline.evidence.production_rust_tests,
        "production manifest crate",
    )?;
    let generator_count = run_cargo_test_suite(
        &generator_manifest(&baseline),
        &[],
        baseline.evidence.generator_rust_tests,
        "clear generator crate",
    )?;
    println!(
        "parity ok: {production_count} production and {generator_count} generator tests, including doctests"
    );
    Ok(())
}

fn run_anti_drift() -> Result<(), DynError> {
    let baseline = load_baseline()?;
    let count = run_cargo_test_suite(
        &verus_manifest(),
        &["--test", "anti_drift"],
        baseline.evidence.anti_drift_tests,
        "production-to-mirror anti-drift",
    )?;
    println!("anti-drift ok: {count} production, generator, and mirror comparisons");
    Ok(())
}

fn run_lean_check() -> Result<(), DynError> {
    let baseline = load_baseline()?;
    reject_forbidden_lean_declarations()?;
    verify_lean_toolchain(&baseline, &lean_model_dir())?;

    let manifest_model = lean_model_dir().join("Ed25519YaoModel/Manifest.lean");
    let theorem_count = count_lean_theorems(&manifest_model)?;
    require_exact_count(
        "Lean model theorem",
        theorem_count,
        baseline.evidence.lean_model_theorems,
    )?;

    let lake = resolve_program("lake", "install Lean through elan")?;
    run_command(
        Command::new(lake)
            .arg("build")
            .arg("Ed25519YaoModel")
            .current_dir(lean_model_dir()),
        "lean-check named Ed25519YaoModel target",
    )?;
    require_file(
        &lean_model_dir().join(".lake/build/lib/lean/Ed25519YaoModel.olean"),
        "named Lean model output",
    )?;
    println!("lean-check ok: {theorem_count} theorems and Ed25519YaoModel.olean produced");
    Ok(())
}

fn run_aeneas_check() -> Result<(), DynError> {
    let baseline = load_baseline()?;
    reject_forbidden_lean_declarations()?;
    verify_lean_toolchain(&baseline, &lean_boundary_dir())?;

    let aeneas_dir = lean_boundary_dir().join("tools/aeneas");
    let charon_dir = lean_boundary_dir().join("tools/charon");
    verify_git_checkout(&aeneas_dir, &baseline.aeneas, "Aeneas")?;
    verify_git_checkout(&charon_dir, &baseline.charon, "Charon")?;
    verify_tool_binary(&aeneas_dir.join("bin/aeneas"), &aeneas_dir, "Aeneas")?;
    verify_tool_binary(&charon_dir.join("bin/charon"), &charon_dir, "Charon")?;

    let artifact_paths = aeneas_artifact_paths();
    let snapshots = snapshot_artifacts(&artifact_paths)?;
    let extraction = lean_boundary_dir().join("scripts/extract-reference-boundary.sh");
    require_file(&extraction, "Aeneas reference-boundary extractor")?;
    run_command(
        &mut Command::new(extraction),
        "aeneas-check reference-boundary extraction",
    )?;
    assert_artifacts_unchanged(&snapshots)?;
    reject_forbidden_lean_declarations()?;
    verify_generated_extraction_scope(&baseline)?;

    let lake = resolve_program("lake", "install Lean through elan")?;
    run_command(
        Command::new(lake)
            .arg("build")
            .arg("Ed25519Yao")
            .arg("Ed25519YaoBoundary")
            .current_dir(lean_boundary_dir()),
        "aeneas-check named Lean boundary targets",
    )?;
    require_file(
        &lean_boundary_dir().join(".lake/build/lib/lean/Ed25519Yao.olean"),
        "named generated Lean output",
    )?;
    require_file(
        &lean_boundary_dir().join(".lake/build/lib/lean/Ed25519YaoBoundary.olean"),
        "named Lean boundary output",
    )?;
    println!(
        "aeneas-check ok: {} generated functions, 2 stable Lean artifacts, and 2 named Lean targets checked",
        baseline.evidence.aeneas_extracted_functions
    );
    Ok(())
}

fn run_verus_check() -> Result<(), DynError> {
    let baseline = load_baseline()?;
    reject_forbidden_verus_declarations()?;
    verify_vstd_pin(&baseline)?;

    let verus = resolve_program("verus", "install the pinned repository Verus release")?;
    let cargo_verus = resolve_program(
        "cargo-verus",
        "install cargo-verus from the same pinned Verus release",
    )?;
    verify_same_tool_bundle(&verus, &cargo_verus)?;

    let version_output = capture_command(
        Command::new(&verus).arg("--version"),
        "verus --version",
        true,
    )?;
    if !version_output.contains(&format!("Version: {}", baseline.verus.release)) {
        return Err(format!(
            "Verus release mismatch: expected {}; received `{}`",
            baseline.verus.release,
            version_output.trim().replace('\n', " | ")
        )
        .into());
    }

    let manifest = verus_manifest();
    let output = capture_command(
        Command::new(cargo_verus)
            .arg("verify")
            .arg("--locked")
            .arg("--manifest-path")
            .arg(manifest),
        "verus-check pinned cargo-verus driver",
        true,
    )?;
    let verified = parse_verus_verified_count(&output)?;
    require_exact_count(
        "Verus obligation",
        verified,
        baseline.evidence.verus_obligations,
    )?;
    println!(
        "verus-check ok: {verified} obligations verified by release {}",
        baseline.verus.release
    );
    Ok(())
}

fn run_cargo_test_suite(
    manifest: &Path,
    selectors: &[&str],
    expected_count: usize,
    label: &str,
) -> Result<usize, DynError> {
    let actual_count = count_cargo_tests(manifest, selectors)?;
    require_exact_count(label, actual_count, expected_count)?;

    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command
        .arg("test")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(manifest)
        .args(selectors);
    run_command(&mut command, label)?;
    Ok(actual_count)
}

fn count_cargo_tests(manifest: &Path, selectors: &[&str]) -> Result<usize, DynError> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command
        .arg("test")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(manifest)
        .args(selectors)
        .args(["--", "--list", "--format", "terse"]);
    let output = capture_command(&mut command, "list Rust tests", false)?;
    Ok(output
        .lines()
        .filter(|line| line.trim_end().ends_with(": test"))
        .count())
}

fn run_cargo_capture(args: &[&str], context: &str) -> Result<String, DynError> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    capture_command(Command::new(cargo).args(args), context, true)
}

fn run_command(command: &mut Command, context: &str) -> Result<(), DynError> {
    let status = command.status()?;
    ensure_success(context, status)
}

fn capture_command(command: &mut Command, context: &str, relay: bool) -> Result<String, DynError> {
    let output = command.output()?;
    ensure_success(context, output.status)?;
    if relay {
        relay_output(&output)?;
    }
    combined_output(&output)
}

fn relay_output(output: &Output) -> Result<(), DynError> {
    let stdout = std::str::from_utf8(&output.stdout)?;
    let stderr = std::str::from_utf8(&output.stderr)?;
    print!("{stdout}");
    eprint!("{stderr}");
    Ok(())
}

fn combined_output(output: &Output) -> Result<String, DynError> {
    let stdout = std::str::from_utf8(&output.stdout)?;
    let stderr = std::str::from_utf8(&output.stderr)?;
    Ok(format!("{stdout}\n{stderr}"))
}

fn ensure_success(context: &str, status: ExitStatus) -> Result<(), DynError> {
    if status.success() {
        Ok(())
    } else {
        Err(format!("{context} exited with status {status}").into())
    }
}

fn require_exact_count(label: &str, actual: usize, expected: usize) -> Result<(), DynError> {
    if actual == expected && actual > 0 {
        Ok(())
    } else {
        Err(
            format!("{label} count mismatch: expected nonzero {expected}, received {actual}")
                .into(),
        )
    }
}

fn resolve_program(program: &str, remediation: &str) -> Result<PathBuf, DynError> {
    for directory in env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
    {
        let candidate = directory.join(program);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!("required program `{program}` is unavailable; {remediation}").into())
}

fn require_file(path: &Path, description: &str) -> Result<(), DynError> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("missing {description} at {}", path.display()).into())
    }
}

fn verify_git_checkout(directory: &Path, pin: &SourcePin, tool: &str) -> Result<(), DynError> {
    if !directory.join(".git").exists() {
        return Err(format!(
            "missing pinned {tool} checkout at {}; run lean-boundary/scripts/setup-aeneas.sh",
            directory.display()
        )
        .into());
    }
    let revision = capture_command(
        Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(["rev-parse", "HEAD"]),
        &format!("read {tool} revision"),
        false,
    )?;
    if revision.trim() != pin.rev {
        return Err(format!(
            "{tool} revision mismatch: expected {}, received {}",
            pin.rev,
            revision.trim()
        )
        .into());
    }
    let remote = capture_command(
        Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(["remote", "get-url", "origin"]),
        &format!("read {tool} origin"),
        false,
    )?;
    if remote.trim() != pin.repo {
        return Err(format!(
            "{tool} origin mismatch: expected {}, received {}",
            pin.repo,
            remote.trim()
        )
        .into());
    }
    let status = capture_command(
        Command::new("git").arg("-C").arg(directory).args([
            "status",
            "--porcelain",
            "--untracked-files=no",
        ]),
        &format!("read {tool} checkout status"),
        false,
    )?;
    if !status.trim().is_empty() {
        return Err(format!("{tool} source checkout contains tracked modifications").into());
    }
    Ok(())
}

fn verify_tool_binary(binary: &Path, source: &Path, tool: &str) -> Result<(), DynError> {
    require_file(binary, &format!("{tool} binary"))?;
    let canonical_binary = binary.canonicalize()?;
    let canonical_source = source.canonicalize()?;
    if !canonical_binary.starts_with(&canonical_source) {
        return Err(format!(
            "{tool} binary {} is outside pinned source checkout {}",
            canonical_binary.display(),
            canonical_source.display()
        )
        .into());
    }
    Ok(())
}

fn verify_same_tool_bundle(verus: &Path, cargo_verus: &Path) -> Result<(), DynError> {
    let canonical_verus = verus.canonicalize()?;
    let canonical_cargo_verus = cargo_verus.canonicalize()?;
    if canonical_verus.parent() != canonical_cargo_verus.parent() {
        return Err(format!(
            "verus and cargo-verus must come from one release bundle: {} vs {}",
            canonical_verus.display(),
            canonical_cargo_verus.display()
        )
        .into());
    }
    Ok(())
}

fn verify_vstd_pin(baseline: &VerificationBaseline) -> Result<(), DynError> {
    let cargo_toml = fs::read_to_string(verus_manifest())?;
    let expected = format!("vstd = \"={}\"", baseline.verus.vstd);
    if !cargo_toml.lines().any(|line| line.trim() == expected) {
        return Err(format!("Verus manifest must contain exact pin `{expected}`").into());
    }
    Ok(())
}

fn verify_lean_toolchain(
    baseline: &VerificationBaseline,
    directory: &Path,
) -> Result<(), DynError> {
    let configured = fs::read_to_string(directory.join("lean-toolchain"))?;
    if configured.trim() != baseline.lean.toolchain {
        return Err(format!(
            "Lean toolchain mismatch in {}: expected {}, received {}",
            directory.display(),
            baseline.lean.toolchain,
            configured.trim()
        )
        .into());
    }
    let lake = resolve_program("lake", "install Lean through elan")?;
    let version = capture_command(
        Command::new(lake).arg("--version").current_dir(directory),
        "lake --version",
        false,
    )?;
    let expected_version = baseline
        .lean
        .toolchain
        .rsplit(':')
        .next()
        .ok_or("Lean toolchain has no version component")?;
    if !version.contains(expected_version.trim_start_matches('v')) {
        return Err(format!(
            "Lake did not select Lean {expected_version}; received `{}`",
            version.trim()
        )
        .into());
    }
    Ok(())
}

fn load_baseline() -> Result<VerificationBaseline, DynError> {
    let source = fs::read_to_string(baseline_path())?;
    let baseline: VerificationBaseline = toml::from_str(&source)?;
    validate_baseline(&baseline)?;
    Ok(baseline)
}

fn validate_baseline(baseline: &VerificationBaseline) -> Result<(), DynError> {
    validate_source_pin(&baseline.aeneas, "Aeneas")?;
    validate_source_pin(&baseline.charon, "Charon")?;
    if baseline.verus.release.is_empty()
        || baseline.verus.vstd.is_empty()
        || baseline.lean.toolchain.is_empty()
        || baseline.extraction.crate_path.is_empty()
    {
        return Err("verification baseline contains an empty tool or crate pin".into());
    }
    let mut unique_functions = HashSet::new();
    for function in &baseline.extraction.functions {
        if function.is_empty() || !unique_functions.insert(function) {
            return Err("Aeneas extraction scope contains an empty or duplicate function".into());
        }
    }
    require_exact_count(
        "Aeneas extraction scope",
        baseline.extraction.functions.len(),
        baseline.evidence.aeneas_extracted_functions,
    )?;
    let counts = [
        baseline.evidence.vector_cases,
        baseline.evidence.production_rust_tests,
        baseline.evidence.generator_rust_tests,
        baseline.evidence.anti_drift_tests,
        baseline.evidence.verus_obligations,
        baseline.evidence.lean_model_theorems,
    ];
    if counts.contains(&0) {
        return Err("verification baseline contains a zero evidence count".into());
    }
    require_file(
        &repository_root()
            .join(&baseline.extraction.crate_path)
            .join("Cargo.toml"),
        "configured Aeneas extraction crate manifest",
    )?;
    Ok(())
}

fn validate_source_pin(pin: &SourcePin, tool: &str) -> Result<(), DynError> {
    if !pin.repo.starts_with("https://github.com/") {
        return Err(format!("{tool} repository pin must use an HTTPS GitHub URL").into());
    }
    if pin.rev.len() != 40 || !pin.rev.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{tool} revision must be a full 40-character Git hash").into());
    }
    Ok(())
}

fn aeneas_artifact_paths() -> [PathBuf; 2] {
    [
        lean_boundary_dir().join("Ed25519Yao/Types.lean"),
        lean_boundary_dir().join("Ed25519Yao/Funs.lean"),
    ]
}

fn snapshot_artifacts(paths: &[PathBuf]) -> Result<Vec<ArtifactSnapshot>, DynError> {
    paths
        .iter()
        .map(|path| {
            require_file(path, "checked-in Aeneas artifact")?;
            Ok(ArtifactSnapshot {
                path: path.clone(),
                bytes: fs::read(path)?,
            })
        })
        .collect()
}

fn assert_artifacts_unchanged(snapshots: &[ArtifactSnapshot]) -> Result<(), DynError> {
    for snapshot in snapshots {
        let regenerated = fs::read(&snapshot.path)?;
        if regenerated != snapshot.bytes {
            return Err(format!(
                "Aeneas artifact drifted after regeneration: {}",
                snapshot.path.display()
            )
            .into());
        }
    }
    Ok(())
}

fn verify_generated_extraction_scope(baseline: &VerificationBaseline) -> Result<(), DynError> {
    let generated = fs::read_to_string(lean_boundary_dir().join("Ed25519Yao/Funs.lean"))?;
    let boundary = fs::read_to_string(lean_boundary_dir().join("Ed25519YaoBoundary/Scope.lean"))?;
    for function in &baseline.extraction.functions {
        let function_name = function
            .rsplit("::")
            .next()
            .ok_or("extraction function has no Rust item name")?;
        let generated_declaration = format!("def {function_name}\n");
        if !generated.contains(&generated_declaration) {
            return Err(
                format!("generated Lean is missing scoped function `{function_name}`").into(),
            );
        }
        let lean_name = function.replace("::", ".");
        if !boundary.contains(&lean_name) {
            return Err(format!(
                "Lean boundary does not reference generated function `{lean_name}`"
            )
            .into());
        }
    }
    Ok(())
}

fn count_lean_theorems(path: &Path) -> Result<usize, DynError> {
    let source = fs::read_to_string(path)?;
    Ok(source
        .lines()
        .filter(|line| line.trim_start().starts_with("theorem "))
        .count())
}

fn parse_verus_verified_count(output: &str) -> Result<usize, DynError> {
    let result_line = output
        .lines()
        .find(|line| line.contains("verification results::"))
        .ok_or("Verus output did not contain a verification result count")?;
    if !result_line.contains(", 0 errors") {
        return Err(format!("Verus reported a nonzero error count: {result_line}").into());
    }
    let count = result_line
        .split("verification results::")
        .nth(1)
        .and_then(|result| result.split_whitespace().next())
        .ok_or("Verus result line did not contain a verified count")?
        .parse()?;
    Ok(count)
}

fn reject_forbidden_lean_declarations() -> Result<(), DynError> {
    let mut lean_files = Vec::new();
    collect_source_files(
        &formal_verification_dir(),
        "lean",
        &[".lake", "tools"],
        &mut lean_files,
    )?;
    reject_tokens(&lean_files, &["sorry", "admit", "axiom"], "Lean")?;
    println!(
        "Lean source guard ok: {} project-owned files contain no sorry, admit, or axiom token",
        lean_files.len()
    );
    Ok(())
}

fn reject_forbidden_verus_declarations() -> Result<(), DynError> {
    let mut rust_files = Vec::new();
    collect_source_files(&verus_dir(), "rs", &["target"], &mut rust_files)?;
    reject_tokens(
        &rust_files,
        &[
            "assume",
            "assume_specification",
            "external_body",
            "admit",
            "axiom",
        ],
        "Verus",
    )?;
    println!(
        "Verus source guard ok: {} mirror files contain no unchecked-declaration token",
        rust_files.len()
    );
    Ok(())
}

fn collect_source_files(
    directory: &Path,
    extension: &str,
    skipped_directories: &[&str],
    files: &mut Vec<PathBuf>,
) -> Result<(), DynError> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            let skipped = path.file_name().is_some_and(|name| {
                skipped_directories
                    .iter()
                    .any(|skipped_name| name == *skipped_name)
            });
            if !skipped {
                collect_source_files(&path, extension, skipped_directories, files)?;
            }
        } else if path
            .extension()
            .is_some_and(|candidate| candidate == extension)
        {
            files.push(path);
        }
    }
    Ok(())
}

fn reject_tokens(files: &[PathBuf], forbidden: &[&str], owner: &str) -> Result<(), DynError> {
    if files.is_empty() {
        return Err(format!("no project-owned {owner} source files were found").into());
    }
    for file in files {
        let source = fs::read_to_string(file)?;
        for token in
            source.split(|character: char| !character.is_alphanumeric() && character != '_')
        {
            if forbidden.contains(&token) {
                return Err(format!(
                    "forbidden {owner} declaration token `{token}` in {}",
                    file.display()
                )
                .into());
            }
        }
    }
    Ok(())
}

fn path_string(path: &Path) -> Result<&str, DynError> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()).into())
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../..")
        .canonicalize()
        .expect("repository root must be readable")
}

fn production_manifest() -> PathBuf {
    repository_root().join("crates/ed25519-yao/Cargo.toml")
}

fn generator_dir(baseline: &VerificationBaseline) -> PathBuf {
    repository_root().join(&baseline.extraction.crate_path)
}

fn generator_manifest(baseline: &VerificationBaseline) -> PathBuf {
    generator_dir(baseline).join("Cargo.toml")
}

fn formal_verification_dir() -> PathBuf {
    repository_root().join("crates/ed25519-yao/formal-verification")
}

fn baseline_path() -> PathBuf {
    formal_verification_dir().join("toolchain.toml")
}

fn verus_dir() -> PathBuf {
    formal_verification_dir().join("verus")
}

fn verus_manifest() -> PathBuf {
    verus_dir().join("Cargo.toml")
}

fn lean_model_dir() -> PathBuf {
    formal_verification_dir().join("lean-model")
}

fn lean_boundary_dir() -> PathBuf {
    formal_verification_dir().join("lean-boundary")
}
