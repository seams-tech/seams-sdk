use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

type DynError = Box<dyn std::error::Error>;

fn main() {
    if let Err(err) = run() {
        eprintln!("formal verification task failed: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), DynError> {
    let task = env::args().nth(1).unwrap_or_else(|| "all".to_string());
    match task.as_str() {
        "all" => {
            run_vectors_check()?;
            run_parity()?;
            run_aeneas_check()?;
            run_lean_check()?;
            run_verus_check()?;
        }
        "check" => {
            run_vectors_check()?;
            run_parity()?;
        }
        "vectors-check" => run_vectors_check()?,
        "parity" => run_parity()?,
        "lean-check" => run_lean_check()?,
        "aeneas-check" => run_aeneas_check()?,
        "verus-check" => run_verus_check()?,
        "help" | "--help" | "-h" => print_help(),
        other => {
            return Err(format!(
                "unknown task `{other}`; expected one of: all, check, vectors-check, parity, lean-check, aeneas-check, verus-check"
            )
            .into());
        }
    }
    Ok(())
}

fn print_help() {
    println!(
        "usage: cargo hss-fv [all|check|vectors-check|parity|lean-check|aeneas-check|verus-check]"
    );
}

fn crate_manifest_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")
}

fn fixture_reference_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("f_expand_v1.json")
}

fn formal_verification_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("formal-verification")
}

fn lean_privacy_verification_dir() -> PathBuf {
    formal_verification_dir().join("lean-privacy")
}

fn lean_boundary_verification_dir() -> PathBuf {
    formal_verification_dir().join("lean-boundary")
}

fn lean_boundary_tools_dir() -> PathBuf {
    lean_boundary_verification_dir().join("tools")
}

fn verus_verification_dir() -> PathBuf {
    formal_verification_dir().join("verus")
}

fn cargo_program() -> OsString {
    env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

fn run_vectors_check() -> Result<(), DynError> {
    let output = Command::new(cargo_program())
        .args([
            "run",
            "--quiet",
            "--manifest-path",
            crate_manifest_path()
                .to_str()
                .ok_or("manifest path is not valid UTF-8")?,
            "--bin",
            "emit_fixture_json",
        ])
        .output()?;
    ensure_success("vectors-check cargo run", output.status)?;
    let expected = fs::read_to_string(fixture_reference_path())?;
    let actual = String::from_utf8(output.stdout)?;
    if actual != expected {
        return Err("fixture output does not match committed reference file".into());
    }
    println!("vectors-check ok");
    Ok(())
}

fn run_parity() -> Result<(), DynError> {
    let status = Command::new(cargo_program())
        .args([
            "test",
            "--manifest-path",
            crate_manifest_path()
                .to_str()
                .ok_or("manifest path is not valid UTF-8")?,
            "fv_hss_",
        ])
        .status()?;
    ensure_success("parity cargo test", status)?;
    println!("parity ok");
    Ok(())
}

fn run_lean_check() -> Result<(), DynError> {
    let lake = require_lake()?;
    let status = Command::new(lake)
        .arg("build")
        .current_dir(lean_privacy_verification_dir())
        .status()?;
    ensure_success("lean-check lake build", status)?;
    println!("lean-check ok");
    Ok(())
}

fn run_aeneas_check() -> Result<(), DynError> {
    let aeneas = require_aeneas()?;
    let charon = require_charon()?;
    let lake = require_lake()?;

    let aeneas_help = Command::new(&aeneas)
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    ensure_success("aeneas-check aeneas -version", aeneas_help)?;

    let charon_help = Command::new(&charon)
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    ensure_success("aeneas-check charon version", charon_help)?;

    let extract_script = lean_boundary_verification_dir()
        .join("scripts")
        .join("extract-visible-boundary.sh");
    let extract_status = Command::new(&extract_script).status()?;
    ensure_success("aeneas-check extract-visible-boundary.sh", extract_status)?;

    ensure_clean_after_aeneas_extraction()?;

    let status = Command::new(lake)
        .arg("build")
        .current_dir(lean_boundary_verification_dir())
        .status()?;
    ensure_success("aeneas-check lake build", status)?;
    println!("aeneas-check ok");
    Ok(())
}

fn resolve_aeneas() -> Option<PathBuf> {
    if command_exists("aeneas") {
        return Some(PathBuf::from("aeneas"));
    }

    let local = lean_boundary_tools_dir()
        .join("aeneas")
        .join("bin")
        .join("aeneas");
    local.exists().then_some(local)
}

fn resolve_charon() -> Option<PathBuf> {
    if command_exists("charon") {
        return Some(PathBuf::from("charon"));
    }

    let local = lean_boundary_tools_dir()
        .join("charon")
        .join("bin")
        .join("charon");
    local.exists().then_some(local)
}

fn require_aeneas() -> Result<PathBuf, DynError> {
    resolve_aeneas().ok_or_else(|| {
        format!(
            "Aeneas toolchain not installed; expected `aeneas` on PATH or {}",
            lean_boundary_tools_dir()
                .join("aeneas")
                .join("bin")
                .join("aeneas")
                .display()
        )
        .into()
    })
}

fn require_charon() -> Result<PathBuf, DynError> {
    resolve_charon().ok_or_else(|| {
        format!(
            "Aeneas toolchain not installed; expected `charon` on PATH or {}",
            lean_boundary_tools_dir()
                .join("charon")
                .join("bin")
                .join("charon")
                .display()
        )
        .into()
    })
}

fn run_verus_check() -> Result<(), DynError> {
    let verus_dir = verus_verification_dir();
    let manifest_path = verus_dir.join("Cargo.toml");

    if command_exists("cargo-verus") {
        let status = Command::new(cargo_program())
            .args([
                "verus",
                "verify",
                "--manifest-path",
                manifest_path
                    .to_str()
                    .ok_or("verus manifest path is not valid UTF-8")?,
            ])
            .status()?;
        ensure_success("verus-check cargo verus", status)?;
        run_verus_anti_drift_tests(&manifest_path)?;
        println!("verus-check ok");
        return Ok(());
    }

    if command_exists("verus") {
        let status = Command::new("verus")
            .arg("src/lib.rs")
            .current_dir(&verus_dir)
            .status()?;
        ensure_success("verus-check verus", status)?;
        run_verus_anti_drift_tests(&manifest_path)?;
        println!("verus-check ok");
        return Ok(());
    }

    println!(
        "Verus toolchain not installed; expected `cargo-verus` or `verus` to be available for {}",
        manifest_path.display()
    );
    Ok(())
}

fn run_verus_anti_drift_tests(manifest_path: &Path) -> Result<(), DynError> {
    let status = Command::new(cargo_program())
        .args([
            "test",
            "--manifest-path",
            manifest_path
                .to_str()
                .ok_or("verus manifest path is not valid UTF-8")?,
            "--test",
            "anti_drift",
        ])
        .status()?;
    ensure_success("verus-check anti-drift cargo test", status)?;
    println!("verus anti-drift ok");
    Ok(())
}

fn resolve_lake() -> Option<PathBuf> {
    if command_exists("lake") {
        return Some(PathBuf::from("lake"));
    }
    let home = env::var_os("HOME")?;
    let fallback = PathBuf::from(home).join(".elan").join("bin").join("lake");
    fallback.exists().then_some(fallback)
}

fn require_lake() -> Result<PathBuf, DynError> {
    resolve_lake().ok_or_else(|| {
        "Lean toolchain not installed; expected `lake` on PATH or `$HOME/.elan/bin/lake`".into()
    })
}

fn ensure_clean_after_aeneas_extraction() -> Result<(), DynError> {
    let boundary_dir = lean_boundary_verification_dir();
    let tracked_paths = [
        boundary_dir
            .join("generated")
            .join("visible-boundary-package")
            .join("Ed25519Hss")
            .join("Types.lean"),
        boundary_dir
            .join("generated")
            .join("visible-boundary-package")
            .join("Ed25519Hss")
            .join("Funs.lean"),
        boundary_dir
            .join("generated")
            .join("visible-boundary-package")
            .join("Ed25519Hss")
            .join("FunsExternal_Template.lean"),
        boundary_dir.join("Ed25519Hss").join("Types.lean"),
        boundary_dir.join("Ed25519Hss").join("Funs.lean"),
        boundary_dir.join("Ed25519Hss").join("FunsExternal.lean"),
    ];

    let mut command = Command::new("git");
    command.arg("diff").arg("--exit-code").arg("--");
    for path in tracked_paths {
        command.arg(path);
    }
    let status = command.status()?;
    ensure_success(
        "aeneas-check generated boundary artifacts differ from committed files",
        status,
    )
}

fn command_exists(program: &str) -> bool {
    env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
        .any(|dir| dir.join(program).exists())
}

fn ensure_success(context: &str, status: ExitStatus) -> Result<(), DynError> {
    if status.success() {
        Ok(())
    } else {
        Err(format!("{context} exited with status {status}").into())
    }
}
