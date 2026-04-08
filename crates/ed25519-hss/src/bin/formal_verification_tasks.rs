use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

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
            run_proof_check()?;
        }
        "check" => {
            run_vectors_check()?;
            run_parity()?;
        }
        "vectors-check" => run_vectors_check()?,
        "parity" => run_parity()?,
        "proof-check" => run_proof_check()?,
        "verus-check" => run_verus_check()?,
        "help" | "--help" | "-h" => print_help(),
        other => {
            return Err(format!(
                "unknown task `{other}`; expected one of: all, check, vectors-check, parity, proof-check, verus-check"
            )
            .into());
        }
    }
    Ok(())
}

fn print_help() {
    println!("usage: cargo hss-fv [all|check|vectors-check|parity|proof-check|verus-check]");
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

fn run_proof_check() -> Result<(), DynError> {
    let lake = match resolve_lake() {
        Some(path) => path,
        None => {
            println!("Lean toolchain not installed; skipping proof-check");
            return Ok(());
        }
    };
    let status = Command::new(lake)
        .arg("build")
        .current_dir(lean_privacy_verification_dir())
        .status()?;
    ensure_success("proof-check lake build", status)?;
    println!("proof-check ok");
    Ok(())
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
