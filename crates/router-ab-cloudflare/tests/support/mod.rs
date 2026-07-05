#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

pub fn read_src_file(file_name: &str) -> String {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    if file_name == "lib.rs" {
        return read_aggregate_rust_source(&src_dir);
    }
    if file_name == "strict_worker.rs" {
        return read_module_rust_source(&src_dir.join("strict_worker"));
    }
    if file_name == "durable_object.rs" {
        return read_module_rust_source(&src_dir.join("durable_object"));
    }
    let path = src_dir.join(file_name);
    fs::read_to_string(path).expect("source file should read")
}

pub fn rust_source_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_rust_files(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    out
}

pub fn extract_struct_block(source: &str, struct_name: &str) -> String {
    let marker = format!("struct {struct_name}");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("struct marker `{marker}` should exist"));
    let body_start = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("struct `{struct_name}` should have a body"));
    let mut depth = 0usize;
    for (offset, ch) in source[body_start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth
                    .checked_sub(1)
                    .expect("struct body braces should stay balanced");
                if depth == 0 {
                    return source[start..=body_start + offset].to_owned();
                }
            }
            _ => {}
        }
    }
    panic!("struct `{struct_name}` body should end");
}

pub fn extract_function_body(source: &str, function_name: &str) -> String {
    let marker = format!("fn {function_name}");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("function marker `{marker}` should exist"));
    let body_start = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("function `{function_name}` should have a body"));
    let mut depth = 0usize;
    for (offset, ch) in source[body_start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth
                    .checked_sub(1)
                    .expect("function body braces should stay balanced");
                if depth == 0 {
                    return source[body_start..=body_start + offset].to_owned();
                }
            }
            _ => {}
        }
    }
    panic!("function `{function_name}` body should end");
}

pub fn extract_braced_block_after_marker(source: &str, marker: &str) -> String {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("marker `{marker}` should exist"));
    let body_start = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("marker `{marker}` should have a braced block"));
    let mut depth = 0usize;
    for (offset, ch) in source[body_start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth
                    .checked_sub(1)
                    .expect("braced block should stay balanced");
                if depth == 0 {
                    return source[body_start..=body_start + offset].to_owned();
                }
            }
            _ => {}
        }
    }
    panic!("marker `{marker}` braced block should end");
}

fn read_aggregate_rust_source(src_dir: &Path) -> String {
    let mut files = Vec::new();
    collect_rust_files(src_dir, &mut files);
    read_joined_sources(files)
}

fn read_module_rust_source(module_dir: &Path) -> String {
    let mut files = Vec::new();
    collect_rust_files(module_dir, &mut files);
    read_joined_sources(files)
}

fn read_joined_sources(mut files: Vec<PathBuf>) -> String {
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let source = fs::read_to_string(&path).expect("source file should read");
            format!("\n// source: {}\n{source}", path.display())
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("source directory should read") {
        let entry = entry.expect("source entry should read");
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}
