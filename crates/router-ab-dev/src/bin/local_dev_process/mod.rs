#![allow(dead_code)]

use router_ab_core::LocalServiceRoleV1;
use router_ab_dev::{
    local_env_materialization_plan_v1, local_worker_bind_addr_v1, parse_local_env_file_contents_v1,
    parse_local_worker_role_config_for_role_v1, LocalWorkerRoleConfigV1,
    LOCAL_DERIVER_A_ENV_FILE_V1, LOCAL_DERIVER_B_ENV_FILE_V1, LOCAL_ROUTER_ENV_FILE_V1,
    LOCAL_SIGNING_WORKER_ENV_FILE_V1, LOCAL_WORKER_HEALTH_PATH_V1,
};
use serde::Serialize;
use std::{
    fs::{self, File},
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

pub const PID_DIR: &str = ".router-ab-local/pids";
pub const LOG_DIR: &str = ".router-ab-local/logs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalWorkerProcessSpec {
    pub role: LocalServiceRoleV1,
    pub role_label: &'static str,
    pub env_file: &'static str,
    pub pid_file: &'static str,
    pub stdout_file: &'static str,
    pub stderr_file: &'static str,
}

pub const LOCAL_WORKER_PROCESS_SPECS: &[LocalWorkerProcessSpec] = &[
    LocalWorkerProcessSpec {
        role: LocalServiceRoleV1::DeriverA,
        role_label: "deriver-a",
        env_file: LOCAL_DERIVER_A_ENV_FILE_V1,
        pid_file: "deriver-a.pid",
        stdout_file: "deriver-a.stdout.log",
        stderr_file: "deriver-a.stderr.log",
    },
    LocalWorkerProcessSpec {
        role: LocalServiceRoleV1::DeriverB,
        role_label: "deriver-b",
        env_file: LOCAL_DERIVER_B_ENV_FILE_V1,
        pid_file: "deriver-b.pid",
        stdout_file: "deriver-b.stdout.log",
        stderr_file: "deriver-b.stderr.log",
    },
    LocalWorkerProcessSpec {
        role: LocalServiceRoleV1::SigningWorker,
        role_label: "signing-worker",
        env_file: LOCAL_SIGNING_WORKER_ENV_FILE_V1,
        pid_file: "signing-worker.pid",
        stdout_file: "signing-worker.stdout.log",
        stderr_file: "signing-worker.stderr.log",
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalWorkerSpawnReceipt {
    pub role: LocalServiceRoleV1,
    pub role_label: &'static str,
    pub pid: u32,
    pub url: String,
    pub stdout_log: String,
    pub stderr_log: String,
}

pub struct ManagedChild {
    child: Child,
}

impl ManagedChild {
    pub fn spawn(
        worker_binary: &Path,
        root: &Path,
        spec: LocalWorkerProcessSpec,
    ) -> Result<(Self, LocalWorkerSpawnReceipt), Box<dyn std::error::Error>> {
        let config = read_worker_config(root, spec)?;
        let url = config.bind_url().to_owned();
        let logs = root.join(LOG_DIR);
        fs::create_dir_all(&logs)?;
        let stdout_log = logs.join(spec.stdout_file);
        let stderr_log = logs.join(spec.stderr_file);
        let stdout = File::create(&stdout_log)?;
        let stderr = File::create(&stderr_log)?;
        let mut command = Command::new(worker_binary);
        command
            .arg("--role")
            .arg(spec.role_label)
            .arg("--env")
            .arg(root.join(spec.env_file))
            .current_dir(root)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        #[cfg(unix)]
        command.process_group(0);
        let child = command.spawn()?;
        let pid = child.id();
        Ok((
            Self { child },
            LocalWorkerSpawnReceipt {
                role: spec.role,
                role_label: spec.role_label,
                pid,
                url,
                stdout_log: stdout_log.display().to_string(),
                stderr_log: stderr_log.display().to_string(),
            },
        ))
    }

    pub fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    pub fn disarm(self) {
        std::mem::forget(self);
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn normalize_root(root: PathBuf) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if root.as_os_str().is_empty() {
        return Err("local root must not be empty".into());
    }
    if root.is_absolute() {
        Ok(root)
    } else {
        Ok(std::env::current_dir()?.join(root))
    }
}

pub fn resolve_worker_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let binary = std::env::current_exe()?.with_file_name("router_ab_local_worker");
    if !binary.exists() {
        return Err(format!(
            "router_ab_local_worker was not found next to {}; build it first",
            std::env::current_exe()?.display()
        )
        .into());
    }
    Ok(binary)
}

pub fn read_worker_config(
    root: &Path,
    spec: LocalWorkerProcessSpec,
) -> Result<LocalWorkerRoleConfigV1, Box<dyn std::error::Error>> {
    let env_path = root.join(spec.env_file);
    let env_contents = fs::read_to_string(&env_path)
        .map_err(|error| format!("failed to read {}: {error}", env_path.display()))?;
    let config = parse_local_worker_role_config_for_role_v1(
        spec.role,
        parse_local_env_file_contents_v1(&env_contents)?,
    )?;
    Ok(config)
}

pub fn worker_bind_url(
    root: &Path,
    spec: LocalWorkerProcessSpec,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(read_worker_config(root, spec)?.bind_url().to_owned())
}

pub fn wait_for_managed_health(
    url: &str,
    child: &mut Child,
) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..100 {
        if child.try_wait()?.is_some() {
            return Err(format!("local worker at {url} exited before health check").into());
        }
        if get_health(url).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(format!("local worker at {url} did not become healthy").into())
}

pub fn wait_for_existing_health(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..100 {
        if get_health(url).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(format!("local worker at {url} did not become healthy").into())
}

pub fn get_health(base_url: &str) -> Result<String, Box<dyn std::error::Error>> {
    get_path(base_url, LOCAL_WORKER_HEALTH_PATH_V1)
}

pub fn get_path(base_url: &str, path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let authority = http_authority(base_url)?;
    let mut stream = TcpStream::connect(authority)?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nhost: {authority}\r\nconnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    if response.starts_with("HTTP/1.1 200 ") {
        Ok(response)
    } else {
        Err(format!("GET {path} response was not 200").into())
    }
}

pub fn post_json_to_path<T: Serialize>(
    base_url: &str,
    path: &str,
    body: &T,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    post_json_to_path_with_headers(base_url, path, body, &[])
}

pub fn post_json_to_path_with_authorization<T: Serialize>(
    base_url: &str,
    path: &str,
    authorization: &str,
    body: &T,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    post_json_to_path_with_headers(base_url, path, body, &[("authorization", authorization)])
}

pub fn post_json_to_path_with_headers<T: Serialize>(
    base_url: &str,
    path: &str,
    body: &T,
    headers: &[(&str, &str)],
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    let authority = http_authority(base_url)?;
    let body = serde_json::to_vec(body)?;
    let mut stream = TcpStream::connect(authority)?;
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nhost: {authority}\r\ncontent-type: application/json\r\n",
    )?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(
        stream,
        "content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("response missing header terminator")?;
    let headers = std::str::from_utf8(&response[..header_end])?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("response missing status")?
        .parse::<u16>()?;
    Ok((
        status,
        String::from_utf8(response[header_end + 4..].to_vec())?,
    ))
}

pub fn write_materialized_envs_with_urls(
    root: &Path,
    seed: &[u8],
    urls: &LocalWorkerUrls,
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = local_env_materialization_plan_v1(seed)?;
    for directory in &plan.directories {
        fs::create_dir_all(root.join(directory))?;
    }
    for file in plan.files {
        let contents = file
            .contents
            .replace("http://127.0.0.1:9090", &urls.router)
            .replace("http://127.0.0.1:9091", &urls.deriver_a)
            .replace("http://127.0.0.1:9092", &urls.deriver_b)
            .replace("http://127.0.0.1:9093", &urls.signing_worker);
        let path = root.join(file.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalWorkerUrls {
    pub router: String,
    pub deriver_a: String,
    pub deriver_b: String,
    pub signing_worker: String,
}

impl LocalWorkerUrls {
    pub fn from_env(root: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let router = read_router_public_url(root)?;
        let deriver_a = worker_bind_url(root, LOCAL_WORKER_PROCESS_SPECS[0])?;
        let deriver_b = worker_bind_url(root, LOCAL_WORKER_PROCESS_SPECS[1])?;
        let signing_worker = worker_bind_url(root, LOCAL_WORKER_PROCESS_SPECS[2])?;
        Ok(Self {
            router,
            deriver_a,
            deriver_b,
            signing_worker,
        })
    }
}

fn read_router_public_url(root: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let env_path = root.join(LOCAL_ROUTER_ENV_FILE_V1);
    let env_contents = fs::read_to_string(&env_path)
        .map_err(|error| format!("failed to read {}: {error}", env_path.display()))?;
    let config = parse_local_worker_role_config_for_role_v1(
        LocalServiceRoleV1::Router,
        parse_local_env_file_contents_v1(&env_contents)?,
    )?;
    Ok(config.bind_url().to_owned())
}

pub fn ephemeral_root(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path =
        std::env::temp_dir().join(format!("router-ab-{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path)?;
    Ok(path)
}

pub fn free_port_url() -> Result<String, Box<dyn std::error::Error>> {
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    Ok(format!("http://127.0.0.1:{port}"))
}

pub fn pid_path(root: &Path, spec: LocalWorkerProcessSpec) -> PathBuf {
    root.join(PID_DIR).join(spec.pid_file)
}

pub fn write_pid(root: &Path, spec: LocalWorkerProcessSpec, pid: u32) -> std::io::Result<()> {
    fs::create_dir_all(root.join(PID_DIR))?;
    fs::write(pid_path(root, spec), format!("{pid}\n"))
}

pub fn read_pid(
    root: &Path,
    spec: LocalWorkerProcessSpec,
) -> Result<Option<u32>, Box<dyn std::error::Error>> {
    let path = pid_path(root, spec);
    if !path.exists() {
        return Ok(None);
    }
    let pid = fs::read_to_string(&path)?
        .trim()
        .parse::<u32>()
        .map_err(|error| format!("invalid pid file {}: {error}", path.display()))?;
    Ok(Some(pid))
}

pub fn remove_pid(root: &Path, spec: LocalWorkerProcessSpec) -> std::io::Result<()> {
    let path = pid_path(root, spec);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub fn terminate_pid(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("kill -TERM {pid} exited with {status}").into())
    }
}

pub fn assert_worker_binary_bindable(
    root: &Path,
    spec: LocalWorkerProcessSpec,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = read_worker_config(root, spec)?;
    let _ = local_worker_bind_addr_v1(&config)?;
    Ok(())
}

fn http_authority(base_url: &str) -> Result<&str, Box<dyn std::error::Error>> {
    base_url
        .strip_prefix("http://")
        .ok_or_else(|| format!("URL must use http://, received {base_url}").into())
}
