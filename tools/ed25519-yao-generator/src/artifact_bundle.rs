use core::fmt;
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use ed25519_yao_artifact_fs_policy::{validate_artifact_descriptor, ArtifactFilesystemPolicyError};
use rustix::fs::{AtFlags, Dir, Mode, OFlags, RenameFlags};
use sha2::{Digest, Sha256};

use crate::{
    compile_fixed_sha512_32_v1, compile_provisional_activation_core_v1,
    compile_provisional_export_core_v1,
};

const PROVISIONAL_ARTIFACT_BUNDLE_MAGIC_V1: &[u8; 8] = b"EYAOBA01";
const PROVISIONAL_ARTIFACT_ENTRY_COUNT_V1: usize = 6;
const ARTIFACT_STAGING_PREFIX: &str = ".ed25519-yao-phase2a-bundle.tmp-";
const ARTIFACT_STAGING_ATTEMPTS: usize = 16;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("Phase 2A artifact filesystem I/O supports only Linux and macOS");

/// Fixed SHA-512/32 canonical IR filename in a provisional bundle.
pub const PROVISIONAL_ARTIFACT_SHA512_IR_FILE_V1: &str = "sha512-fixed32.ir.bin";
/// Fixed SHA-512/32 canonical schedule filename in a provisional bundle.
pub const PROVISIONAL_ARTIFACT_SHA512_SCHEDULE_FILE_V1: &str = "sha512-fixed32.schedule.bin";
/// Provisional activation-core canonical IR filename.
pub const PROVISIONAL_ARTIFACT_ACTIVATION_IR_FILE_V1: &str = "activation.ir.bin";
/// Provisional activation-core canonical schedule filename.
pub const PROVISIONAL_ARTIFACT_ACTIVATION_SCHEDULE_FILE_V1: &str = "activation.schedule.bin";
/// Provisional export-core canonical IR filename.
pub const PROVISIONAL_ARTIFACT_EXPORT_IR_FILE_V1: &str = "export.ir.bin";
/// Provisional export-core canonical schedule filename.
pub const PROVISIONAL_ARTIFACT_EXPORT_SCHEDULE_FILE_V1: &str = "export.schedule.bin";
/// Canonical provisional bundle-index filename.
pub const PROVISIONAL_ARTIFACT_BUNDLE_INDEX_FILE_V1: &str = "ed25519-yao-phase2a-bundle-v1.bin";

/// SHA-256 identity of one provisional artifact file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisionalArtifactFileDigest32V1([u8; 32]);

impl ProvisionalArtifactFileDigest32V1 {
    /// Exposes public digest bytes for reproducibility checks.
    pub const fn expose_public_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// SHA-256 identity of the canonical provisional bundle index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisionalArtifactBundleDigest32V1([u8; 32]);

impl ProvisionalArtifactBundleDigest32V1 {
    /// Exposes public digest bytes for reproducibility checks.
    pub const fn expose_public_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// One fixed, generator-produced provisional binary artifact.
pub struct ProvisionalArtifactBundleEntryV1 {
    tag: u8,
    filename: &'static str,
    bytes: Vec<u8>,
    digest: ProvisionalArtifactFileDigest32V1,
}

impl ProvisionalArtifactBundleEntryV1 {
    /// Fixed entry tag encoded in the bundle index.
    pub const fn tag(&self) -> u8 {
        self.tag
    }

    /// Fixed repository-independent artifact filename.
    pub const fn filename(&self) -> &'static str {
        self.filename
    }

    /// Exact canonical artifact bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// SHA-256 over the exact artifact bytes.
    pub const fn digest(&self) -> ProvisionalArtifactFileDigest32V1 {
        self.digest
    }
}

/// Complete generator-only Phase 2A artifact bundle.
pub struct ProvisionalArtifactBundleV1 {
    entries: [ProvisionalArtifactBundleEntryV1; PROVISIONAL_ARTIFACT_ENTRY_COUNT_V1],
    index: Vec<u8>,
    digest: ProvisionalArtifactBundleDigest32V1,
}

impl ProvisionalArtifactBundleV1 {
    /// Returns all six entries in fixed tag order.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = &ProvisionalArtifactBundleEntryV1> {
        self.entries.iter()
    }

    /// Returns the exact canonical bundle-index bytes.
    pub fn canonical_index(&self) -> &[u8] {
        &self.index
    }

    /// SHA-256 identity of the canonical bundle index.
    pub const fn digest(&self) -> ProvisionalArtifactBundleDigest32V1 {
        self.digest
    }

    /// Atomically publishes the six artifacts and index, or checks an exact existing bundle.
    pub fn emit_to(&self, output_dir: &Path) -> Result<(), ProvisionalArtifactBundleErrorV1> {
        let (parent, target_name) = open_parent_directory(output_dir)?;
        if let Some(existing) = open_bundle_directory_at(&parent, &target_name, output_dir)? {
            return self.check_open_directory(&existing, output_dir);
        }

        let mut staging = StagingDirectory::create(parent, output_dir)?;
        for entry in &self.entries {
            write_new_file(&staging.directory, output_dir, entry.filename, &entry.bytes)?;
        }
        write_new_file(
            &staging.directory,
            output_dir,
            PROVISIONAL_ARTIFACT_BUNDLE_INDEX_FILE_V1,
            &self.index,
        )?;
        rustix::fs::fsync(&staging.directory)
            .map_err(|error| rustix_io_error("sync staging directory", output_dir, error))?;
        self.check_open_directory(&staging.directory, output_dir)?;

        match staging.publish(&target_name) {
            Ok(()) => Ok(()),
            Err(error) if error == rustix::io::Errno::EXIST => {
                let existing = open_bundle_directory_at(&staging.parent, &target_name, output_dir)?
                    .ok_or_else(|| {
                        io_error(
                            "open concurrently published bundle",
                            output_dir,
                            std::io::Error::new(
                                std::io::ErrorKind::NotFound,
                                "bundle disappeared after no-replace publication",
                            ),
                        )
                    })?;
                self.check_open_directory(&existing, output_dir)
            }
            Err(error) => Err(rustix_io_error(
                "atomically publish artifact bundle",
                output_dir,
                error,
            )),
        }
    }

    /// Checks an emitted directory byte for byte and rejects missing or extra files.
    pub fn check_directory(
        &self,
        input_dir: &Path,
    ) -> Result<(), ProvisionalArtifactBundleErrorV1> {
        let directory = open_directory_path(input_dir)?;
        self.check_open_directory(&directory, input_dir)
    }

    fn check_open_directory(
        &self,
        directory: &OwnedFd,
        display_path: &Path,
    ) -> Result<(), ProvisionalArtifactBundleErrorV1> {
        validate_artifact_directory(directory, display_path)?;
        let expected = expected_filenames();
        check_directory_entries(directory, display_path, &expected)?;
        for entry in &self.entries {
            check_file(directory, display_path, entry.filename, &entry.bytes)?;
        }
        check_file(
            directory,
            display_path,
            PROVISIONAL_ARTIFACT_BUNDLE_INDEX_FILE_V1,
            &self.index,
        )?;
        check_directory_entries(directory, display_path, &expected)
    }
}

/// Failure while emitting or checking provisional artifacts.
#[derive(Debug)]
pub enum ProvisionalArtifactBundleErrorV1 {
    /// The selected path is not a normalized Linux/macOS path.
    InvalidPath(PathBuf),
    /// A path component permits an untrusted directory-namespace writer.
    UnsafeNamespaceDirectory(PathBuf),
    /// The artifact directory has unsafe ownership or write permissions.
    UnsafeArtifactDirectory(PathBuf),
    /// An artifact file has unsafe ownership or write permissions.
    UnsafeArtifactFile(String),
    /// A descriptor is backed by a remote or unsupported filesystem.
    UnsupportedArtifactFilesystem(PathBuf),
    /// A descriptor has an ACL that expands authority beyond mode bits.
    AuthorityExpandingArtifactAcl(PathBuf),
    /// The selected path is not a directory.
    NotDirectory(PathBuf),
    /// An emitted file is absent.
    MissingFile(&'static str),
    /// An unrecognized directory entry is present.
    UnexpectedFile(String),
    /// An expected filename is occupied by a directory, symlink, or special file.
    NonRegularFile(String),
    /// An expected file has another hardlink.
    MultipleLinks(String),
    /// An expected file changed while its descriptor was being read.
    ConcurrentMutation(String),
    /// One file differs from the deterministic generator output.
    ByteMismatch(&'static str),
    /// A filesystem operation failed.
    Io {
        /// Stable operation label.
        operation: &'static str,
        /// Affected path.
        path: PathBuf,
        /// Original I/O error.
        source: std::io::Error,
    },
}

impl fmt::Display for ProvisionalArtifactBundleErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(path) => write!(
                formatter,
                "{} is not a normalized artifact bundle path",
                path.display()
            ),
            Self::UnsafeNamespaceDirectory(path) => write!(
                formatter,
                "{} is not a protected artifact namespace directory",
                path.display()
            ),
            Self::UnsafeArtifactDirectory(path) => write!(
                formatter,
                "{} has unsafe artifact-directory ownership or permissions",
                path.display()
            ),
            Self::UnsafeArtifactFile(filename) => write!(
                formatter,
                "artifact entry {filename} has unsafe ownership or permissions"
            ),
            Self::UnsupportedArtifactFilesystem(path) => write!(
                formatter,
                "{} is on a remote or unsupported artifact filesystem",
                path.display()
            ),
            Self::AuthorityExpandingArtifactAcl(path) => write!(
                formatter,
                "{} has an authority-expanding artifact access-control list",
                path.display()
            ),
            Self::NotDirectory(path) => write!(formatter, "{} is not a directory", path.display()),
            Self::MissingFile(filename) => write!(formatter, "missing artifact file {filename}"),
            Self::UnexpectedFile(filename) => {
                write!(formatter, "unexpected artifact file {filename}")
            }
            Self::NonRegularFile(filename) => {
                write!(formatter, "artifact entry {filename} is not a regular file")
            }
            Self::MultipleLinks(filename) => {
                write!(
                    formatter,
                    "artifact entry {filename} has multiple hardlinks"
                )
            }
            Self::ConcurrentMutation(filename) => {
                write!(
                    formatter,
                    "artifact entry {filename} changed while being read"
                )
            }
            Self::ByteMismatch(filename) => {
                write!(
                    formatter,
                    "artifact file {filename} differs from canonical bytes"
                )
            }
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "failed to {operation} at {}: {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ProvisionalArtifactBundleErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Compiles all six provisional artifacts and their canonical bundle index.
pub fn build_provisional_artifact_bundle_v1() -> ProvisionalArtifactBundleV1 {
    let sha = compile_fixed_sha512_32_v1();
    let activation = compile_provisional_activation_core_v1();
    let export = compile_provisional_export_core_v1();
    let entries = [
        bundle_entry(
            1,
            PROVISIONAL_ARTIFACT_SHA512_IR_FILE_V1,
            sha.canonical_encoding(),
        ),
        bundle_entry(
            2,
            PROVISIONAL_ARTIFACT_SHA512_SCHEDULE_FILE_V1,
            sha.canonical_schedule_encoding(),
        ),
        bundle_entry(
            3,
            PROVISIONAL_ARTIFACT_ACTIVATION_IR_FILE_V1,
            activation.canonical_encoding(),
        ),
        bundle_entry(
            4,
            PROVISIONAL_ARTIFACT_ACTIVATION_SCHEDULE_FILE_V1,
            activation.canonical_schedule_encoding(),
        ),
        bundle_entry(
            5,
            PROVISIONAL_ARTIFACT_EXPORT_IR_FILE_V1,
            export.canonical_encoding(),
        ),
        bundle_entry(
            6,
            PROVISIONAL_ARTIFACT_EXPORT_SCHEDULE_FILE_V1,
            export.canonical_schedule_encoding(),
        ),
    ];
    let index = encode_index(&entries);
    let digest = ProvisionalArtifactBundleDigest32V1(Sha256::digest(&index).into());
    ProvisionalArtifactBundleV1 {
        entries,
        index,
        digest,
    }
}

fn bundle_entry(tag: u8, filename: &'static str, bytes: &[u8]) -> ProvisionalArtifactBundleEntryV1 {
    ProvisionalArtifactBundleEntryV1 {
        tag,
        filename,
        bytes: bytes.to_vec(),
        digest: ProvisionalArtifactFileDigest32V1(Sha256::digest(bytes).into()),
    }
}

fn encode_index(
    entries: &[ProvisionalArtifactBundleEntryV1; PROVISIONAL_ARTIFACT_ENTRY_COUNT_V1],
) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(PROVISIONAL_ARTIFACT_BUNDLE_MAGIC_V1);
    encoded.push(PROVISIONAL_ARTIFACT_ENTRY_COUNT_V1 as u8);
    for entry in entries {
        encoded.push(entry.tag);
        let filename_len = u16::try_from(entry.filename.len()).expect("fixed filename fits u16");
        encoded.extend_from_slice(&filename_len.to_be_bytes());
        encoded.extend_from_slice(entry.filename.as_bytes());
        let byte_len = u64::try_from(entry.bytes.len()).expect("artifact length fits u64");
        encoded.extend_from_slice(&byte_len.to_be_bytes());
        encoded.extend_from_slice(&entry.digest.0);
    }
    encoded
}

fn expected_filenames() -> BTreeSet<&'static str> {
    [
        PROVISIONAL_ARTIFACT_SHA512_IR_FILE_V1,
        PROVISIONAL_ARTIFACT_SHA512_SCHEDULE_FILE_V1,
        PROVISIONAL_ARTIFACT_ACTIVATION_IR_FILE_V1,
        PROVISIONAL_ARTIFACT_ACTIVATION_SCHEDULE_FILE_V1,
        PROVISIONAL_ARTIFACT_EXPORT_IR_FILE_V1,
        PROVISIONAL_ARTIFACT_EXPORT_SCHEDULE_FILE_V1,
        PROVISIONAL_ARTIFACT_BUNDLE_INDEX_FILE_V1,
    ]
    .into_iter()
    .collect()
}

fn directory_open_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn open_directory_path(path: &Path) -> Result<OwnedFd, ProvisionalArtifactBundleErrorV1> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(ProvisionalArtifactBundleErrorV1::InvalidPath(
            path.to_path_buf(),
        ));
    }
    let anchor = if path.is_absolute() { "/" } else { "." };
    let mut directory = rustix::fs::open(anchor, directory_open_flags(), Mode::empty())
        .map_err(|error| rustix_io_error("open artifact path anchor", path, error))?;
    let mut resolved = PathBuf::from(anchor);
    validate_namespace_directory(&directory, &resolved)?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                let next =
                    rustix::fs::openat(&directory, name, directory_open_flags(), Mode::empty())
                        .map_err(|error| directory_open_error(path, error))?;
                resolved.push(name);
                validate_namespace_directory(&next, &resolved)?;
                directory = next;
            }
            Component::ParentDir | Component::Prefix(_) => unreachable!("components prevalidated"),
        }
    }
    Ok(directory)
}

fn open_parent_directory(
    target: &Path,
) -> Result<(OwnedFd, std::ffi::OsString), ProvisionalArtifactBundleErrorV1> {
    let target_name = target
        .file_name()
        .ok_or_else(|| ProvisionalArtifactBundleErrorV1::InvalidPath(target.to_path_buf()))?;
    let parent_path = target.parent().unwrap_or_else(|| Path::new("."));
    let parent = open_directory_path(parent_path)?;
    Ok((parent, target_name.to_os_string()))
}

fn validate_namespace_directory(
    directory: &OwnedFd,
    display_path: &Path,
) -> Result<(), ProvisionalArtifactBundleErrorV1> {
    validate_filesystem_policy(directory, display_path)?;
    let metadata = rustix::fs::fstat(directory).map_err(|error| {
        rustix_io_error("inspect artifact namespace directory", display_path, error)
    })?;
    let mode = Mode::from_raw_mode(metadata.st_mode);
    let current_uid = rustix::process::geteuid().as_raw();
    let shared_write = mode.intersects(Mode::WGRP | Mode::WOTH);
    if !trusted_owner(metadata.st_uid, current_uid) || (shared_write && !mode.contains(Mode::SVTX))
    {
        return Err(ProvisionalArtifactBundleErrorV1::UnsafeNamespaceDirectory(
            display_path.to_path_buf(),
        ));
    }
    Ok(())
}

fn validate_artifact_directory(
    directory: &OwnedFd,
    display_path: &Path,
) -> Result<(), ProvisionalArtifactBundleErrorV1> {
    validate_filesystem_policy(directory, display_path)?;
    let metadata = rustix::fs::fstat(directory)
        .map_err(|error| rustix_io_error("inspect artifact directory", display_path, error))?;
    let mode = Mode::from_raw_mode(metadata.st_mode);
    let current_uid = rustix::process::geteuid().as_raw();
    if !trusted_owner(metadata.st_uid, current_uid) || mode.intersects(Mode::WGRP | Mode::WOTH) {
        return Err(ProvisionalArtifactBundleErrorV1::UnsafeArtifactDirectory(
            display_path.to_path_buf(),
        ));
    }
    Ok(())
}

const fn trusted_owner(owner_uid: u32, current_uid: u32) -> bool {
    owner_uid == 0 || owner_uid == current_uid
}

fn validate_filesystem_policy<Fd: std::os::fd::AsFd>(
    descriptor: Fd,
    display_path: &Path,
) -> Result<(), ProvisionalArtifactBundleErrorV1> {
    match validate_artifact_descriptor(descriptor) {
        Ok(()) => Ok(()),
        Err(ArtifactFilesystemPolicyError::UnsupportedFilesystem { .. }) => Err(
            ProvisionalArtifactBundleErrorV1::UnsupportedArtifactFilesystem(
                display_path.to_path_buf(),
            ),
        ),
        Err(ArtifactFilesystemPolicyError::AuthorityExpandingAcl) => Err(
            ProvisionalArtifactBundleErrorV1::AuthorityExpandingArtifactAcl(
                display_path.to_path_buf(),
            ),
        ),
        Err(ArtifactFilesystemPolicyError::Inspection(error)) => Err(io_error(
            "inspect artifact filesystem policy",
            display_path,
            error,
        )),
    }
}

fn open_bundle_directory_at(
    parent: &OwnedFd,
    target_name: &std::ffi::OsStr,
    display_path: &Path,
) -> Result<Option<OwnedFd>, ProvisionalArtifactBundleErrorV1> {
    match rustix::fs::openat(parent, target_name, directory_open_flags(), Mode::empty()) {
        Ok(directory) => Ok(Some(directory)),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(None),
        Err(error) if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::NOTDIR => {
            Err(ProvisionalArtifactBundleErrorV1::NotDirectory(
                display_path.to_path_buf(),
            ))
        }
        Err(error) => Err(rustix_io_error(
            "open artifact bundle directory",
            display_path,
            error,
        )),
    }
}

fn check_directory_entries(
    directory: &OwnedFd,
    display_path: &Path,
    expected: &BTreeSet<&'static str>,
) -> Result<(), ProvisionalArtifactBundleErrorV1> {
    let entries = Dir::read_from(directory)
        .map_err(|error| rustix_io_error("read artifact directory", display_path, error))?;
    let mut actual = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            rustix_io_error("read artifact directory entry", display_path, error)
        })?;
        let filename = entry.file_name().to_bytes();
        if filename == b"." || filename == b".." {
            continue;
        }
        let filename = std::str::from_utf8(filename).map_err(|_| {
            ProvisionalArtifactBundleErrorV1::UnexpectedFile(
                String::from_utf8_lossy(filename).into_owned(),
            )
        })?;
        if !expected.contains(filename) {
            return Err(ProvisionalArtifactBundleErrorV1::UnexpectedFile(
                filename.to_owned(),
            ));
        }
        actual.insert(filename.to_owned());
    }
    for filename in expected {
        if !actual.contains(*filename) {
            return Err(ProvisionalArtifactBundleErrorV1::MissingFile(filename));
        }
    }
    Ok(())
}

fn check_file(
    directory: &OwnedFd,
    display_directory: &Path,
    filename: &'static str,
    expected: &[u8],
) -> Result<(), ProvisionalArtifactBundleErrorV1> {
    let path = display_directory.join(filename);
    let descriptor = match rustix::fs::openat(
        directory,
        filename,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error == rustix::io::Errno::NOENT => {
            return Err(ProvisionalArtifactBundleErrorV1::MissingFile(filename));
        }
        Err(error) if error == rustix::io::Errno::LOOP => {
            return Err(ProvisionalArtifactBundleErrorV1::NonRegularFile(
                filename.to_owned(),
            ));
        }
        Err(error) => return Err(rustix_io_error("open artifact", &path, error)),
    };
    let mut file = fs::File::from(descriptor);
    let before = FileSnapshot::read(&file, filename, &path)?;
    if before.size != expected.len() as u64 {
        return Err(ProvisionalArtifactBundleErrorV1::ByteMismatch(filename));
    }
    let read_limit = expected
        .len()
        .checked_add(1)
        .expect("fixed artifact length permits a one-byte rejection sentinel");
    let mut actual = Vec::with_capacity(read_limit);
    Read::by_ref(&mut file)
        .take(read_limit as u64)
        .read_to_end(&mut actual)
        .map_err(|error| io_error("read bounded artifact", &path, error))?;
    let after = FileSnapshot::read(&file, filename, &path)?;
    if before != after {
        return Err(ProvisionalArtifactBundleErrorV1::ConcurrentMutation(
            filename.to_owned(),
        ));
    }
    if actual != expected {
        return Err(ProvisionalArtifactBundleErrorV1::ByteMismatch(filename));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileSnapshot {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    links: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileSnapshot {
    fn read(
        file: &fs::File,
        filename: &'static str,
        display_path: &Path,
    ) -> Result<Self, ProvisionalArtifactBundleErrorV1> {
        validate_filesystem_policy(file, display_path)?;
        let metadata = file
            .metadata()
            .map_err(|error| io_error("read artifact metadata", Path::new(filename), error))?;
        if !metadata.file_type().is_file() {
            return Err(ProvisionalArtifactBundleErrorV1::NonRegularFile(
                filename.to_owned(),
            ));
        }
        if metadata.nlink() != 1 {
            return Err(ProvisionalArtifactBundleErrorV1::MultipleLinks(
                filename.to_owned(),
            ));
        }
        let current_uid = rustix::process::geteuid().as_raw();
        if !trusted_owner(metadata.uid(), current_uid) || metadata.mode() & 0o022 != 0 {
            return Err(ProvisionalArtifactBundleErrorV1::UnsafeArtifactFile(
                filename.to_owned(),
            ));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            owner: metadata.uid(),
            links: metadata.nlink(),
            size: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }
}

fn write_new_file(
    directory: &OwnedFd,
    display_directory: &Path,
    filename: &'static str,
    bytes: &[u8],
) -> Result<(), ProvisionalArtifactBundleErrorV1> {
    let path = display_directory.join(filename);
    let descriptor = rustix::fs::openat(
        directory,
        filename,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|error| rustix_io_error("create artifact", &path, error))?;
    let mut file = fs::File::from(descriptor);
    file.write_all(bytes)
        .map_err(|error| io_error("write artifact", &path, error))?;
    file.sync_all()
        .map_err(|error| io_error("sync artifact", &path, error))?;
    let snapshot = FileSnapshot::read(&file, filename, &path)?;
    if snapshot.size != bytes.len() as u64 {
        return Err(ProvisionalArtifactBundleErrorV1::ConcurrentMutation(
            filename.to_owned(),
        ));
    }
    Ok(())
}

struct StagingDirectory {
    parent: OwnedFd,
    directory: OwnedFd,
    name: String,
    published: bool,
}

impl StagingDirectory {
    fn create(
        parent: OwnedFd,
        display_path: &Path,
    ) -> Result<Self, ProvisionalArtifactBundleErrorV1> {
        for _ in 0..ARTIFACT_STAGING_ATTEMPTS {
            let name = random_staging_name(display_path)?;
            match rustix::fs::mkdirat(&parent, name.as_str(), Mode::RWXU) {
                Ok(()) => {
                    let directory = match rustix::fs::openat(
                        &parent,
                        name.as_str(),
                        directory_open_flags(),
                        Mode::empty(),
                    ) {
                        Ok(directory) => directory,
                        Err(error) => {
                            let _ =
                                rustix::fs::unlinkat(&parent, name.as_str(), AtFlags::REMOVEDIR);
                            return Err(rustix_io_error(
                                "open staging directory",
                                display_path,
                                error,
                            ));
                        }
                    };
                    return Ok(Self {
                        parent,
                        directory,
                        name,
                        published: false,
                    });
                }
                Err(error) if error == rustix::io::Errno::EXIST => {}
                Err(error) => {
                    return Err(rustix_io_error(
                        "create staging directory",
                        display_path,
                        error,
                    ));
                }
            }
        }
        Err(io_error(
            "create unique staging directory",
            display_path,
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "exhausted staging-name attempts",
            ),
        ))
    }

    fn publish(&mut self, target_name: &std::ffi::OsStr) -> Result<(), rustix::io::Errno> {
        rustix::fs::renameat_with(
            &self.parent,
            self.name.as_str(),
            &self.parent,
            target_name,
            RenameFlags::NOREPLACE,
        )?;
        self.published = true;
        rustix::fs::fsync(&self.parent)
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        for filename in expected_filenames() {
            let _ = rustix::fs::unlinkat(&self.directory, filename, AtFlags::empty());
        }
        let _ = rustix::fs::unlinkat(&self.parent, self.name.as_str(), AtFlags::REMOVEDIR);
    }
}

fn random_staging_name(display_path: &Path) -> Result<String, ProvisionalArtifactBundleErrorV1> {
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random).map_err(|error| {
        io_error(
            "generate staging directory name",
            display_path,
            std::io::Error::other(error.to_string()),
        )
    })?;
    let mut name = String::with_capacity(ARTIFACT_STAGING_PREFIX.len() + random.len() * 2);
    name.push_str(ARTIFACT_STAGING_PREFIX);
    for byte in random {
        use core::fmt::Write as _;
        write!(name, "{byte:02x}").expect("writing to a String succeeds");
    }
    Ok(name)
}

fn directory_open_error(path: &Path, error: rustix::io::Errno) -> ProvisionalArtifactBundleErrorV1 {
    if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::NOTDIR {
        ProvisionalArtifactBundleErrorV1::NotDirectory(path.to_path_buf())
    } else {
        rustix_io_error("open artifact directory", path, error)
    }
}

fn rustix_io_error(
    operation: &'static str,
    path: &Path,
    source: rustix::io::Errno,
) -> ProvisionalArtifactBundleErrorV1 {
    io_error(operation, path, source.into())
}

fn io_error(
    operation: &'static str,
    path: &Path,
    source: std::io::Error,
) -> ProvisionalArtifactBundleErrorV1 {
    ProvisionalArtifactBundleErrorV1::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock follows Unix epoch")
                .as_nanos();
            let temporary_root = fs::canonicalize(std::env::temp_dir())
                .expect("test temporary root has a direct canonical path");
            let path = temporary_root.join(format!(
                "ed25519-yao-artifact-{label}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test directory is created");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn bundle_path(&self) -> PathBuf {
            self.0.join("bundle")
        }

        fn entry_names(&self) -> BTreeSet<String> {
            fs::read_dir(&self.0)
                .expect("test root is readable")
                .map(|entry| {
                    entry
                        .expect("test entry is readable")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect()
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn bundle_index_and_entry_order_are_frozen() {
        let bundle = build_provisional_artifact_bundle_v1();
        assert_eq!(&bundle.canonical_index()[..8], b"EYAOBA01");
        assert_eq!(bundle.canonical_index()[8], 6);
        assert_eq!(
            bundle
                .entries()
                .map(|entry| entry.tag())
                .collect::<Vec<_>>(),
            [1, 2, 3, 4, 5, 6]
        );
        assert_eq!(bundle.canonical_index().len(), 387);
        assert_eq!(
            bundle.digest().expose_public_bytes(),
            [
                0xaa, 0x62, 0xb8, 0x3b, 0x38, 0x16, 0x3b, 0xf8, 0x98, 0xc9, 0x00, 0x84, 0xf2, 0xeb,
                0x25, 0xdf, 0x1c, 0x95, 0xba, 0x41, 0x27, 0x4d, 0x0f, 0x78, 0x26, 0x25, 0x0f, 0x91,
                0x68, 0xb8, 0x0d, 0xb1,
            ]
        );
    }

    #[test]
    fn emitted_bundle_checks_idempotently_and_detects_mutation() {
        let bundle = build_provisional_artifact_bundle_v1();
        let root = TestDirectory::new("mutation");
        let output = root.bundle_path();
        let stale = root.path().join(format!("{ARTIFACT_STAGING_PREFIX}stale"));
        fs::create_dir(&stale).expect("stale staging directory is created");
        assert!(!output.exists());
        bundle
            .emit_to(&output)
            .expect("bundle publishes atomically");
        assert!(output.is_dir());
        assert!(stale.is_dir());
        assert_eq!(
            root.entry_names(),
            BTreeSet::from([
                "bundle".to_owned(),
                format!("{ARTIFACT_STAGING_PREFIX}stale")
            ])
        );
        bundle.emit_to(&output).expect("repeat emit is stable");
        bundle
            .check_directory(&output)
            .expect("emitted bundle checks");
        let mutation = output.join(PROVISIONAL_ARTIFACT_EXPORT_IR_FILE_V1);
        fs::write(&mutation, b"mutated").expect("test mutation writes");
        assert!(matches!(
            bundle.check_directory(&output),
            Err(ProvisionalArtifactBundleErrorV1::ByteMismatch(
                PROVISIONAL_ARTIFACT_EXPORT_IR_FILE_V1
            ))
        ));
        assert!(matches!(
            bundle.emit_to(&output),
            Err(ProvisionalArtifactBundleErrorV1::ByteMismatch(
                PROVISIONAL_ARTIFACT_EXPORT_IR_FILE_V1
            ))
        ));
        assert_eq!(fs::read(&mutation).expect("mutation remains"), b"mutated");
    }

    #[test]
    fn publisher_rejects_existing_empty_or_nondirectory_targets_without_mutation() {
        let bundle = build_provisional_artifact_bundle_v1();
        let root = TestDirectory::new("existing-target");
        let output = root.bundle_path();
        fs::create_dir(&output).expect("empty target directory is created");
        assert!(matches!(
            bundle.emit_to(&output),
            Err(ProvisionalArtifactBundleErrorV1::MissingFile(_))
        ));
        assert_eq!(
            fs::read_dir(&output)
                .expect("empty target remains readable")
                .count(),
            0
        );

        fs::remove_dir(&output).expect("empty target is removed");
        fs::write(&output, b"plain file").expect("plain target file writes");
        assert!(matches!(
            bundle.emit_to(&output),
            Err(ProvisionalArtifactBundleErrorV1::NotDirectory(_))
        ));
        assert_eq!(
            fs::read(&output).expect("plain target remains"),
            b"plain file"
        );
    }

    #[test]
    fn publisher_rejects_unprotected_shared_parent() {
        let bundle = build_provisional_artifact_bundle_v1();
        let root = TestDirectory::new("unsafe-parent");
        let parent = root.path().join("shared");
        fs::create_dir(&parent).expect("shared parent is created");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777))
            .expect("shared parent permissions are set");
        let output = parent.join("bundle");
        assert!(matches!(
            bundle.emit_to(&output),
            Err(ProvisionalArtifactBundleErrorV1::UnsafeNamespaceDirectory(
                _
            ))
        ));
        assert!(!output.exists());
    }

    #[test]
    fn checker_and_publisher_reject_unprotected_ancestor() {
        let bundle = build_provisional_artifact_bundle_v1();
        let root = TestDirectory::new("unsafe-ancestor");
        let ancestor = root.path().join("shared");
        let parent = ancestor.join("owned-parent");
        fs::create_dir(&ancestor).expect("ancestor is created");
        fs::create_dir(&parent).expect("parent is created");
        let existing = parent.join("existing-bundle");
        bundle
            .emit_to(&existing)
            .expect("bundle emits before permission change");
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o777))
            .expect("ancestor permissions are set");

        assert!(matches!(
            bundle.check_directory(&existing),
            Err(ProvisionalArtifactBundleErrorV1::UnsafeNamespaceDirectory(
                _
            ))
        ));
        let new_bundle = parent.join("new-bundle");
        assert!(matches!(
            bundle.emit_to(&new_bundle),
            Err(ProvisionalArtifactBundleErrorV1::UnsafeNamespaceDirectory(
                _
            ))
        ));
        assert!(!new_bundle.exists());
    }

    #[test]
    fn checker_rejects_writable_bundle_and_entry() {
        let bundle = build_provisional_artifact_bundle_v1();
        let root = TestDirectory::new("unsafe-artifact-permissions");
        let output = root.bundle_path();
        bundle.emit_to(&output).expect("bundle emits");

        fs::set_permissions(&output, fs::Permissions::from_mode(0o777))
            .expect("bundle permissions are set");
        assert!(matches!(
            bundle.check_directory(&output),
            Err(
                ProvisionalArtifactBundleErrorV1::UnsafeNamespaceDirectory(_)
                    | ProvisionalArtifactBundleErrorV1::UnsafeArtifactDirectory(_)
            )
        ));
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700))
            .expect("bundle permissions are restored");

        let entry = output.join(PROVISIONAL_ARTIFACT_EXPORT_IR_FILE_V1);
        fs::set_permissions(&entry, fs::Permissions::from_mode(0o666))
            .expect("entry permissions are set");
        assert!(matches!(
            bundle.check_directory(&output),
            Err(ProvisionalArtifactBundleErrorV1::UnsafeArtifactFile(_))
        ));
    }

    #[test]
    fn root_effective_uid_does_not_trust_another_owner() {
        assert!(!trusted_owner(501, 0));
        assert!(trusted_owner(0, 0));
        assert!(trusted_owner(501, 501));
    }

    #[test]
    fn checker_rejects_missing_extra_and_oversized_files() {
        let bundle = build_provisional_artifact_bundle_v1();
        let root = TestDirectory::new("shape");
        let output = root.bundle_path();
        bundle.emit_to(&output).expect("bundle emits");
        let index = output.join(PROVISIONAL_ARTIFACT_BUNDLE_INDEX_FILE_V1);
        fs::remove_file(&index).expect("index removal succeeds");
        assert!(matches!(
            bundle.check_directory(&output),
            Err(ProvisionalArtifactBundleErrorV1::MissingFile(
                PROVISIONAL_ARTIFACT_BUNDLE_INDEX_FILE_V1
            ))
        ));
        fs::write(&index, bundle.canonical_index()).expect("index restores");

        let extra = output.join("unexpected.bin");
        fs::write(&extra, b"extra").expect("extra file writes");
        assert!(matches!(
            bundle.check_directory(&output),
            Err(ProvisionalArtifactBundleErrorV1::UnexpectedFile(_))
        ));
        fs::remove_file(extra).expect("extra file removal succeeds");

        let expected_path = output.join(PROVISIONAL_ARTIFACT_EXPORT_IR_FILE_V1);
        let expected_len = fs::metadata(&expected_path)
            .expect("expected file metadata exists")
            .len();
        let oversized = fs::OpenOptions::new()
            .append(true)
            .open(&expected_path)
            .expect("expected file opens for append");
        oversized
            .set_len(expected_len + 1)
            .expect("expected file grows by one byte");
        assert!(matches!(
            bundle.check_directory(&output),
            Err(ProvisionalArtifactBundleErrorV1::ByteMismatch(
                PROVISIONAL_ARTIFACT_EXPORT_IR_FILE_V1
            ))
        ));
    }

    #[test]
    fn checker_and_publisher_reject_root_and_ancestor_symlinks() {
        let bundle = build_provisional_artifact_bundle_v1();
        let root = TestDirectory::new("directory-symlink");
        let real_parent = root.path().join("real-parent");
        fs::create_dir(&real_parent).expect("real parent is created");
        let output = real_parent.join("bundle");
        bundle.emit_to(&output).expect("bundle emits");

        let linked_root = root.path().join("linked-root");
        symlink(&output, &linked_root).expect("root symlink is created");
        assert!(matches!(
            bundle.check_directory(&linked_root),
            Err(ProvisionalArtifactBundleErrorV1::NotDirectory(_))
        ));
        assert!(matches!(
            bundle.emit_to(&linked_root),
            Err(ProvisionalArtifactBundleErrorV1::NotDirectory(_))
        ));

        let linked_parent = root.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).expect("ancestor symlink is created");
        let through_ancestor = linked_parent.join("bundle");
        assert!(matches!(
            bundle.check_directory(&through_ancestor),
            Err(ProvisionalArtifactBundleErrorV1::NotDirectory(_))
        ));
        assert!(matches!(
            bundle.emit_to(&linked_parent.join("new-bundle")),
            Err(ProvisionalArtifactBundleErrorV1::NotDirectory(_))
        ));
    }

    #[test]
    fn checker_and_publisher_reject_expected_symlinks_and_hardlinks() {
        let bundle = build_provisional_artifact_bundle_v1();
        let root = TestDirectory::new("entry-links");
        let output = root.bundle_path();
        bundle.emit_to(&output).expect("bundle emits");
        let expected_path = output.join(PROVISIONAL_ARTIFACT_EXPORT_IR_FILE_V1);
        let external = root.path().join("external.bin");
        fs::write(&external, b"external").expect("external file writes");

        fs::remove_file(&expected_path).expect("expected file removal succeeds");
        symlink(&external, &expected_path).expect("expected symlink is created");
        assert!(matches!(
            bundle.check_directory(&output),
            Err(ProvisionalArtifactBundleErrorV1::NonRegularFile(_))
        ));
        assert!(matches!(
            bundle.emit_to(&output),
            Err(ProvisionalArtifactBundleErrorV1::NonRegularFile(_))
        ));

        fs::remove_file(&expected_path).expect("expected symlink removal succeeds");
        let export = bundle
            .entries()
            .find(|entry| entry.filename() == PROVISIONAL_ARTIFACT_EXPORT_IR_FILE_V1)
            .expect("export entry exists");
        fs::write(&expected_path, export.bytes()).expect("expected file restores");
        fs::remove_file(&external).expect("external file removal succeeds");
        fs::hard_link(&expected_path, &external).expect("hardlink is created");
        assert!(matches!(
            bundle.check_directory(&output),
            Err(ProvisionalArtifactBundleErrorV1::MultipleLinks(_))
        ));
        assert!(matches!(
            bundle.emit_to(&output),
            Err(ProvisionalArtifactBundleErrorV1::MultipleLinks(_))
        ));
    }

    #[test]
    fn artifact_paths_reject_parent_components() {
        let bundle = build_provisional_artifact_bundle_v1();
        let root = TestDirectory::new("parent-component");
        let invalid = root.path().join("missing").join("..").join("bundle");
        assert!(matches!(
            bundle.emit_to(&invalid),
            Err(ProvisionalArtifactBundleErrorV1::InvalidPath(_))
        ));
    }
}
