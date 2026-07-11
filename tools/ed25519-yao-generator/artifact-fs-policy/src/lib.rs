#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![doc = "Descriptor-only host filesystem policy for benchmark artifacts."]

use core::fmt;
use std::os::fd::AsFd;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("the artifact filesystem policy supports only Linux and macOS");

#[cfg(target_os = "linux")]
mod platform {
    use std::io;
    use std::os::fd::BorrowedFd;

    use super::ArtifactFilesystemPolicyError;

    const EXT_SUPER_MAGIC: u64 = 0x0000_ef53;
    const TMPFS_MAGIC: u64 = 0x0102_1994;
    const ZFS_SUPER_MAGIC: u64 = 0x2fc1_2fc1;
    const UBIFS_SUPER_MAGIC: u64 = 0x2405_1905;
    const JFS_SUPER_MAGIC: u64 = 0x3153_464a;
    const XFS_SUPER_MAGIC: u64 = 0x5846_5342;
    const RAMFS_MAGIC: u64 = 0x8584_58f6;
    const BTRFS_SUPER_MAGIC: u64 = 0x9123_683e;
    const F2FS_SUPER_MAGIC: u64 = 0xf2f5_2010;
    const MAX_XATTR_LIST_BYTES: usize = 64 * 1024;
    const XATTR_READ_ATTEMPTS: usize = 3;
    const ACL_XATTR_NAMES: [&[u8]; 6] = [
        b"system.posix_acl_access",
        b"system.posix_acl_default",
        b"system.nfs4_acl",
        b"security.NTACL",
        b"trusted.SGI_ACL_FILE",
        b"trusted.SGI_ACL_DEFAULT",
    ];

    pub(super) fn validate(
        descriptor: BorrowedFd<'_>,
    ) -> Result<(), ArtifactFilesystemPolicyError> {
        let filesystem = rustix::fs::fstatfs(descriptor)
            .map_err(|error| ArtifactFilesystemPolicyError::Inspection(error.into()))?;
        let identifier = filesystem.f_type as u64;
        if !is_allowed_local_filesystem(identifier) {
            return Err(ArtifactFilesystemPolicyError::UnsupportedFilesystem { identifier });
        }
        let attributes = list_extended_attributes(descriptor)
            .map_err(ArtifactFilesystemPolicyError::Inspection)?;
        if contains_acl_attribute(&attributes) {
            return Err(ArtifactFilesystemPolicyError::AuthorityExpandingAcl);
        }
        Ok(())
    }

    pub(super) const fn is_allowed_local_filesystem(identifier: u64) -> bool {
        matches!(
            identifier,
            EXT_SUPER_MAGIC
                | TMPFS_MAGIC
                | ZFS_SUPER_MAGIC
                | UBIFS_SUPER_MAGIC
                | JFS_SUPER_MAGIC
                | XFS_SUPER_MAGIC
                | RAMFS_MAGIC
                | BTRFS_SUPER_MAGIC
                | F2FS_SUPER_MAGIC
        )
    }

    pub(super) fn contains_acl_attribute(attributes: &[u8]) -> bool {
        attributes
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
            .any(|name| ACL_XATTR_NAMES.contains(&name))
    }

    fn list_extended_attributes(descriptor: BorrowedFd<'_>) -> io::Result<Vec<u8>> {
        for _ in 0..XATTR_READ_ATTEMPTS {
            let required = rustix::fs::flistxattr(descriptor, &mut [])?;
            if required > MAX_XATTR_LIST_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "extended-attribute list exceeds the policy bound",
                ));
            }
            let mut attributes = vec![0_u8; required];
            match rustix::fs::flistxattr(descriptor, &mut attributes) {
                Ok(actual) => {
                    attributes.truncate(actual);
                    return Ok(attributes);
                }
                Err(error) if error == rustix::io::Errno::RANGE => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "extended-attribute list changed during inspection",
        ))
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use core::ffi::c_void;
    use std::io;
    use std::os::fd::{AsRawFd, BorrowedFd};
    use std::ptr::NonNull;

    use super::ArtifactFilesystemPolicyError;

    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    const ACL_MAX_ENTRIES: libc::c_int = 128;
    const ACL_EXTENDED_ALLOW: libc::c_int = 1;
    const ACL_EXTENDED_DENY: libc::c_int = 2;

    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> *mut c_void;
        fn acl_get_entry(
            acl: *mut c_void,
            entry_id: libc::c_int,
            entry: *mut *mut c_void,
        ) -> libc::c_int;
        fn acl_get_tag_type(entry: *mut c_void, tag_type: *mut libc::c_int) -> libc::c_int;
        fn acl_free(object: *mut c_void) -> libc::c_int;
    }

    pub(super) fn validate(
        descriptor: BorrowedFd<'_>,
    ) -> Result<(), ArtifactFilesystemPolicyError> {
        let filesystem = rustix::fs::fstatfs(descriptor)
            .map_err(|error| ArtifactFilesystemPolicyError::Inspection(error.into()))?;
        if filesystem.f_flags & libc::MNT_LOCAL as u32 == 0 {
            return Err(ArtifactFilesystemPolicyError::UnsupportedFilesystem {
                identifier: filesystem.f_type as u64,
            });
        }
        if descriptor_has_authority_expanding_acl(descriptor)
            .map_err(ArtifactFilesystemPolicyError::Inspection)?
        {
            return Err(ArtifactFilesystemPolicyError::AuthorityExpandingAcl);
        }
        Ok(())
    }

    fn descriptor_has_authority_expanding_acl(descriptor: BorrowedFd<'_>) -> io::Result<bool> {
        // SAFETY: `__error` returns the calling thread's valid errno pointer.
        unsafe {
            *libc::__error() = 0;
        }
        // SAFETY: The borrowed descriptor remains open for this call and the ACL type is the
        // macOS `ACL_TYPE_EXTENDED` ABI value. A non-null result is owned and freed below.
        let acl = unsafe { acl_get_fd_np(descriptor.as_raw_fd(), ACL_TYPE_EXTENDED) };
        let Some(acl) = NonNull::new(acl) else {
            // SAFETY: No function call occurs between `acl_get_fd_np` and this thread-local read.
            let errno = unsafe { *libc::__error() };
            // APFS reports an absent extended ACL as either errno 0 or `ENOENT`.
            return if errno == 0 || errno == libc::ENOENT {
                Ok(false)
            } else {
                Err(io::Error::from_raw_os_error(errno))
            };
        };
        let acl = OwnedAcl(acl);
        acl_has_allow_entry(acl.0)
    }

    fn acl_has_allow_entry(acl: NonNull<c_void>) -> io::Result<bool> {
        for index in 0..ACL_MAX_ENTRIES {
            let mut entry = core::ptr::null_mut();
            // SAFETY: `acl` is a live object returned by `acl_get_fd_np`; the entry index is
            // bounded by the macOS `ACL_MAX_ENTRIES` ABI and `entry` is valid output storage.
            let result = unsafe { acl_get_entry(acl.as_ptr(), index, &mut entry) };
            if result == -1 {
                // macOS reports the first index beyond the ACL as `EINVAL`.
                let errno = unsafe { *libc::__error() };
                return if errno == libc::EINVAL {
                    Ok(false)
                } else {
                    Err(io::Error::from_raw_os_error(errno))
                };
            }
            if result != 0 || entry.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ACL entry enumeration returned an invalid result",
                ));
            }
            let mut tag_type = 0;
            // SAFETY: `entry` was returned by a successful `acl_get_entry` call for the live ACL,
            // and `tag_type` is valid output storage.
            if unsafe { acl_get_tag_type(entry, &mut tag_type) } != 0 {
                return Err(io::Error::last_os_error());
            }
            match tag_type {
                ACL_EXTENDED_ALLOW => return Ok(true),
                ACL_EXTENDED_DENY => {}
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "extended ACL contains an unknown entry tag",
                    ));
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "extended ACL exceeds the platform entry bound",
        ))
    }

    struct OwnedAcl(NonNull<c_void>);

    impl Drop for OwnedAcl {
        fn drop(&mut self) {
            // SAFETY: The pointer came from a successful `acl_get_fd_np` call and this guard owns
            // it exactly once. `acl_free` does not retain the pointer.
            let _ = unsafe { acl_free(self.0.as_ptr()) };
        }
    }

    #[cfg(test)]
    pub(super) const fn mount_flags_are_local(flags: u32) -> bool {
        flags & libc::MNT_LOCAL as u32 != 0
    }
}

/// Failure to establish the artifact filesystem security policy.
#[derive(Debug)]
pub enum ArtifactFilesystemPolicyError {
    /// The descriptor is backed by a remote or unrecognized filesystem.
    UnsupportedFilesystem {
        /// Platform filesystem identifier returned by `fstatfs`.
        identifier: u64,
    },
    /// An access-control list grants authority beyond the checked mode bits.
    AuthorityExpandingAcl,
    /// Descriptor metadata or ACL inspection failed.
    Inspection(std::io::Error),
}

impl fmt::Display for ArtifactFilesystemPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFilesystem { identifier } => write!(
                formatter,
                "filesystem identifier 0x{identifier:016x} is remote or unsupported"
            ),
            Self::AuthorityExpandingAcl => {
                formatter.write_str("descriptor has an authority-expanding access-control list")
            }
            Self::Inspection(error) => {
                write!(formatter, "filesystem policy inspection failed: {error}")
            }
        }
    }
}

impl std::error::Error for ArtifactFilesystemPolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inspection(error) => Some(error),
            Self::UnsupportedFilesystem { .. } | Self::AuthorityExpandingAcl => None,
        }
    }
}

/// Requires a local supported filesystem and no ACL authority beyond mode bits.
pub fn validate_artifact_descriptor<Fd: AsFd>(
    descriptor: Fd,
) -> Result<(), ArtifactFilesystemPolicyError> {
    platform::validate(descriptor.as_fd())
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    #[cfg(target_os = "macos")]
    use std::fs::{self, OpenOptions};
    #[cfg(target_os = "macos")]
    use std::path::PathBuf;
    #[cfg(target_os = "macos")]
    use std::process::Command;
    #[cfg(target_os = "macos")]
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::validate_artifact_descriptor;
    #[cfg(target_os = "macos")]
    use super::ArtifactFilesystemPolicyError;

    #[cfg(target_os = "macos")]
    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn current_temporary_filesystem_is_accepted() {
        let directory = File::open(std::env::temp_dir()).expect("temporary directory opens");
        validate_artifact_descriptor(&directory).expect("temporary filesystem meets policy");
    }

    #[test]
    fn remote_and_unknown_filesystem_identifiers_are_rejected() {
        #[cfg(target_os = "linux")]
        {
            assert!(!super::platform::is_allowed_local_filesystem(0x0000_6969));
            assert!(!super::platform::is_allowed_local_filesystem(0xff53_4d42));
            assert!(!super::platform::is_allowed_local_filesystem(0xdead_beef));
        }
        #[cfg(target_os = "macos")]
        {
            assert!(!super::platform::mount_flags_are_local(0));
            assert!(super::platform::mount_flags_are_local(
                libc::MNT_LOCAL as u32
            ));
        }
    }

    #[test]
    fn platform_acl_representation_is_rejected() {
        #[cfg(target_os = "linux")]
        {
            assert!(super::platform::contains_acl_attribute(
                b"user.note\0system.posix_acl_access\0"
            ));
            assert!(super::platform::contains_acl_attribute(
                b"system.nfs4_acl\0"
            ));
            assert!(!super::platform::contains_acl_attribute(
                b"user.note\0security.selinux\0"
            ));
        }
        #[cfg(target_os = "macos")]
        {
            let artifact = TempArtifact::create();
            let status = Command::new("chmod")
                .args(["+a", "everyone deny write"])
                .arg(&artifact.path)
                .status()
                .expect("macOS chmod runs");
            assert!(status.success());
            let file = File::open(&artifact.path).expect("ACL fixture opens");
            validate_artifact_descriptor(file).expect("deny-only ACL does not expand authority");

            let status = Command::new("chmod")
                .args(["-N"])
                .arg(&artifact.path)
                .status()
                .expect("macOS ACL removal runs");
            assert!(status.success());
            let status = Command::new("chmod")
                .args(["+a", "everyone allow read"])
                .arg(&artifact.path)
                .status()
                .expect("macOS chmod runs");
            assert!(status.success());
            let file = File::open(&artifact.path).expect("ACL fixture reopens");
            assert!(matches!(
                validate_artifact_descriptor(file),
                Err(ArtifactFilesystemPolicyError::AuthorityExpandingAcl)
            ));
        }
    }

    #[cfg(target_os = "macos")]
    struct TempArtifact {
        path: PathBuf,
    }

    #[cfg(target_os = "macos")]
    impl TempArtifact {
        fn create() -> Self {
            for _ in 0..16 {
                let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "ed25519-yao-artifact-fs-policy-{}-{id}",
                    std::process::id()
                ));
                match OpenOptions::new().write(true).create_new(true).open(&path) {
                    Ok(_) => return Self { path },
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("ACL fixture is created: {error}"),
                }
            }
            panic!("ACL fixture name attempts are exhausted")
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for TempArtifact {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
