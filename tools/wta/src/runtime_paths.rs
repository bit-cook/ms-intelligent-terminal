use std::path::PathBuf;
use std::sync::OnceLock;

/// Canonical on-disk root for all WTA runtime data (logs, the prompt
/// override directory, the agent-pane session index, the master-pipe
/// rendezvous file, hook-installer staging, …).
///
/// Layout depends on whether the current process has package identity:
///
///   * **Packaged** (the normal case — every production wta process runs
///     either as a conpty child of the packaged WindowsTerminal.exe or as
///     a master spawned in-package by SharedWta, so it inherits package
///     identity):
///         %LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalState\IntelligentTerminal\
///     This keeps WTA's data inside the package's private store — it is
///     cleaned up on uninstall, isolated between the dev-sideload family
///     (`IntelligentTerminal_rd9vj3e6a2mbr`) and the store family
///     (`Microsoft.IntelligentTerminal_8wekyb3d8bbwe`), and sits alongside
///     the WT app's own `settings.json` / `state.json` in `LocalState`.
///
///   * **Unpackaged** (dev builds run directly out of the Cargo target dir,
///     tests): falls back to the bare
///         %LOCALAPPDATA%\IntelligentTerminal\
///     This is the legacy location. Note such processes already fail COM
///     activation (0x80073D54), so they are not a supported production
///     configuration — the fallback exists only so logging / tests keep
///     working when run outside the package.
///
/// Resolution is cached: `intelligent_terminal_root` is called on every log
/// write, and querying package identity is a syscall, so we resolve once.
pub fn intelligent_terminal_root() -> Option<PathBuf> {
    static ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();
    ROOT.get_or_init(resolve_root).clone()
}

fn resolve_root() -> Option<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("APPDATA"))
        .map(PathBuf::from)?;

    match current_package_family_name() {
        Some(family) => Some(
            local
                .join("Packages")
                .join(family)
                .join("LocalState")
                .join("IntelligentTerminal"),
        ),
        None => Some(local.join("IntelligentTerminal")),
    }
}

/// Returns the current process's package family name (e.g.
/// `IntelligentTerminal_rd9vj3e6a2mbr`), or `None` when the process has no
/// package identity (unpackaged) or the OS call fails for any other reason.
fn current_package_family_name() -> Option<std::ffi::OsString> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    use windows_sys::Win32::Storage::Packaging::Appx::GetCurrentPackageFamilyName;

    // First call with a null buffer queries the required length. A packaged
    // process returns ERROR_INSUFFICIENT_BUFFER and fills `len`; an
    // unpackaged process returns APPMODEL_ERROR_NO_PACKAGE (any non-122 rc
    // means "no usable identity" for our purposes).
    let mut len: u32 = 0;
    let rc = unsafe { GetCurrentPackageFamilyName(&mut len, std::ptr::null_mut()) };
    if rc != ERROR_INSUFFICIENT_BUFFER || len == 0 {
        return None;
    }

    // `len` includes the trailing NUL; allocate exactly that and call again.
    let mut buf = vec![0u16; len as usize];
    let rc = unsafe { GetCurrentPackageFamilyName(&mut len, buf.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }

    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    if end == 0 {
        return None;
    }
    Some(std::ffi::OsString::from_wide(&buf[..end]))
}

pub fn runtime_prompt_root() -> Option<PathBuf> {
    intelligent_terminal_root().map(|root| root.join("prompts"))
}

pub fn runtime_log_path(file_name: &str) -> PathBuf {
    if let Some(root) = intelligent_terminal_root() {
        let log_dir = root.join("logs");
        let _ = std::fs::create_dir_all(&log_dir);
        return log_dir.join(file_name);
    }

    PathBuf::from(file_name)
}

pub fn master_pipe_file_path() -> Option<PathBuf> {
    intelligent_terminal_root().map(|root| root.join("master-pipe.txt"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpackaged_process_has_no_package_family_name() {
        // `cargo test` runs the test binary without package identity, so the
        // OS call must report "no package" and we must fall back gracefully
        // rather than panicking or returning a bogus name.
        assert_eq!(current_package_family_name(), None);
    }

    #[test]
    fn unpackaged_root_falls_back_to_bare_intelligent_terminal() {
        // With no package identity (test context), the root is the legacy
        // bare `…\IntelligentTerminal`, NOT a `Packages\<pfn>\LocalState`
        // path. Guard the suffix so a future regression that always emits
        // the packaged layout is caught.
        let root = resolve_root().expect("LOCALAPPDATA/APPDATA set in CI/dev");
        assert!(
            root.ends_with("IntelligentTerminal"),
            "unexpected root: {}",
            root.display(),
        );
        assert!(
            !root.to_string_lossy().contains("LocalState"),
            "unpackaged root must not point into a package store: {}",
            root.display(),
        );
    }
}
