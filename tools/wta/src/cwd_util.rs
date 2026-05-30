//! Validation helper for "starting directory" values that wta hands to
//! external launchers (`wtcli new-tab -d <cwd>`, the `resume_in_new_agent_tab`
//! protocol event consumed by WT to spawn a new tab, the boot-time
//! `--initial-load-cwd` flag, etc.).
//!
//! Agent session metadata (cwd recorded by Claude/Copilot/Gemini in their
//! per-session JSONL files) can easily go stale: the user moves or deletes
//! the project directory, mounts a different drive, etc. Passing a stale
//! cwd downstream causes `CreateProcessW` to fail with
//! `ERROR_DIRECTORY` (0x10b), which surfaces as a new tab/pane that opens
//! but is immediately broken — the connection prints
//! `Could not find ... working directory` and the user can't type
//! anything useful.
//!
//! Validating BEFORE we hand the value off lets us fall back cleanly: by
//! omitting the directory argument entirely, the consumer uses its own
//! default chain (profile `startingDirectory` → `%USERPROFILE%`), which
//! mirrors what plain `wtcli new-tab` (no `-d`) already does. We
//! deliberately do NOT pick a substitute directory ourselves — letting
//! the consumer's normal default kick in keeps behaviour consistent with
//! a vanilla "open new tab" action.
//!
//! ## WSL / UNC / Unix-path safety
//!
//! `fs::metadata` operates against the **Windows** filesystem, so a path
//! that's perfectly valid in WSL (`/home/user/proj`, `~/proj`) would be
//! reported as missing — and we'd wrongly strip it, leaving a WSL
//! profile booting in `%USERPROFILE%` instead of the project root.
//! Worse, `\\wsl$\<distro>\...` and `\\wsl.localhost\<distro>\...` UNC
//! paths can stall `fs::metadata` for seconds when the distro isn't
//! running, which is exactly the hazard that
//! [GH microsoft/terminal#9541] caused WT itself to drop its own
//! pre-launch existence check (see `Profile::EvaluateStartingDirectory`
//! in `src/cascadia/TerminalSettingsModel/Profile.cpp`).
//!
//! We therefore only run the existence check on paths we can cheaply
//! prove are **local Windows** (drive-letter form, optionally with the
//! `\\?\` extended-length prefix). Everything else — Unix-style,
//! WSL UNC, network UNC, relative — is passed through unchanged. In
//! those cases the original behaviour applies: WT will still surface a
//! launch failure inline via `ConptyConnection` if the path really is
//! bad, but we don't *create* false failures by guessing.

use std::path::Path;

/// Returns `Some(string)` if the candidate cwd is safe to forward to a
/// launcher. The result is:
///
/// * `None` when `path` is empty, **or** when it's a local Windows path
///   that doesn't exist / isn't a directory. The caller should drop the
///   cwd argument entirely so the launcher falls back to its own
///   default.
/// * `Some(s)` in every other case — including paths we deliberately
///   *don't* validate (Unix-style, WSL UNC, network UNC, relative).
///   For those, we return the string unchanged so downstream behaviour
///   matches what it would have done before this helper existed.
///
/// The existence check is a single `fs::metadata` syscall scoped to
/// local Windows paths only. On local NTFS this is effectively free;
/// we don't run it on WSL/network paths precisely to avoid the
/// multi-second stalls those filesystems can introduce.
pub fn validate_starting_directory<P: AsRef<Path>>(path: P) -> Option<String> {
    let p = path.as_ref();
    let s = p.to_string_lossy();
    if s.is_empty() {
        return None;
    }

    if !is_local_windows_path(&s) {
        // Unix-style, WSL UNC, generic UNC, relative — pass through.
        // See the module-level doc comment for the rationale.
        return Some(s.into_owned());
    }

    match std::fs::metadata(p) {
        Ok(meta) if meta.is_dir() => Some(s.into_owned()),
        _ => None,
    }
}

/// `true` only when `s` looks like a *local* Windows path we can safely
/// hit with `fs::metadata` without risking a slow / hanging syscall:
///
/// * `C:`, `C:\…`, `C:/…` (drive-letter, absolute or drive-relative)
/// * `\\?\C:\…` / `//?/C:\…` (extended-length, drive-letter form)
///
/// Explicitly NOT local-Windows:
///
/// * `/foo`, `~/foo`, `~` (Unix-style / WSL home expansion)
/// * `\\wsl$\<distro>\…`, `\\wsl.localhost\<distro>\…` (WSL UNC)
/// * `\\?\UNC\server\share\…` (extended-length UNC, including WSL)
/// * `\\server\share\…` (generic network UNC)
/// * `foo\bar`, `./foo` (relative)
fn is_local_windows_path(s: &str) -> bool {
    // Drive-letter form: "C:" or "C:\..." or "C:/..."
    if has_drive_letter_prefix(s) {
        return true;
    }
    // Extended-length, drive-letter only. "\\?\UNC\..." routes to a UNC
    // path so it's intentionally NOT counted as local.
    for prefix in [r"\\?\", "//?/"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            return has_drive_letter_prefix(rest);
        }
    }
    false
}

fn has_drive_letter_prefix(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn unique_temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("wta-cwd-util-{tag}-{pid}-{nanos}"));
        p
    }

    #[test]
    fn empty_path_returns_none() {
        assert_eq!(validate_starting_directory(""), None);
        assert_eq!(validate_starting_directory(PathBuf::new()), None);
    }

    #[test]
    fn nonexistent_local_path_returns_none() {
        let p = unique_temp_dir("nope");
        let _ = fs::remove_dir_all(&p);
        assert!(!p.exists());
        assert_eq!(validate_starting_directory(&p), None);
    }

    #[test]
    fn file_path_returns_none() {
        let dir = unique_temp_dir("file");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("a.txt");
        fs::write(&file, b"x").unwrap();
        assert_eq!(validate_starting_directory(&file), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn existing_directory_returns_path_string() {
        let dir = unique_temp_dir("ok");
        fs::create_dir_all(&dir).unwrap();
        let got = validate_starting_directory(&dir);
        assert_eq!(got, Some(dir.to_string_lossy().into_owned()));
        let _ = fs::remove_dir_all(&dir);
    }

    /// Unix-style cwds (typical for WSL profiles) must pass through
    /// unchanged. They can't be validated against the Windows filesystem
    /// without false-rejecting every WSL session — that bug would show
    /// up as "all my WSL agent panes boot in %USERPROFILE% instead of
    /// the project root".
    #[test]
    fn unix_style_paths_pass_through_unchanged() {
        for s in ["/home/user/proj", "/", "/tmp", "~/work", "~"] {
            assert_eq!(
                validate_starting_directory(s),
                Some(s.to_string()),
                "unix-style path `{}` was filtered",
                s
            );
        }
    }

    /// WSL UNC paths can stall `fs::metadata` for seconds when the
    /// distro is stopped — the exact failure GH#9541 fixed in WT. We
    /// avoid the syscall entirely and trust WT/wtcli to surface a real
    /// failure inline if the path is unreachable.
    #[test]
    fn wsl_unc_paths_pass_through_unchanged() {
        for s in [
            r"\\wsl$\Ubuntu\home\user\proj",
            r"\\wsl.localhost\Ubuntu\home\user\proj",
            r"\\?\UNC\wsl$\Ubuntu\home\user\proj",
        ] {
            assert_eq!(
                validate_starting_directory(s),
                Some(s.to_string()),
                "WSL UNC path `{}` was filtered",
                s
            );
        }
    }

    /// Generic SMB / network UNC paths are also pass-through: the
    /// remote host may be unreachable and we don't want to gate a
    /// launch on a network round-trip.
    #[test]
    fn network_unc_paths_pass_through_unchanged() {
        for s in [r"\\server\share\proj", r"\\10.0.0.1\share\dir"] {
            assert_eq!(
                validate_starting_directory(s),
                Some(s.to_string()),
                "UNC path `{}` was filtered",
                s
            );
        }
    }

    /// Relative paths have no anchor we can resolve from here. Pass
    /// through and let the launcher interpret them in its own context.
    #[test]
    fn relative_paths_pass_through_unchanged() {
        for s in ["foo", r"foo\bar", "./foo", r".\foo"] {
            assert_eq!(
                validate_starting_directory(s),
                Some(s.to_string()),
                "relative path `{}` was filtered",
                s
            );
        }
    }

    /// Extended-length drive-letter form (`\\?\C:\...`) is a local
    /// Windows path and SHOULD be validated like a regular `C:\...`.
    #[test]
    fn extended_length_drive_letter_is_validated() {
        let dir = unique_temp_dir("extlen");
        fs::create_dir_all(&dir).unwrap();
        let ext = format!(r"\\?\{}", dir.to_string_lossy());
        let got = validate_starting_directory(&ext);
        assert_eq!(got, Some(ext.clone()));
        // Non-existent extended-length path → None.
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(validate_starting_directory(&ext), None);
    }

    #[test]
    fn is_local_windows_path_classification() {
        // Local Windows: drive-letter forms.
        for s in [
            r"C:\",
            r"C:\foo",
            "C:/foo",
            "C:",
            r"d:\users\me",
            r"\\?\C:\foo",
            r"\\?\D:\bar",
            "//?/C:/foo",
        ] {
            assert!(is_local_windows_path(s), "should be local: {}", s);
        }
        // NOT local: unix, UNC (including WSL & extended-length UNC), relative.
        for s in [
            "",
            "/",
            "/home/user",
            "~/proj",
            "~",
            r"\\server\share",
            r"\\wsl$\Ubuntu\home",
            r"\\wsl.localhost\Ubuntu\home",
            r"\\?\UNC\server\share",
            r"\\?\UNC\wsl$\Ubuntu",
            "foo",
            r"foo\bar",
            "./foo",
        ] {
            assert!(!is_local_windows_path(s), "should NOT be local: {}", s);
        }
    }
}

