//! Slice 04: per-run isolation. On this platform the backend is seatbelt
//! (`/usr/bin/sandbox-exec`): every broker-executed command runs inside a
//! generated profile that denies all network except the policy's egress
//! allowlist and denies all writes outside the run's own workdir. The
//! profile is derived from the policy, never hand-edited per call, and the
//! active backend is recorded on every `tool.request` so the declaration in
//! `profile_requirements.isolation` is observable rather than asserted.

use crate::Fault;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

static SANDBOX_SEQ: AtomicU64 = AtomicU64::new(0);

/// A process-unique scratch directory under TMPDIR. Run ids are millisecond
/// timestamps, so two runs opened in the same millisecond (parallel tests,
/// tight loops) would otherwise share a sandbox workdir and each other's
/// staged files; the atomic suffix makes the path unique regardless.
pub fn unique_run_dir(prefix: &str) -> PathBuf {
    let n = SANDBOX_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()))
}

pub struct Sandbox {
    profile: String,
    workdir: PathBuf,
    kind: &'static str,
}

impl Sandbox {
    /// Builds the per-run sandbox. `egress_allow` comes from
    /// `profile_requirements.egress.allow`; each entry is `ip:port` in
    /// seatbelt remote-ip syntax (`localhost:11434` is the loopback form).
    pub fn per_run(workdir: &Path, egress_allow: &[String]) -> Result<Sandbox, Fault> {
        std::fs::create_dir_all(workdir).map_err(|e| {
            Fault::new(
                format!("cannot create run workdir {}: {e}", workdir.display()),
                "check TMPDIR is writable; every run needs its own scratch directory",
            )
        })?;
        // Symlinks (macOS /tmp -> /private/tmp) would silently widen or
        // narrow the subpath scope, so resolve before writing the profile.
        let workdir = workdir.canonicalize().map_err(|e| {
            Fault::new(
                format!("cannot canonicalise workdir {}: {e}", workdir.display()),
                "the workdir must exist and be readable at sandbox build time",
            )
        })?;
        let mut profile = String::from("(version 1)\n(allow default)\n(deny network*)\n");
        for host in egress_allow {
            profile.push_str(&format!("(allow network* (remote ip \"{host}\"))\n"));
        }
        profile.push_str("(deny file-write*)\n");
        profile.push_str(&format!(
            "(allow file-write* (subpath \"{}\"))\n",
            workdir.display()
        ));
        // The shell itself needs the null device and its tty.
        profile
            .push_str("(allow file-write-data (literal \"/dev/null\") (literal \"/dev/tty\"))\n");
        let kind = if Path::new(SANDBOX_EXEC).exists() {
            "seatbelt"
        } else {
            "none"
        };
        Ok(Sandbox {
            profile,
            workdir,
            kind,
        })
    }

    /// What `tool.request.sandbox` records. "none" means the backend binary
    /// is missing and the profile is not being enforced; the laptop profile
    /// degrades rather than refuses, and the record says so.
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    /// One command inside the sandbox with a cleaned environment. The child
    /// sees PATH, HOME and TMPDIR pointed at the workdir, plus exactly the
    /// `inject` pairs (credential handles the policy granted), and nothing
    /// else from the parent, which is what keeps a hostile `env` empty.
    pub fn command(&self, shell_command: &str, inject: &[(String, String)]) -> Command {
        let mut cmd = if self.kind == "seatbelt" {
            let mut c = Command::new(SANDBOX_EXEC);
            c.arg("-p")
                .arg(&self.profile)
                .arg("sh")
                .arg("-c")
                .arg(shell_command);
            c
        } else {
            let mut c = Command::new("sh");
            c.arg("-c").arg(shell_command);
            c
        };
        cmd.env_clear();
        cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        cmd.env("HOME", &self.workdir);
        cmd.env("TMPDIR", &self.workdir);
        for (k, v) in inject {
            cmd.env(k, v);
        }
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox(name: &str, egress: &[String]) -> Sandbox {
        let dir = std::env::temp_dir().join(format!("gantry-sbx-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Sandbox::per_run(&dir, egress).unwrap()
    }

    #[test]
    fn profile_denies_network_and_foreign_writes() {
        let s = sandbox("profile", &[]);
        assert!(s.profile.contains("(deny network*)"));
        assert!(s.profile.contains("(deny file-write*)"));
        assert!(s.profile.contains(&format!(
            "(allow file-write* (subpath \"{}\"))",
            s.workdir().display()
        )));
        assert_eq!(s.kind(), "seatbelt");
    }

    #[test]
    fn allowlist_entries_become_remote_ip_allows() {
        let s = sandbox("egress", &["localhost:11434".to_string()]);
        assert!(s
            .profile
            .contains("(allow network* (remote ip \"localhost:11434\"))"));
    }

    #[test]
    fn environment_is_cleaned_and_injection_is_explicit() {
        std::env::set_var("GANTRY_SBX_CANARY", "leak-me");
        let s = sandbox("env", &[]);
        let out = s
            .command(
                "env",
                &[("GRANTED".to_string(), "handle-value".to_string())],
            )
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        std::env::remove_var("GANTRY_SBX_CANARY");
        assert!(!text.contains("leak-me"), "parent env leaked: {text}");
        assert!(
            text.contains("GRANTED=handle-value"),
            "injection missing: {text}"
        );
    }

    #[test]
    fn writes_outside_the_workdir_fail_inside() {
        let s = sandbox("writes", &[]);
        let foreign =
            std::env::temp_dir().join(format!("gantry-sbx-foreign-{}", std::process::id()));
        let _ = std::fs::remove_file(&foreign);
        let out = s
            .command(&format!("touch {}", foreign.display()), &[])
            .output()
            .unwrap();
        assert!(!out.status.success(), "foreign write succeeded");
        assert!(!foreign.exists());
        let inside = s.workdir().join("mine");
        let out = s
            .command(&format!("touch {}", inside.display()), &[])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "workdir write failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(inside.exists());
    }

    /// Loopback is network too; an empty allowlist denies it. This is the
    /// no-network-in-tests invariant used as a fixture: the connection is
    /// attempted at a loopback listener and must die at the sandbox.
    #[test]
    fn loopback_is_denied_when_allowlist_is_empty() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let s = sandbox("loopback", &[]);
        let out = s
            .command(&format!("nc -w 1 127.0.0.1 {port} < /dev/null"), &[])
            .output()
            .unwrap();
        assert!(!out.status.success(), "sandboxed nc reached loopback");
    }
}
