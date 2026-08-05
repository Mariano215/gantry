//! Slice 04: the credential broker. Agents hold handles; values live here
//! and are substituted at the tool boundary, inside the sandbox's
//! environment, after the policy allowed the call. A handle that the calling
//! capability does not declare resolves to nothing, so asking for a secret
//! you were not granted is a refusal rather than a leak.

use crate::Fault;
use std::collections::BTreeMap;

/// `{{handle:NAME}}` is the only substitution form. It is deliberately not
/// valid shell, so an unsubstituted handle fails loudly instead of running.
const OPEN: &str = "{{handle:";
const CLOSE: &str = "}}";

pub struct CredentialBroker {
    values: BTreeMap<String, String>,
}

/// What a substitution produced: the command with handles replaced by
/// environment references, and the pairs to inject into the child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Substitution {
    pub command: String,
    pub env: Vec<(String, String)>,
    pub handles_used: Vec<String>,
}

impl CredentialBroker {
    /// Loads handle values from the process environment: handle `NAME` reads
    /// `GANTRY_SECRET_NAME`. The values never enter an event, a prompt or a
    /// tool argument; only handle names do.
    pub fn from_env(handles: &[String]) -> CredentialBroker {
        let mut values = BTreeMap::new();
        for h in handles {
            let var = format!(
                "GANTRY_SECRET_{}",
                h.to_uppercase().replace(['-', '.'], "_")
            );
            if let Ok(v) = std::env::var(&var) {
                if !v.is_empty() {
                    values.insert(h.clone(), v);
                }
            }
        }
        CredentialBroker { values }
    }

    pub fn with_values(values: BTreeMap<String, String>) -> CredentialBroker {
        CredentialBroker { values }
    }

    /// Replaces every `{{handle:NAME}}` with `"$GANTRY_HANDLE_NAME"` and
    /// returns the environment pairs to inject. `granted` is the calling
    /// capability's `credentials` list: a handle outside it is refused, and
    /// so is a handle the broker holds no value for.
    pub fn substitute(&self, command: &str, granted: &[String]) -> Result<Substitution, Fault> {
        let mut out = String::with_capacity(command.len());
        let mut env: Vec<(String, String)> = Vec::new();
        let mut handles_used: Vec<String> = Vec::new();
        let mut rest = command;
        while let Some(start) = rest.find(OPEN) {
            out.push_str(&rest[..start]);
            let after = &rest[start + OPEN.len()..];
            let end = after.find(CLOSE).ok_or_else(|| {
                Fault::new(
                    format!("unterminated credential handle in {command}"),
                    "close the handle with }}, as in {{handle:NAME}}",
                )
            })?;
            let name = &after[..end];
            if !granted.iter().any(|g| g == name) {
                return Err(Fault::new(
                    format!("this capability does not declare credential handle {name}"),
                    format!("add {name} to the capability's credentials list in config/policy.json, or drop the handle from the call"),
                ));
            }
            let value = self.values.get(name).ok_or_else(|| {
                Fault::new(
                    format!("no value is registered for credential handle {name}"),
                    format!(
                        "export GANTRY_SECRET_{} before the run; the broker never invents a value",
                        name.to_uppercase()
                    ),
                )
            })?;
            let var = format!(
                "GANTRY_HANDLE_{}",
                name.to_uppercase().replace(['-', '.'], "_")
            );
            out.push_str(&format!("\"${var}\""));
            if !handles_used.iter().any(|h| h == name) {
                handles_used.push(name.to_string());
                env.push((var, value.clone()));
            }
            rest = &after[end + CLOSE.len()..];
        }
        out.push_str(rest);
        Ok(Substitution {
            command: out,
            env,
            handles_used,
        })
    }

    /// The handle names present in a command, for the `tool.request` record.
    /// Names only; a value never reaches this function's output.
    pub fn handles_in(command: &str) -> Vec<String> {
        let mut found = Vec::new();
        let mut rest = command;
        while let Some(start) = rest.find(OPEN) {
            let after = &rest[start + OPEN.len()..];
            match after.find(CLOSE) {
                Some(end) => {
                    let name = after[..end].to_string();
                    if !found.contains(&name) {
                        found.push(name);
                    }
                    rest = &after[end + CLOSE.len()..];
                }
                None => break,
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn broker() -> CredentialBroker {
        let mut v = BTreeMap::new();
        v.insert("api-token".to_string(), "sk-secret-value".to_string());
        CredentialBroker::with_values(v)
    }

    #[test]
    fn substitution_puts_the_value_in_env_not_in_the_command() {
        let granted = vec!["api-token".to_string()];
        let s = broker()
            .substitute("curl -H \"Auth: {{handle:api-token}}\" https://x", &granted)
            .unwrap();
        assert!(
            !s.command.contains("sk-secret-value"),
            "value in command: {}",
            s.command
        );
        assert!(s.command.contains("\"$GANTRY_HANDLE_API_TOKEN\""));
        assert_eq!(
            s.env,
            vec![(
                "GANTRY_HANDLE_API_TOKEN".to_string(),
                "sk-secret-value".to_string()
            )]
        );
        assert_eq!(s.handles_used, vec!["api-token".to_string()]);
    }

    #[test]
    fn undeclared_handle_is_refused() {
        let fault = broker()
            .substitute("echo {{handle:api-token}}", &[])
            .unwrap_err();
        assert!(fault.cause.contains("api-token"), "{fault}");
        assert!(fault.fix.contains("credentials list"), "{fault}");
    }

    #[test]
    fn granted_but_unset_handle_is_refused_not_blanked() {
        let empty = CredentialBroker::with_values(BTreeMap::new());
        let fault = empty
            .substitute("echo {{handle:api-token}}", &["api-token".to_string()])
            .unwrap_err();
        assert!(fault.cause.contains("no value is registered"), "{fault}");
        assert!(
            fault.fix.contains("GANTRY_SECRET_API-TOKEN")
                || fault.fix.contains("GANTRY_SECRET_API"),
            "{fault}"
        );
    }

    #[test]
    fn repeated_handle_injects_once() {
        let granted = vec!["api-token".to_string()];
        let s = broker()
            .substitute("echo {{handle:api-token}} {{handle:api-token}}", &granted)
            .unwrap();
        assert_eq!(s.env.len(), 1);
        assert_eq!(s.command.matches("$GANTRY_HANDLE_API_TOKEN").count(), 2);
    }

    #[test]
    fn handles_in_names_only() {
        assert_eq!(
            CredentialBroker::handles_in("a {{handle:one}} b {{handle:two}} c"),
            vec!["one".to_string(), "two".to_string()]
        );
        assert!(CredentialBroker::handles_in("no handles here").is_empty());
    }

    #[test]
    fn unterminated_handle_faults() {
        let fault = broker()
            .substitute("echo {{handle:api-token", &["api-token".to_string()])
            .unwrap_err();
        assert!(fault.cause.contains("unterminated"), "{fault}");
    }
}
