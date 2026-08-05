//! Slice 03: the policy engine. Loads the machine form of
//! docs/POLICY-SCHEMA.md from JSON, refuses to load a policy that lies
//! (shadowed rules, post gates without rollback, silent denials), and
//! evaluates every tool call to exactly one decision. `decide` is a pure
//! function of the policy, the call and the identity, which is what makes a
//! decision replayable from an exported ledger alone.

use crate::event::{jcs_bytes, subject_hash};
use crate::Fault;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "write.local")]
    WriteLocal,
    #[serde(rename = "write.shared")]
    WriteShared,
    #[serde(rename = "irreversible")]
    Irreversible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Rung {
    Led,
    Assisted,
    Autonomous,
}

impl Effect {
    /// The schema spelling, for messages an agent reads.
    pub fn schema_name(self) -> &'static str {
        match self {
            Effect::Read => "read",
            Effect::WriteLocal => "write.local",
            Effect::WriteShared => "write.shared",
            Effect::Irreversible => "irreversible",
        }
    }
}

impl Rung {
    pub fn schema_name(self) -> &'static str {
        match self {
            Rung::Led => "led",
            Rung::Assisted => "assisted",
            Rung::Autonomous => "autonomous",
        }
    }

    /// The ladder, low to high. Promotion moves up one, demotion down one;
    /// neither wraps.
    pub fn up(self) -> Option<Rung> {
        match self {
            Rung::Led => Some(Rung::Assisted),
            Rung::Assisted => Some(Rung::Autonomous),
            Rung::Autonomous => None,
        }
    }

    pub fn down(self) -> Option<Rung> {
        match self {
            Rung::Led => None,
            Rung::Assisted => Some(Rung::Led),
            Rung::Autonomous => Some(Rung::Assisted),
        }
    }

    pub fn parse(s: &str) -> Option<Rung> {
        match s {
            "led" => Some(Rung::Led),
            "assisted" => Some(Rung::Assisted),
            "autonomous" => Some(Rung::Autonomous),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
    Hold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Gate {
    Pre,
    Post,
    None,
}

/// The trust-budget table from docs/POLICY-SCHEMA.md. Irreversible is `pre`
/// at every rung; autonomous is post-hoc review with rollback, and there is
/// no rollback for an unrecallable act.
pub fn gate(rung: Rung, effect: Effect) -> Gate {
    match (rung, effect) {
        (Rung::Led, _) => Gate::Pre,
        (_, Effect::Irreversible) => Gate::Pre,
        (Rung::Assisted, Effect::WriteShared) => Gate::Pre,
        (Rung::Assisted, _) => Gate::None,
        (Rung::Autonomous, Effect::Read) => Gate::None,
        (Rung::Autonomous, _) => Gate::Post,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub id: String,
    pub tools: Vec<String>,
    pub effect: Effect,
    pub rung: Rung,
    #[serde(default)]
    pub credentials: Vec<String>,
    #[serde(default)]
    pub rollback: Option<String>,
    #[serde(default)]
    pub sensors: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleMatch {
    #[serde(default)]
    pub capability: Option<String>,
    /// Patterns matched against the request target: a path for file tools, a
    /// command line for shell, a host for egress. `path_in` is the slice 00
    /// name for the same field and stays accepted.
    #[serde(default, alias = "path_in")]
    pub target_in: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleWhen {
    pub profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(rename = "match")]
    pub matcher: RuleMatch,
    #[serde(default)]
    pub when: Option<RuleWhen>,
    pub action: Action,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub v: u32,
    #[serde(default)]
    pub policy_version: Option<String>,
    pub profile: String,
    pub profile_requirements: Value,
    pub capabilities: Vec<Capability>,
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub trust_budget: Value,
}

/// What the running system can provide for each profile requirement that has
/// an availability question. The caller observes these at run open and passes
/// them in; nothing here reads the system, which is what keeps this check and
/// the drift check from being two copies of one observer.
///
/// Availability is not divergence. Divergence is "the policy declares microvm
/// and this run observed seatbelt": one declared value against the one value
/// currently in force, reported per field. Availability asks whether anything
/// on this machine could meet the declaration at all, which is why each field
/// is a set rather than a value: a host that can boot a microvm answers yes
/// for microvm even while this particular run sits inside seatbelt.
#[derive(Debug, Clone)]
pub struct Providable {
    pub isolation: Vec<String>,
    pub identity: Vec<String>,
    pub anchoring: Vec<String>,
    pub key_custody: Vec<String>,
}

/// Declaring `none` asks for nothing, and nothing is always available.
fn with_none(provided: &str) -> Vec<String> {
    if provided == "none" {
        vec!["none".to_string()]
    } else {
        vec![provided.to_string(), "none".to_string()]
    }
}

impl Providable {
    /// What this build can provide, given the isolation backend the caller
    /// observed. The other three are fixed because this build implements
    /// exactly one of each: identity is the local process identity, the ledger
    /// is a local file with no anchoring, and the actor key is a software seed
    /// read from a file or the environment. A policy naming `oidc`, `rfc3161`
    /// or an `hsm` names something no code path here produces, on any machine.
    pub fn for_this_build(isolation_backend: &str) -> Providable {
        Providable {
            isolation: with_none(isolation_backend),
            identity: with_none("local"),
            anchoring: vec!["none".to_string()],
            key_custody: vec!["software".to_string()],
        }
    }
}

/// One profile requirement this system cannot meet with anything it has.
#[derive(Debug, Clone, Serialize)]
pub struct Shortfall {
    pub field: String,
    pub declared: String,
    pub providable: Vec<String>,
}

impl Shortfall {
    fn line(&self) -> String {
        format!(
            "{} declares {} and this system provides {}",
            self.field,
            self.declared,
            self.providable.join(" or ")
        )
    }
}

/// Every `profile_requirements` field whose declared value is outside what the
/// system can provide. An absent field asks for nothing and is not a
/// shortfall; the hash fields (`instruction_pack`, `host_permissions`) and the
/// egress allowlist have no availability question, and the attestation key is
/// resolved by `ActorSigner::declared`.
pub fn unavailable_requirements(requirements: &Value, providable: &Providable) -> Vec<Shortfall> {
    let checks = [
        (
            "isolation.declared",
            &requirements["isolation"]["declared"],
            &providable.isolation,
        ),
        (
            "identity.declared",
            &requirements["identity"]["declared"],
            &providable.identity,
        ),
        (
            "ledger.anchoring",
            &requirements["ledger"]["anchoring"],
            &providable.anchoring,
        ),
        (
            "ledger.key_custody",
            &requirements["ledger"]["key_custody"],
            &providable.key_custody,
        ),
    ];
    checks
        .iter()
        .filter_map(|(field, declared, provided)| {
            let declared = declared.as_str()?;
            if provided.iter().any(|p| p == declared) {
                return None;
            }
            Some(Shortfall {
                field: field.to_string(),
                declared: declared.to_string(),
                providable: (*provided).clone(),
            })
        })
        .collect()
}

/// `profile_requirements.on_unavailable`, applied at run open.
///
/// `refuse` stops the control plane before it appends anything and the fault
/// names every requirement that is unavailable, so a `regulated` profile
/// cannot quietly become a `laptop` on a machine with no HSM. `degrade` (the
/// laptop default) returns the shortfalls for the caller to record on
/// `run.open`, so the weakening is on the ledger rather than swallowed.
///
/// A value that is neither refuses on every run, empty shortfall list or not:
/// a typo that fell through to degrade would be the silent degradation this
/// field exists to rule out.
pub fn availability_check(
    profile: &str,
    requirements: &Value,
    providable: &Providable,
) -> Result<Vec<Shortfall>, Fault> {
    let stance = requirements["on_unavailable"].as_str().unwrap_or("degrade");
    if stance != "degrade" && stance != "refuse" {
        return Err(Fault::new(
            format!("profile_requirements.on_unavailable is {stance}, which is neither degrade nor refuse"),
            "set it to refuse, so an unavailable requirement stops the run, or to degrade, so the run starts and records the shortfall on run.open",
        ));
    }
    let short = unavailable_requirements(requirements, providable);
    if stance == "refuse" && !short.is_empty() {
        let named = short
            .iter()
            .map(Shortfall::line)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(Fault::new(
            format!(
                "profile {profile} sets on_unavailable refuse and this system cannot provide what it declares: {named}"
            ),
            "run this profile on a deployment that has those backends, or lower the declarations in profile_requirements to what this one provides; setting on_unavailable to degrade instead starts the run and records the shortfall, which is a weaker profile than the one declared",
        ));
    }
    Ok(short)
}

/// One tool call as the evaluator sees it.
#[derive(Debug, Clone)]
pub struct CallRequest {
    pub tool: String,
    pub target: String,
    pub args: Value,
}

/// Maps one to one onto the subject of a `policy.decision` event.
#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub verdict: Action,
    pub capability: Option<String>,
    pub rule: String,
    pub rung: Option<Rung>,
    pub effect: Option<Effect>,
    pub gate: Option<Gate>,
    pub obligation: Option<String>,
    pub request: Value,
    pub identity: Value,
    pub message: Option<String>,
}

impl Policy {
    /// The computed content version: SHA-256 of the RFC 8785 form of the
    /// document with `policy_version` itself omitted.
    pub fn version(&self) -> Result<String, Fault> {
        let mut doc = serde_json::to_value(self).map_err(|e| {
            Fault::new(
                format!("policy does not serialise: {e}"),
                "report this as a bug; a loaded policy is serialisable by construction",
            )
        })?;
        if let Some(map) = doc.as_object_mut() {
            map.remove("policy_version");
        }
        Ok(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(jcs_bytes(&doc)?))
        ))
    }

    pub fn load(path: &Path) -> Result<Policy, Fault> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            Fault::new(
                format!("cannot read policy {}: {e}", path.display()),
                "check the path; the tracked machine policy is config/policy.json",
            )
        })?;
        let mut policy: Policy = serde_json::from_str(&text).map_err(|e| {
            Fault::new(
                format!("{} does not parse as a policy: {e}", path.display()),
                "match the document shape in docs/POLICY-SCHEMA.md: v, profile, profile_requirements, capabilities, rules",
            )
        })?;
        let computed = policy.version()?;
        if let Some(written) = &policy.policy_version {
            if *written != computed {
                return Err(Fault::new(
                    format!(
                        "policy_version in {} is {written} but the content hashes to {computed}",
                        path.display()
                    ),
                    "policy_version is computed, never hand-written; delete the field or set it to the computed value",
                ));
            }
        }
        policy.policy_version = Some(computed);
        policy.validate()?;
        Ok(policy)
    }

    /// The load-time checks that make a policy refuse to lie. Each one is a
    /// CLAUDE.md architecture invariant: ci/policy-shadow, ci/policy-rollback,
    /// and the rule that a denial always names its rule (which requires every
    /// deny to carry an action-naming message).
    pub fn validate(&self) -> Result<(), Fault> {
        for cap in &self.capabilities {
            if gate(cap.rung, cap.effect) == Gate::Post && cap.rollback.is_none() {
                return Err(Fault::new(
                    format!(
                        "capability {} resolves to a post gate ({} + {}) with no rollback handle",
                        cap.id,
                        cap.rung.schema_name(),
                        cap.effect.schema_name()
                    ),
                    "declare a rollback handle on the capability, or lower its rung so the gate is pre",
                ));
            }
        }
        for rule in &self.rules {
            if let Some(cap_id) = &rule.matcher.capability {
                if !self.capabilities.iter().any(|c| c.id == *cap_id) {
                    return Err(Fault::new(
                        format!(
                            "rule {} names capability {cap_id}, which is not declared",
                            rule.id
                        ),
                        "declare the capability in the policy or fix the name in the rule match",
                    ));
                }
            }
            if rule.action != Action::Allow
                && rule.message.as_deref().unwrap_or("").trim().is_empty()
            {
                return Err(Fault::new(
                    format!("rule {} can deny or hold but carries no message", rule.id),
                    "add a message that names the action to take; the reader of a denial is an agent",
                ));
            }
        }
        for (i, later) in self.rules.iter().enumerate() {
            for earlier in &self.rules[..i] {
                if covers(earlier, later) {
                    return Err(Fault::new(
                        format!(
                            "rule {} is unreachable: every call it matches is already matched by earlier rule {}",
                            later.id, earlier.id
                        ),
                        "narrow the earlier rule, move the later rule above it, or delete the later rule",
                    ));
                }
            }
        }
        Ok(())
    }

    /// One call, one evaluation, one decision. Pure and total. Gates on the
    /// capability's declared rung; the broker passes the earned rung via
    /// `decide_with_earned`.
    pub fn decide(&self, call: &CallRequest, identity: &Value) -> Result<Decision, Fault> {
        self.decide_with_earned(call, identity, &|_, declared| declared)
    }

    /// Like `decide`, but the rung that gates is `earned(capability_id,
    /// declared_rung)`, so a caller holding ledger history gates on the rung
    /// the capability has actually earned, not the one the policy asserts.
    pub fn decide_with_earned(
        &self,
        call: &CallRequest,
        identity: &Value,
        earned: &dyn Fn(&str, Rung) -> Rung,
    ) -> Result<Decision, Fault> {
        let request = json!({
            "tool": call.tool,
            "args_hash": subject_hash(&call.args)?,
            "target": call.target,
        });
        let cap = self.capabilities.iter().find(|c| {
            c.tools
                .iter()
                .any(|p| tool_pattern_matches(p, &call.tool, &call.target))
        });
        let cap = match cap {
            Some(c) => c,
            None => {
                let (rule_id, message) = self.default_rule();
                return Ok(Decision {
                    verdict: Action::Deny,
                    capability: None,
                    rule: rule_id,
                    rung: None,
                    effect: None,
                    gate: None,
                    obligation: None,
                    request,
                    identity: identity.clone(),
                    message: Some(message),
                });
            }
        };
        let rule = self.rules.iter().find(|r| {
            r.matcher.capability.as_deref().is_none_or(|c| c == cap.id)
                && r.matcher
                    .target_in
                    .as_ref()
                    .is_none_or(|pats| pats.iter().any(|p| glob_matches(p, &call.target)))
                && r.when.as_ref().is_none_or(|w| w.profile == self.profile)
        });
        let rule = match rule {
            Some(r) => r,
            None => {
                // Unreachable when an r-default exists; kept total anyway.
                let (rule_id, message) = self.default_rule();
                return Ok(Decision {
                    verdict: Action::Deny,
                    capability: Some(cap.id.clone()),
                    rule: rule_id,
                    rung: Some(cap.rung),
                    effect: Some(cap.effect),
                    gate: None,
                    obligation: None,
                    request,
                    identity: identity.clone(),
                    message: Some(message),
                });
            }
        };
        let rung = earned(&cap.id, cap.rung);
        let g = gate(rung, cap.effect);
        // An earned promotion can move a gate to post, but post-hoc review
        // without a rollback handle is the thing Policy::validate refuses at
        // load; at runtime the same rule degrades the gate to pre instead.
        let g = if g == Gate::Post && cap.rollback.is_none() {
            Gate::Pre
        } else {
            g
        };
        let verdict = match rule.action {
            Action::Deny => Action::Deny,
            Action::Hold => Action::Hold,
            Action::Allow if g == Gate::Pre => Action::Hold,
            Action::Allow => Action::Allow,
        };
        let obligation = match (verdict, g) {
            (Action::Allow, Gate::Post) => Some("review".to_string()),
            (Action::Hold, _) => Some("approval".to_string()),
            _ => None,
        };
        let message = match verdict {
            Action::Deny => rule.message.clone(),
            Action::Hold => Some(rule.message.clone().unwrap_or_else(|| format!(
                "This call gates pre at rung {} for effect {} and needs an approval event before it can proceed. Ask a human approver, or lower the ambition of the call to a capability with a lower gate.",
                rung.schema_name(), cap.effect.schema_name()
            ))),
            Action::Allow => None,
        };
        Ok(Decision {
            verdict,
            capability: Some(cap.id.clone()),
            rule: rule.id.clone(),
            rung: Some(rung),
            effect: Some(cap.effect),
            gate: Some(g),
            obligation,
            request,
            identity: identity.clone(),
            message,
        })
    }

    fn default_rule(&self) -> (String, String) {
        let fallback_msg = "No capability declares this tool. Add it to a capability in config/policy.json with an effect class and a rung, then re-run.".to_string();
        self.rules
            .iter()
            .find(|r| r.matcher.capability.is_none() && r.matcher.target_in.is_none())
            .map(|r| {
                (
                    r.id.clone(),
                    r.message.clone().unwrap_or_else(|| fallback_msg.clone()),
                )
            })
            .unwrap_or_else(|| ("r-default".to_string(), fallback_msg))
    }

    /// ci/policy-host-parity: every host deny entry, replayed through this
    /// policy, must resolve to something other than allow, so a denial
    /// short-circuited by the host list is still explicable afterwards.
    pub fn host_parity(&self, settings_json: &str) -> Result<Vec<Fault>, Fault> {
        let settings: Value = serde_json::from_str(settings_json).map_err(|e| {
            Fault::new(
                format!("settings file does not parse as JSON: {e}"),
                "fix .claude/settings.json; it must be the host harness permission document",
            )
        })?;
        let deny = settings["permissions"]["deny"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let identity = json!({"id": "system:policy-check", "source": "local"});
        let mut faults = Vec::new();
        for entry in deny {
            let entry = match entry.as_str() {
                Some(s) => s,
                None => continue,
            };
            let (tool, inner) = match parse_tool_pattern(entry) {
                Some(t) => t,
                None => continue,
            };
            let call = CallRequest {
                tool: tool.to_string(),
                target: sample_target(inner),
                args: json!({}),
            };
            let decision = self.decide(&call, &identity)?;
            if decision.verdict == Action::Allow {
                faults.push(Fault::new(
                    format!(
                        "host deny entry {entry} has no denying or holding rule here: sample target {} resolves to allow under rule {}",
                        call.target, decision.rule
                    ),
                    "add a matching deny rule to config/policy.json so a short-circuited host denial is explicable from the policy",
                ));
            }
        }
        Ok(faults)
    }
}

/// "Tool(pattern)" against a (tool, target) pair. `Bash(git push:*)` is a
/// command prefix; anything else is a wildcard match on the target.
pub fn tool_pattern_matches(pattern: &str, tool: &str, target: &str) -> bool {
    match parse_tool_pattern(pattern) {
        Some((name, inner)) => {
            name == tool
                && match inner.rsplit_once(':') {
                    Some((prefix, "*")) => {
                        target == prefix || target.starts_with(&format!("{prefix} "))
                    }
                    _ => glob_matches(inner, target),
                }
        }
        None => pattern == tool,
    }
}

fn parse_tool_pattern(pattern: &str) -> Option<(&str, &str)> {
    let open = pattern.find('(')?;
    let inner = pattern.get(open + 1..pattern.len().checked_sub(1)?)?;
    if !pattern.ends_with(')') {
        return None;
    }
    Some((&pattern[..open], inner))
}

/// Wildcard match: `*` and `**` match any sequence, `?` one character.
/// A leading `./` on either side is ignored, and a leading `**/` also
/// matches a target with no directory component at all.
pub fn glob_matches(pattern: &str, target: &str) -> bool {
    let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
    let target = target.strip_prefix("./").unwrap_or(target);
    if glob_inner(pattern.as_bytes(), target.as_bytes()) {
        return true;
    }
    match pattern.strip_prefix("**/") {
        Some(rest) => glob_inner(rest.as_bytes(), target.as_bytes()),
        None => false,
    }
}

fn glob_inner(p: &[u8], t: &[u8]) -> bool {
    match (p.first(), t.first()) {
        (None, None) => true,
        (None, Some(_)) => false,
        (Some(b'*'), _) => glob_inner(&p[1..], t) || (!t.is_empty() && glob_inner(p, &t[1..])),
        (Some(b'?'), Some(_)) => glob_inner(&p[1..], &t[1..]),
        (Some(c), Some(d)) if c == d => glob_inner(&p[1..], &t[1..]),
        _ => false,
    }
}

/// Conservative reachability: does `earlier` match everything `later`
/// matches? Only provable structure counts (an absent constraint covers any;
/// pattern sets are compared by literal glob match), so a false positive is
/// impossible and a clever pair of overlapping globs can still slip through.
fn covers(earlier: &Rule, later: &Rule) -> bool {
    let cap_covered = match (&earlier.matcher.capability, &later.matcher.capability) {
        (None, _) => true,
        (Some(a), Some(b)) => a == b,
        (Some(_), None) => false,
    };
    let when_covered = match (&earlier.when, &later.when) {
        (None, _) => true,
        (Some(a), Some(b)) => a.profile == b.profile,
        (Some(_), None) => false,
    };
    let target_covered = match (&earlier.matcher.target_in, &later.matcher.target_in) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(a), Some(b)) => b
            .iter()
            .all(|bp| a.iter().any(|ap| ap == bp || glob_matches(ap, bp))),
    };
    cap_covered && when_covered && target_covered
}

/// A concrete target that the pattern matches, for replaying a host deny
/// entry through the policy.
fn sample_target(inner: &str) -> String {
    if let Some((prefix, "*")) = inner.rsplit_once(':') {
        return format!("{prefix} x");
    }
    inner.replace("**", "x").replace(['*', '?'], "x")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_json(rules: Value, capabilities: Value) -> String {
        json!({
            "v": 1,
            "profile": "laptop",
            "profile_requirements": {},
            "capabilities": capabilities,
            "rules": rules,
        })
        .to_string()
    }

    fn load_str(text: &str) -> Result<Policy, Fault> {
        let dir = std::env::temp_dir().join(format!(
            "gantry-pol-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("policy.json");
        std::fs::write(&p, text).unwrap();
        Policy::load(&p)
    }

    fn caps() -> Value {
        json!([
            {"id": "repo.read", "tools": ["Read(**)", "Grep(**)"], "effect": "read", "rung": "autonomous"},
            {"id": "vcs.publish", "tools": ["Bash(git push:*)"], "effect": "irreversible", "rung": "led"},
            {"id": "shell.exec", "tools": ["Bash(**)"], "effect": "write.local", "rung": "autonomous", "rollback": "git.worktree"},
        ])
    }

    #[test]
    fn gate_table_matches_the_doc() {
        assert_eq!(gate(Rung::Led, Effect::Read), Gate::Pre);
        assert_eq!(gate(Rung::Assisted, Effect::Read), Gate::None);
        assert_eq!(gate(Rung::Assisted, Effect::WriteLocal), Gate::None);
        assert_eq!(gate(Rung::Assisted, Effect::WriteShared), Gate::Pre);
        assert_eq!(gate(Rung::Autonomous, Effect::Read), Gate::None);
        assert_eq!(gate(Rung::Autonomous, Effect::WriteLocal), Gate::Post);
        assert_eq!(gate(Rung::Autonomous, Effect::WriteShared), Gate::Post);
        // Irreversible is pre at every rung, including autonomous.
        assert_eq!(gate(Rung::Autonomous, Effect::Irreversible), Gate::Pre);
        assert_eq!(gate(Rung::Assisted, Effect::Irreversible), Gate::Pre);
    }

    #[test]
    fn glob_semantics() {
        assert!(glob_matches("**", "anything at all"));
        assert!(glob_matches("./.env", ".env"));
        assert!(glob_matches(".env.*", ".env.local"));
        assert!(glob_matches("**/*.pem", "keys/server.pem"));
        assert!(glob_matches("**/*.pem", "server.pem"));
        assert!(glob_matches("**/id_rsa*", "id_rsa"));
        assert!(glob_matches("**/id_rsa*", ".ssh/id_rsa.pub"));
        assert!(glob_matches("rm -rf *", "rm -rf /"));
        assert!(glob_matches("docs/**", "docs/proof/03.md"));
        assert!(!glob_matches("docs/**", "src/main.rs"));
        assert!(!glob_matches("*.pem", "server.crt"));
    }

    #[test]
    fn tool_patterns() {
        assert!(tool_pattern_matches(
            "Bash(git push:*)",
            "Bash",
            "git push origin main"
        ));
        assert!(tool_pattern_matches("Bash(git push:*)", "Bash", "git push"));
        assert!(!tool_pattern_matches(
            "Bash(git push:*)",
            "Bash",
            "git pushx"
        ));
        assert!(!tool_pattern_matches(
            "Bash(git push:*)",
            "Read",
            "git push"
        ));
        assert!(tool_pattern_matches("Read(**)", "Read", "docs/PLAN.md"));
        assert!(!tool_pattern_matches(
            "Read(**/*.pem)",
            "Read",
            "docs/PLAN.md"
        ));
    }

    #[test]
    fn shadowed_deny_refuses_to_load() {
        let text = policy_json(
            json!([
                {"id": "r-allow-read", "match": {"capability": "repo.read"}, "action": "allow"},
                {"id": "r-env", "match": {"capability": "repo.read", "target_in": ["./.env"]}, "action": "deny", "message": "Ask the broker for a handle instead."},
            ]),
            caps(),
        );
        let fault = load_str(&text).unwrap_err();
        assert!(fault.cause.contains("r-env"), "{fault}");
        assert!(fault.cause.contains("unreachable"), "{fault}");
    }

    #[test]
    fn post_gate_without_rollback_refuses_to_load() {
        let text = policy_json(
            json!([{"id": "r-default", "match": {}, "action": "deny", "message": "Declare the tool first."}]),
            json!([{"id": "shell.exec", "tools": ["Bash(**)"], "effect": "write.local", "rung": "autonomous"}]),
        );
        let fault = load_str(&text).unwrap_err();
        assert!(fault.cause.contains("post gate"), "{fault}");
        assert!(fault.fix.contains("rollback"), "{fault}");
    }

    #[test]
    fn deny_without_message_refuses_to_load() {
        let text = policy_json(
            json!([{"id": "r-mute", "match": {"capability": "repo.read"}, "action": "deny"}]),
            caps(),
        );
        let fault = load_str(&text).unwrap_err();
        assert!(fault.cause.contains("r-mute"), "{fault}");
    }

    #[test]
    fn hand_written_wrong_version_refuses_to_load() {
        let mut doc: Value = serde_json::from_str(&policy_json(
            json!([{"id": "r-default", "match": {}, "action": "deny", "message": "Declare the tool first."}]),
            caps(),
        ))
        .unwrap();
        doc["policy_version"] = json!("sha256:0000");
        let fault = load_str(&doc.to_string()).unwrap_err();
        assert!(fault.cause.contains("policy_version"), "{fault}");
    }

    #[test]
    fn decide_walks_first_match_and_gates() {
        let text = policy_json(
            json!([
                {"id": "r-env", "match": {"capability": "repo.read", "target_in": ["./.env"]}, "action": "deny", "message": "Ask the broker for a handle instead."},
                {"id": "r-read", "match": {"capability": "repo.read"}, "action": "allow"},
                {"id": "r-publish", "match": {"capability": "vcs.publish"}, "action": "allow"},
                {"id": "r-shell", "match": {"capability": "shell.exec"}, "action": "allow"},
                {"id": "r-default", "match": {}, "action": "deny", "message": "Declare the tool first."},
            ]),
            caps(),
        );
        let policy = load_str(&text).unwrap();
        let id = json!({"id": "user:test", "source": "local"});
        let call = |tool: &str, target: &str| CallRequest {
            tool: tool.into(),
            target: target.into(),
            args: json!({"t": target}),
        };

        let d = policy.decide(&call("Read", ".env"), &id).unwrap();
        assert_eq!(d.verdict, Action::Deny);
        assert_eq!(d.rule, "r-env");

        let d = policy.decide(&call("Read", "docs/PLAN.md"), &id).unwrap();
        assert_eq!(d.verdict, Action::Allow);
        assert_eq!(d.gate, Some(Gate::None));
        assert_eq!(d.obligation, None);

        // Allow on a pre gate becomes hold with an approval obligation.
        let d = policy
            .decide(&call("Bash", "git push origin main"), &id)
            .unwrap();
        assert_eq!(d.verdict, Action::Hold);
        assert_eq!(d.obligation.as_deref(), Some("approval"));
        assert_eq!(d.rule, "r-publish");

        // Allow on a post gate carries a review obligation.
        let d = policy.decide(&call("Bash", "echo hello"), &id).unwrap();
        assert_eq!(d.verdict, Action::Allow);
        assert_eq!(d.obligation.as_deref(), Some("review"));

        // Undeclared tool: denied, and the decision still names a rule.
        let d = policy.decide(&call("WebSearch", "anything"), &id).unwrap();
        assert_eq!(d.verdict, Action::Deny);
        assert_eq!(d.rule, "r-default");
        assert!(d.message.is_some());
    }

    #[test]
    fn version_is_content_addressed_and_stable() {
        let text = policy_json(
            json!([{"id": "r-default", "match": {}, "action": "deny", "message": "Declare the tool first."}]),
            caps(),
        );
        let p1 = load_str(&text).unwrap();
        let v1 = p1.policy_version.clone().unwrap();
        assert!(v1.starts_with("sha256:"));
        // Loading the same content again yields the same version.
        let p2 = load_str(&text).unwrap();
        assert_eq!(p2.policy_version.unwrap(), v1);
    }
}
