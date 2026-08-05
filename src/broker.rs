//! Slice 03: the tool broker. Every tool call passes here: one registry
//! that refuses loose definitions, one policy evaluation per call, and the
//! request, decision and result on the ledger whatever the outcome. Tool
//! definitions use the MCP shape (name, description, inputSchema) so the
//! registry speaks the wire protocol's vocabulary from day one, even while
//! execution is in-process.

use crate::event::subject_hash;
use crate::gateway::{self, CallResult, ChatMessage, Pinning, Provider};
use crate::ledger::{Ledger, SignedHead};
use crate::policy::{Action, CallRequest, Policy};
use crate::runlog::RunCore;
use crate::sandbox::Sandbox;
use crate::secrets::{CredentialBroker, Substitution};
use crate::Fault;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// An MCP-shaped tool definition, as a client would receive it from
/// `tools/list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// Registry strictness: the checks that make "run any shell command" an
/// unpublishable definition. A schema that accepts any argument shape is a
/// hole in primitive 04, whatever its description says.
pub fn validate_tool_def(def: &ToolDef, policy: &Policy) -> Result<(), Fault> {
    if def.description.trim().is_empty() {
        return Err(Fault::new(
            format!("tool {} has an empty description", def.name),
            "describe what the tool does; the registry publishes nothing it cannot explain",
        ));
    }
    let schema = &def.input_schema;
    if schema["type"] != json!("object") {
        return Err(Fault::new(
            format!("tool {} inputSchema.type is not \"object\"", def.name),
            "declare a closed object schema: type object, named properties, additionalProperties false",
        ));
    }
    let props = match schema["properties"].as_object() {
        Some(p) if !p.is_empty() => p,
        _ => {
            return Err(Fault::new(
                format!(
                    "tool {} declares no properties, so any argument shape is accepted",
                    def.name
                ),
                "name every argument as a typed property; a tool that takes anything is a tool nobody scoped",
            ))
        }
    };
    if schema["additionalProperties"] != json!(false) {
        return Err(Fault::new(
            format!("tool {} does not set additionalProperties false", def.name),
            "close the schema with additionalProperties: false so undeclared arguments are refused",
        ));
    }
    for (prop, spec) in props {
        if spec["type"].as_str().unwrap_or("").is_empty() {
            return Err(Fault::new(
                format!("tool {} property {prop} has no type", def.name),
                "give every property a JSON type; an untyped argument cannot be policy-matched",
            ));
        }
    }
    let declared = policy.capabilities.iter().any(|c| {
        c.tools
            .iter()
            .any(|p| p.split('(').next().unwrap_or(p) == def.name)
    });
    if !declared {
        return Err(Fault::new(
            format!("no capability in the policy declares tool {}", def.name),
            "add the tool to a capability in config/policy.json with an effect class and a rung; undeclared is denied",
        ));
    }
    Ok(())
}

/// What the broker hands back after the ledger already has the full story.
#[derive(Debug, Clone)]
pub struct BrokerResult {
    pub content: String,
    pub taint: bool,
}

pub struct BrokerRun {
    core: RunCore,
    policy: Policy,
    /// name -> schema hash, for the registration check at call time.
    registered: BTreeMap<String, String>,
    identity: Value,
    outstanding_reviews: u64,
    sandbox: Sandbox,
    credentials: CredentialBroker,
    cost_total_usd: f64,
    /// When set, this run executes under a delegated grant and a call whose
    /// capability is outside it is denied at the chokepoint.
    grant: Option<Vec<String>>,
}

impl BrokerRun {
    pub fn open(
        ledger: Ledger,
        policy: Policy,
        workload: &str,
        pin: &Pinning,
    ) -> Result<BrokerRun, Fault> {
        let policy_version = policy.policy_version.clone().ok_or_else(|| {
            Fault::new(
                "policy has no computed version",
                "load the policy with Policy::load, which computes policy_version",
            )
        })?;
        let authority = pin.authority(&policy.profile, &policy_version)?;
        let actor = json!({
            "type": "agent",
            "id": "agent:gantry-broker",
            "identity_source": "local",
            "rung": "assisted",
        });
        let identity = json!({"id": "user:mariano@local", "source": "local"});
        let instruction_pack = authority["instruction_version"].clone();
        let settings_hash = authority["settings_hash"].clone();
        let profile = policy.profile.clone();
        let egress_allow: Vec<String> = policy.profile_requirements["egress"]["allow"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let core = RunCore::open(ledger, actor, authority);
        let sandbox =
            Sandbox::per_run(&crate::sandbox::unique_run_dir("gantry-run"), &egress_allow)?;
        // Only handles some capability declares can hold a value at all.
        let declared_handles: Vec<String> = policy
            .capabilities
            .iter()
            .flat_map(|c| c.credentials.clone())
            .collect();
        let credentials = CredentialBroker::from_env(&declared_handles);
        // profile_requirements.isolation.declared is a claim; the backend the
        // run actually got is observed here and recorded, so a divergence
        // between the two is visible in the record rather than in a promise.
        let declared_isolation = policy.profile_requirements["isolation"]["declared"]
            .as_str()
            .unwrap_or("none")
            .to_string();
        let mut run = BrokerRun {
            core,
            policy,
            registered: BTreeMap::new(),
            identity,
            outstanding_reviews: 0,
            sandbox,
            credentials,
            cost_total_usd: 0.0,
            grant: None,
        };
        run.core.append(
            "run.open",
            json!({
                "profile": profile,
                "workload": workload,
                "instruction_pack": instruction_pack,
                "settings_hash": settings_hash,
                "restored_checkpoint": null,
                "isolation": {
                    "declared": declared_isolation,
                    "active_backend": run.sandbox.kind(),
                    "workdir": run.sandbox.workdir().display().to_string(),
                    "egress_allow": egress_allow,
                },
            }),
        )?;
        Ok(run)
    }

    pub fn sandbox(&self) -> &Sandbox {
        &self.sandbox
    }

    /// A model call inside a broker run, through the same gateway
    /// chokepoint, so an agent loop that reads a document and then acts on
    /// it leaves both halves on one ledger under one run id. `tainted`
    /// names the tool results that fed this prompt, which is what lets a
    /// reader see that untrusted content reached the model.
    pub fn model_call(
        &mut self,
        provider: &Provider,
        messages: &[ChatMessage],
        tainted_inputs: &[String],
    ) -> Result<CallResult, Fault> {
        if !tainted_inputs.is_empty() {
            self.core.append(
                "taint.note",
                json!({
                    "reason": "untrusted tool output is entering a model prompt",
                    "request_ids": tainted_inputs,
                }),
            )?;
        }
        gateway::call_on(&mut self.core, &mut self.cost_total_usd, provider, messages)
    }

    pub fn run_id(&self) -> &str {
        self.core.run_id()
    }

    /// Narrow this run to a delegated grant: the subagent.spawn event puts
    /// the skill and its granted capabilities on the record, and from here
    /// on a call whose matched capability is outside the grant is denied at
    /// the chokepoint with rule r-delegation. Executing a resolved skill is
    /// this plus ordinary calls; the narrowing is enforced where every call
    /// already passes, not in the skill runner's diligence.
    pub fn delegate_scope(
        &mut self,
        skill_id: &str,
        skill_version: &str,
        granted: &[String],
    ) -> Result<(), Fault> {
        self.core.append(
            "subagent.spawn",
            json!({
                "skill": skill_id,
                "version": skill_version,
                "granted": granted,
            }),
        )?;
        self.grant = Some(granted.to_vec());
        Ok(())
    }

    /// Registers the two in-process tools this slice executes. Their
    /// definitions pass the same strictness gate as anything external.
    pub fn register_builtins(&mut self) -> Result<(), Fault> {
        for def in builtin_tools() {
            self.register(&def)?;
        }
        Ok(())
    }

    /// One registration, one `tool.register` event, accepted or not.
    pub fn register(&mut self, def: &ToolDef) -> Result<(), Fault> {
        let schema_hash = subject_hash(&def.input_schema)?;
        match validate_tool_def(def, &self.policy) {
            Ok(()) => {
                self.core.append(
                    "tool.register",
                    json!({
                        "tool": def.name,
                        "schema_version": schema_hash,
                        "schema_hash": schema_hash,
                        "verdict": "registered",
                        "reason": null,
                    }),
                )?;
                self.registered.insert(def.name.clone(), schema_hash);
                Ok(())
            }
            Err(fault) => {
                self.core.append(
                    "tool.register",
                    json!({
                        "tool": def.name,
                        "schema_version": schema_hash,
                        "schema_hash": schema_hash,
                        "verdict": "rejected",
                        "reason": fault.to_string(),
                    }),
                )?;
                Err(Fault::new(
                    format!(
                        "registry rejected tool {} and the rejection is on the ledger: {}",
                        def.name, fault.cause
                    ),
                    fault.fix,
                ))
            }
        }
    }

    /// The chokepoint. Emits `tool.request`, evaluates the policy to exactly
    /// one `policy.decision`, executes only on allow, and emits
    /// `tool.result` in every case.
    pub fn call(&mut self, tool: &str, target: &str) -> Result<BrokerResult, Fault> {
        let schema_version = self.registered.get(tool).cloned().ok_or_else(|| {
            Fault::new(
                format!("tool {tool} is not registered in this run"),
                "register the tool first; the broker executes nothing the registry has not accepted",
            )
        })?;
        let args = builtin_args(tool, target);
        let call = CallRequest {
            tool: tool.to_string(),
            target: target.to_string(),
            args: args.clone(),
        };
        let request_id = format!("{}-req-{}", self.core.run_id(), self.core.event_count());
        let egress_allow = self.policy.profile_requirements["egress"]["allow"].clone();
        let egress_hash = subject_hash(&egress_allow)?;
        // Handle names, never values. The args recorded here are the
        // caller's, so an unsubstituted `{{handle:NAME}}` is what lands on
        // the ledger; substitution happens after the allow, inside the
        // sandbox's environment.
        let credential_handles = CredentialBroker::handles_in(target);
        self.core.append(
            "tool.request",
            json!({
                "request_id": request_id,
                "tool": tool,
                "schema_version": schema_version,
                "args": args,
                "sandbox": self.sandbox.kind(),
                "egress_allowlist_hash": egress_hash,
                "credential_handles": credential_handles,
            }),
        )?;
        // Gate on the rung the capability has earned, replayed from the
        // ledger's capability.run and rung.change history, not the static
        // rung the policy asserts. A demotion recorded by the orchestrator
        // therefore tightens this gate on the very next call.
        let history = self.core.replayable_events()?;
        let mut decision = self
            .policy
            .decide_with_earned(&call, &self.identity, &|cap_id, declared| {
                crate::trust::TrustState::replay(&history, cap_id, declared).rung
            })?;
        // The delegated grant is checked at the same chokepoint, before the
        // one decision event is written, so a sub-agent's denial names its
        // rule like any other.
        if let (Some(grant), Some(cap)) = (&self.grant, decision.capability.as_deref()) {
            if decision.verdict != Action::Deny && !grant.iter().any(|g| g == cap) {
                decision.verdict = Action::Deny;
                decision.rule = "r-delegation".to_string();
                decision.gate = None;
                decision.obligation = None;
                decision.message = Some(format!(
                    "capability {cap} is outside this sub-agent's delegated grant. Run the step under a parent that holds {cap}, or add {cap} to the skill scope and re-delegate."
                ));
            }
        }
        let verdict = decision.verdict;
        let obligation = decision.obligation.clone();
        let message = decision.message.clone();
        let rule = decision.rule.clone();
        let decision_subject = serde_json::to_value(&decision).map_err(|e| {
            Fault::new(
                format!("decision does not serialise: {e}"),
                "report this as a bug; Decision is serialisable by construction",
            )
        })?;
        self.core.append("policy.decision", decision_subject)?;
        match verdict {
            Action::Deny => {
                self.emit_result(&request_id, "denied", None, false, 0, message.as_deref())?;
                Err(Fault::new(
                    format!(
                        "policy denied {tool} on {target}: rule {rule} fired and the decision is on the ledger"
                    ),
                    message.unwrap_or_else(|| "see the policy.decision event for the fix".into()),
                ))
            }
            Action::Hold => {
                // No approval loop exists until slice 06, so a hold cannot yet
                // resolve; the call is blocked and the obligation is recorded.
                self.emit_result(&request_id, "blocked", None, false, 0, message.as_deref())?;
                Err(Fault::new(
                    format!(
                        "policy held {tool} on {target}: rule {rule} gates this call pre and no approval mechanism exists until slice 06"
                    ),
                    message.unwrap_or_else(|| "obtain an approval event, or lower the call's ambition".into()),
                ))
            }
            Action::Allow => {
                if obligation.as_deref() == Some("review") {
                    self.outstanding_reviews += 1;
                }
                // Credential substitution happens here and nowhere earlier:
                // after the policy allowed the call, at the tool boundary,
                // scoped to the capability's declared handles.
                let granted = decision
                    .capability
                    .as_deref()
                    .and_then(|id| self.policy.capabilities.iter().find(|c| c.id == id))
                    .map(|c| c.credentials.clone())
                    .unwrap_or_default();
                let substitution = match self.credentials.substitute(target, &granted) {
                    Ok(s) => s,
                    Err(fault) => {
                        self.emit_result(
                            &request_id,
                            "denied",
                            None,
                            false,
                            0,
                            Some(&fault.to_string()),
                        )?;
                        return Err(Fault::new(
                            format!(
                                "credential broker refused {tool} and the refusal is on the ledger: {}",
                                fault.cause
                            ),
                            fault.fix,
                        ));
                    }
                };
                let started = std::time::Instant::now();
                let outcome = self.execute(tool, target, &substitution);
                let duration_ms = started.elapsed().as_millis() as u64;
                match outcome {
                    Ok(result) => {
                        let result_hash = subject_hash(&result.payload)?;
                        self.emit_result(
                            &request_id,
                            "ok",
                            Some(&result_hash),
                            true,
                            duration_ms,
                            None,
                        )?;
                        Ok(BrokerResult {
                            content: result.content,
                            taint: true,
                        })
                    }
                    Err(fault) => {
                        self.emit_result(
                            &request_id,
                            "blocked",
                            None,
                            false,
                            duration_ms,
                            Some(&fault.to_string()),
                        )?;
                        Err(Fault::new(
                            format!("{tool} on {target} could not execute and the failure is on the ledger: {}", fault.cause),
                            fault.fix,
                        ))
                    }
                }
            }
        }
    }

    fn emit_result(
        &mut self,
        request_id: &str,
        outcome: &str,
        result_hash: Option<&str>,
        taint: bool,
        duration_ms: u64,
        message: Option<&str>,
    ) -> Result<(), Fault> {
        self.core.append(
            "tool.result",
            json!({
                "request_id": request_id,
                "outcome": outcome,
                "result_hash": result_hash,
                "taint": taint,
                "duration_ms": duration_ms,
                "message": message,
            }),
        )
    }

    /// A seal cannot claim clean while post-gate review obligations are
    /// outstanding; the count is written into the seal so the claim is
    /// checkable, not asserted.
    pub fn seal(self, outcome: &str) -> Result<SignedHead, Fault> {
        let outstanding = self.outstanding_reviews;
        let cost = self.cost_total_usd;
        let outcome = if outstanding > 0 && outcome == "complete" {
            "complete-with-outstanding-review".to_string()
        } else {
            outcome.to_string()
        };
        self.core.seal(
            json!({ "outstanding_reviews": outstanding, "cost_total_usd": cost }),
            &outcome,
        )
    }
}

struct ExecResult {
    content: String,
    /// What `result_hash` commits to, richer than the content alone.
    payload: Value,
}

/// The two in-process tools of slice 03. Real sandboxing arrives in slice
/// 04; nothing here executes unless the policy allowed the call.
fn builtin_tools() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "Read".into(),
            description: "Read one file from the working tree and return its contents.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"path": {"type": "string", "description": "path relative to the working tree"}},
                "required": ["path"],
                "additionalProperties": false,
            }),
        },
        ToolDef {
            name: "Bash".into(),
            description: "Run one shell command in the working tree.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"command": {"type": "string", "description": "the command line to run"}},
                "required": ["command"],
                "additionalProperties": false,
            }),
        },
    ]
}

fn builtin_args(tool: &str, target: &str) -> Value {
    match tool {
        "Read" => json!({"path": target}),
        "Bash" => json!({"command": target}),
        _ => json!({"target": target}),
    }
}

impl BrokerRun {
    /// Runs the allowed call. `Read` stays in-process (it cannot write or
    /// reach the network, and the policy already matched the path);
    /// everything that executes code goes through the sandbox with a cleaned
    /// environment and only the granted handles injected.
    fn execute(
        &self,
        tool: &str,
        target: &str,
        substitution: &Substitution,
    ) -> Result<ExecResult, Fault> {
        match tool {
            "Read" => {
                let content = std::fs::read_to_string(target).map_err(|e| {
                    Fault::new(
                        format!("cannot read {target}: {e}"),
                        "check the path exists and is a readable text file",
                    )
                })?;
                Ok(ExecResult {
                    payload: json!({"content": content}),
                    content,
                })
            }
            "Bash" => {
                let out = self
                    .sandbox
                    .command(&substitution.command, &substitution.env)
                    .output()
                    .map_err(|e| {
                        Fault::new(
                            format!("cannot spawn the sandboxed shell: {e}"),
                            "check /usr/bin/sandbox-exec and sh exist; the broker never runs a command outside the sandbox",
                        )
                    })?;
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                let exit = out.status.code().unwrap_or(-1);
                Ok(ExecResult {
                    payload: json!({"stdout": stdout, "stderr": stderr, "exit_code": exit}),
                    content: stdout,
                })
            }
            other => Err(Fault::new(
                format!("tool {other} has no in-process executor yet"),
                "use Read or Bash, or wait for the MCP transport in a later slice",
            )),
        }
    }
}
