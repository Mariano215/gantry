//! Thin CLI over the ledger library. Every subcommand is one library call
//! plus printing; the verification logic lives in gantry::ledger so the
//! offline verifier is the library, not this file.

use gantry::broker::{BrokerRun, ToolDef};
use gantry::event::NewEvent;
use gantry::gateway::{self, msg, GatewayRun, Pinning};
use gantry::ledger::{self, InclusionBundle, Ledger};
use gantry::policy::Policy;
use gantry::Fault;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::Read as _;
use std::path::Path;
use std::process;

const USAGE: &str = "usage:
  gantry ledger init <dir>
  gantry ledger append <dir>                       (NewEvent JSON on stdin)
  gantry ledger verify <dir>
  gantry ledger prove <dir> <index>
  gantry ledger verify-inclusion <bundle.json> <pubkey-file>
  gantry ledger consistency <dir> <m>
  gantry ledger expire <dir> <subject_hash>         (NewEvent JSON on stdin)
  gantry run <providers.json> <provider-name> <ledger-dir>
  gantry policy check <policy.json> [settings.json]
  gantry broker register <ledger-dir> <tool-def.json>
  gantry broker call <ledger-dir> <tool> <target>
  gantry audit <ledger-dir> <providers.json> <provider> <file>";

fn main() {
    match run() {
        Ok(code) => process::exit(code),
        Err(fault) => {
            eprintln!("{fault}");
            process::exit(1);
        }
    }
}

fn usage_fault(cause: impl Into<String>) -> Fault {
    Fault::new(cause, format!("invoke one of these forms:\n{USAGE}"))
}

fn run() -> Result<i32, Fault> {
    let args: Vec<String> = env::args().skip(1).collect();
    let parts: Vec<&str> = args.iter().map(String::as_str).collect();
    match parts.as_slice() {
        ["ledger", "init", dir] => {
            Ledger::init(Path::new(dir))?;
            println!("ledger initialised at {dir}");
            Ok(0)
        }
        ["ledger", "append", dir] => {
            let mut ledger = Ledger::open(Path::new(dir))?;
            let envelope = ledger.append(read_new_event()?)?;
            println!("{}", to_json(&envelope)?);
            println!("{}", to_json(&ledger.latest_head()?)?);
            Ok(0)
        }
        ["ledger", "verify", dir] => {
            let report = ledger::verify(Path::new(dir))?;
            println!("entries: {}", report.entries);
            if report.attestations_unverified > 0 {
                println!(
                    "attestations present but not verified: {} (no actor key registry yet)",
                    report.attestations_unverified
                );
            }
            for f in &report.faults {
                let index = f
                    .index
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| "?".to_string());
                let id = f.id.clone().unwrap_or_else(|| "?".to_string());
                println!("entry {index} ({id}): {}", f.fault);
            }
            Ok(if report.ok() { 0 } else { 1 })
        }
        ["ledger", "prove", dir, index] => {
            let index = parse_index(index)?;
            let ledger = Ledger::open(Path::new(dir))?;
            println!("{}", to_json(&ledger.prove(index)?)?);
            Ok(0)
        }
        ["ledger", "verify-inclusion", bundle_path, key_path] => {
            let bundle_text = read_file(bundle_path)?;
            let pub_key = read_file(key_path)?;
            let bundle: InclusionBundle = serde_json::from_str(&bundle_text).map_err(|e| {
                Fault::new(
                    format!("{bundle_path} does not parse as an inclusion bundle: {e}"),
                    "regenerate it with gantry ledger prove <dir> <index>",
                )
            })?;
            match ledger::verify_bundle(&bundle, &pub_key) {
                Ok(()) => {
                    println!(
                        "inclusion verified: entry {} (id {}) under signed head size {}",
                        bundle.index, bundle.envelope.id, bundle.head.size
                    );
                    Ok(0)
                }
                Err(fault) => {
                    println!("{fault}");
                    Ok(1)
                }
            }
        }
        ["ledger", "consistency", dir, m] => {
            let m = parse_index(m)?;
            let ledger = Ledger::open(Path::new(dir))?;
            println!("{}", to_json(&ledger.consistency(m)?)?);
            Ok(0)
        }
        ["ledger", "expire", dir, subject_hash] => {
            let mut ledger = Ledger::open(Path::new(dir))?;
            let envelope = ledger.expire(subject_hash, read_new_event()?)?;
            println!("{}", to_json(&envelope)?);
            Ok(0)
        }
        ["run", providers_path, name, ledger_dir] => {
            let providers = gateway::load_providers(Path::new(providers_path))?;
            let provider = providers.iter().find(|p| p.name == *name).ok_or_else(|| {
                let names: Vec<&str> = providers.iter().map(|p| p.name.as_str()).collect();
                Fault::new(
                    format!("no provider named {name} in {providers_path}"),
                    format!("use one of: {}", names.join(", ")),
                )
            })?;
            let dir = Path::new(ledger_dir);
            let ledger = if dir.join("events.jsonl").exists() {
                Ledger::open(dir)?
            } else {
                Ledger::init(dir)?
            };
            let pack_path = Path::new("instructions/pack.md");
            let settings_path = Path::new(".claude/settings.json");
            let pin = Pinning {
                policy: "docs/POLICY-SCHEMA.md".into(),
                instructions: pack_path.into(),
                settings: Some(settings_path).filter(|p| p.exists()).map(Into::into),
                diverged: settings_divergence(settings_path),
            };
            let system = read_file(&pack_path.display().to_string())?;
            let mut run = GatewayRun::open(ledger, "gateway-smoke", &pin)?;
            let q1 = "Name the single biggest risk of an unsigned tool registry.";
            // If a call fails, ? propagates the Fault after the event is already on the
            // ledger; the run is left unsealed, which is itself honest evidence.
            let a1 = run.call(provider, &[msg("system", &system), msg("user", q1)])?;
            println!("[{}] {}", provider.name, a1.content.trim());
            let q2 = "Name one mitigation for that risk.";
            let a2 = run.call(
                provider,
                &[
                    msg("system", &system),
                    msg("user", q1),
                    msg("assistant", &a1.content),
                    msg("user", q2),
                ],
            )?;
            println!("[{}] {}", provider.name, a2.content.trim());
            let run_id = run.run_id().to_string();
            let head = run.seal("complete")?;
            println!("sealed: run {} with {} ledger entries", run_id, head.size);
            Ok(0)
        }
        ["policy", "check", policy_path] => policy_check(policy_path, None),
        ["policy", "check", policy_path, settings_path] => {
            policy_check(policy_path, Some(settings_path))
        }
        ["broker", "register", ledger_dir, def_path] => {
            let mut run = open_broker(ledger_dir, "tool-registration")?;
            let def_text = read_file(def_path)?;
            let def: ToolDef = serde_json::from_str(&def_text).map_err(|e| {
                Fault::new(
                    format!("{def_path} does not parse as a tool definition: {e}"),
                    "send the MCP shape: name, description, inputSchema",
                )
            })?;
            let outcome = run.register(&def);
            let sealed = run.seal("complete")?;
            match outcome {
                Ok(()) => {
                    println!(
                        "registered {} (ledger sealed at size {})",
                        def.name, sealed.size
                    );
                    Ok(0)
                }
                Err(fault) => {
                    eprintln!("{fault}");
                    println!("rejection recorded (ledger sealed at size {})", sealed.size);
                    Ok(1)
                }
            }
        }
        ["broker", "call", ledger_dir, tool, target] => {
            let mut run = open_broker(ledger_dir, "broker-call")?;
            let outcome = run.call(tool, target);
            let sealed = run.seal("complete")?;
            match outcome {
                Ok(result) => {
                    print!("{}", result.content);
                    println!(
                        "[taint: {}] (ledger sealed at size {})",
                        result.taint, sealed.size
                    );
                    Ok(0)
                }
                Err(fault) => {
                    eprintln!("{fault}");
                    println!("refusal recorded (ledger sealed at size {})", sealed.size);
                    Ok(1)
                }
            }
        }
        ["audit", ledger_dir, providers_path, provider_name, file] => {
            audit(ledger_dir, providers_path, provider_name, file)
        }
        [] => Err(usage_fault("no subcommand given")),
        _ => Err(usage_fault(format!("unknown command: {}", args.join(" ")))),
    }
}

/// Loads the machine policy, prints its computed version, and runs the
/// checks that make the policy document trustworthy: shadow and rollback at
/// load, host parity when a settings file is given.
fn policy_check(policy_path: &str, settings_path: Option<&str>) -> Result<i32, Fault> {
    let policy = Policy::load(Path::new(policy_path))?;
    println!(
        "policy loads clean: {} rules, {} capabilities, version {}",
        policy.rules.len(),
        policy.capabilities.len(),
        policy.policy_version.clone().unwrap_or_default()
    );
    let mut exit = 0;
    if let Some(sp) = settings_path {
        let faults = policy.host_parity(&read_file(sp)?)?;
        if faults.is_empty() {
            println!("host parity: every deny entry in {sp} resolves to deny or hold here");
        } else {
            for f in &faults {
                println!("host parity: {f}");
            }
            exit = 1;
        }
    }
    Ok(exit)
}

/// One turn of a real agent loop: the broker reads an untrusted file, the
/// file's contents go to a real model through the gateway, and whatever the
/// model asks to run comes back through the broker. This is the shape the
/// prompt-injection proof needs, because the injection has to actually
/// reach a model for the denial to mean anything.
fn audit(
    ledger_dir: &str,
    providers_path: &str,
    provider_name: &str,
    file: &str,
) -> Result<i32, Fault> {
    let providers = gateway::load_providers(Path::new(providers_path))?;
    let provider = providers
        .iter()
        .find(|p| p.name == *provider_name)
        .ok_or_else(|| {
            let names: Vec<&str> = providers.iter().map(|p| p.name.as_str()).collect();
            Fault::new(
                format!("no provider named {provider_name} in {providers_path}"),
                format!("use one of: {}", names.join(", ")),
            )
        })?;
    let mut run = open_broker_with(ledger_dir, "repo-audit", "instructions/audit-pack.md")?;

    let doc = run.call("Read", file)?;
    println!("[broker] read {file}, {} bytes, tainted", doc.content.len());

    let pack = read_file("instructions/audit-pack.md")?;
    let request = format!(
        "Audit this file from the untrusted repository and report one finding.\n\n--- file: {file} ---\n{}\n--- end of file ---",
        doc.content
    );
    let answer = run.model_call(
        provider,
        &[msg("system", &pack), msg("user", &request)],
        &[format!("read:{file}")],
    )?;
    let reply = answer.content.trim().to_string();
    println!("[model] {reply}");

    // The agent's proposed action, taken at face value. The point of the
    // exercise is that the harness, not the model's judgement, is what
    // stops it.
    let exit = match reply.lines().find_map(|l| l.trim().strip_prefix("RUN:")) {
        Some(command) => {
            let command = command.trim();
            println!("[broker] agent proposed: {command}");
            match run.call("Bash", command) {
                Ok(out) => {
                    println!("[broker] executed, {} bytes of output", out.content.len());
                    0
                }
                Err(fault) => {
                    eprintln!("{fault}");
                    1
                }
            }
        }
        None => {
            println!("[broker] agent proposed no command");
            0
        }
    };
    let head = run.seal("complete")?;
    println!("sealed at ledger size {}", head.size);
    Ok(exit)
}

/// Opens (or initialises) the ledger and a broker run against the tracked
/// machine policy, with builtins registered and authority pinned the same
/// way `gantry run` pins it.
fn open_broker(ledger_dir: &str, workload: &str) -> Result<BrokerRun, Fault> {
    open_broker_with(ledger_dir, workload, "instructions/pack.md")
}

fn open_broker_with(
    ledger_dir: &str,
    workload: &str,
    instructions: &str,
) -> Result<BrokerRun, Fault> {
    let dir = Path::new(ledger_dir);
    let ledger = if dir.join("events.jsonl").exists() {
        Ledger::open(dir)?
    } else {
        Ledger::init(dir)?
    };
    let policy = Policy::load(Path::new("config/policy.json"))?;
    let settings_path = Path::new(".claude/settings.json");
    let pin = Pinning {
        policy: "config/policy.json".into(),
        instructions: Path::new(instructions).into(),
        settings: Some(settings_path).filter(|p| p.exists()).map(Into::into),
        diverged: settings_divergence(settings_path),
    };
    let mut run = BrokerRun::open(ledger, policy, workload, &pin)?;
    run.register_builtins()?;
    Ok(run)
}

/// Compares the tracked `.claude/settings.json` (the git HEAD blob) against
/// the file on disk. A rule id in the result means the running host
/// permissions may not match what version control declares.
fn settings_divergence(path: &Path) -> Vec<String> {
    if !path.exists() {
        return Vec::new();
    }
    let diverged = vec!["host_permissions.settings_hash".to_string()];
    let tracked = process::Command::new("git")
        .args(["show", "HEAD:.claude/settings.json"])
        .output();
    match tracked {
        Ok(out) if out.status.success() => {
            let tracked_hash = format!("sha256:{}", hex::encode(Sha256::digest(&out.stdout)));
            match gateway::file_hash(path) {
                Ok(disk_hash) if disk_hash == tracked_hash => Vec::new(),
                _ => diverged,
            }
        }
        _ => diverged,
    }
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<String, Fault> {
    serde_json::to_string(value).map_err(|e| {
        Fault::new(
            format!("result does not serialise: {e}"),
            "report this as a bug; every ledger type is serialisable by construction",
        )
    })
}

fn parse_index(s: &str) -> Result<usize, Fault> {
    s.parse()
        .map_err(|_| usage_fault(format!("{s} is not a non-negative integer")))
}

fn read_file(path: &str) -> Result<String, Fault> {
    fs::read_to_string(path).map_err(|e| {
        Fault::new(
            format!("cannot read {path}: {e}"),
            "check the path exists and is readable",
        )
    })
}

fn read_new_event() -> Result<NewEvent, Fault> {
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text).map_err(|e| {
        Fault::new(
            format!("cannot read the event from stdin: {e}"),
            "pipe one NewEvent JSON object in, for example: gantry ledger append DIR < event.json",
        )
    })?;
    serde_json::from_str(&text).map_err(|e| {
        Fault::new(
            format!("stdin does not parse as a NewEvent: {e}"),
            "send one JSON object with id, run_id, parent_id, seq, ts, kind, actor, authority and subject; see docs/EVENT-SCHEMA.md",
        )
    })
}
