//! Thin CLI over the ledger library. Every subcommand is one library call
//! plus printing; the verification logic lives in gantry::ledger so the
//! offline verifier is the library, not this file.

use gantry::broker::{BrokerRun, ToolDef};
use gantry::durable::DurableRun;
use gantry::event::NewEvent;
use gantry::gateway::{self, msg, GatewayRun, Pinning};
use gantry::graph::Graph;
use gantry::ledger::{self, InclusionBundle, Ledger};
use gantry::policy::Policy;
use gantry::scorer::Scoring;
use gantry::sensor::{Sensor, SensorRun, Verdict};
use gantry::skills::SkillManifest;
use gantry::trust::Orchestrator;
use gantry::Fault;
use serde_json::json;
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
  gantry audit <ledger-dir> <providers.json> <provider> <file>
  gantry sensor gate <ledger-dir> <sensor.json> <artifact>
  gantry sensor repair <ledger-dir> <sensor.json> <artifact> <providers.json> <provider>
  gantry orchestrate step <ledger-dir> <capability> <sensor.json> <artifact> [approver]
  gantry trust history <ledger-dir> <capability>
  gantry durable run <ledger-dir> <task-id> <crash-after|-> <file>...
  gantry durable resume <ledger-dir> <task-id> <file>...
  gantry durable show <ledger-dir> <task-id>
  gantry graph build <graph.json> <file>...
  gantry graph query <ledger-dir> <graph.json> <symbol>
  gantry graph compare <graph.json> <symbol> <file>...
  gantry score <ledger-dir> [scoring.json] [console.html]
  gantry skill resolve <ledger-dir> <package-dir> [pubkey-hex]
  gantry skill delegate <parent-caps-csv> <package-dir>
  gantry skill run <ledger-dir> <package-dir> <parent-caps-csv>
  gantry skill sign <package-dir> <seed-hex>
  gantry template validate <template-dir>
  gantry template init <template-dir> <dest-dir>";

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
            let keys_path = Path::new("config/actor-keys.json");
            let actor_keys: Vec<String> = if keys_path.exists() {
                gantry::skills::KeyRegistry::load(keys_path)?.key_hexes()
            } else {
                Vec::new()
            };
            let report = ledger::verify_with_actor_keys(Path::new(dir), &actor_keys)?;
            println!("entries: {}", report.entries);
            if report.attestations_verified > 0 {
                println!(
                    "attestations verified against config/actor-keys.json: {}",
                    report.attestations_verified
                );
            }
            if report.attestations_unverified > 0 {
                println!(
                    "attestations present but not verified: {} (no registered actor key matches their key id; register it in config/actor-keys.json)",
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
        ["orchestrate", "step", ledger_dir, capability, sensor_path, artifact] => {
            orchestrate_step(ledger_dir, capability, sensor_path, artifact, None)
        }
        ["orchestrate", "step", ledger_dir, capability, sensor_path, artifact, approver] => {
            orchestrate_step(
                ledger_dir,
                capability,
                sensor_path,
                artifact,
                Some(approver),
            )
        }
        ["trust", "history", ledger_dir, capability] => trust_history(ledger_dir, capability),
        ["durable", "run", ledger_dir, task_id, crash_after, files @ ..] if !files.is_empty() => {
            durable_run(ledger_dir, task_id, crash_after, files)
        }
        ["durable", "resume", ledger_dir, task_id, files @ ..] if !files.is_empty() => {
            durable_resume(ledger_dir, task_id, files)
        }
        ["durable", "show", ledger_dir, task_id] => durable_show(ledger_dir, task_id),
        ["graph", "build", graph_path, files @ ..] if !files.is_empty() => {
            graph_build(graph_path, files)
        }
        ["graph", "query", ledger_dir, graph_path, symbol] => {
            graph_query(ledger_dir, graph_path, symbol)
        }
        ["graph", "compare", graph_path, symbol, files @ ..] if !files.is_empty() => {
            graph_compare(graph_path, symbol, files)
        }
        ["score", ledger_dir] => score(ledger_dir, "config/scoring.json", None),
        ["score", ledger_dir, rules] => score(ledger_dir, rules, None),
        ["score", ledger_dir, rules, console] => score(ledger_dir, rules, Some(console)),
        ["skill", "resolve", ledger_dir, package_dir] => {
            skill_resolve(ledger_dir, package_dir, &[])
        }
        ["skill", "resolve", ledger_dir, package_dir, key] => {
            skill_resolve(ledger_dir, package_dir, &[key.to_string()])
        }
        ["skill", "delegate", parent_caps, package_dir] => skill_delegate(parent_caps, package_dir),
        ["skill", "run", ledger_dir, package_dir, parent_caps] => {
            skill_run(ledger_dir, package_dir, parent_caps)
        }
        ["skill", "sign", package_dir, seed_hex] => skill_sign(package_dir, seed_hex),
        ["template", "validate", template_dir] => template_validate(template_dir).map(|_| 0),
        ["template", "init", template_dir, dest_dir] => template_init(template_dir, dest_dir),
        ["sensor", "gate", ledger_dir, sensor_path, artifact] => {
            sensor_gate(ledger_dir, sensor_path, artifact, None)
        }
        ["sensor", "repair", ledger_dir, sensor_path, artifact, providers_path, provider_name] => {
            sensor_gate(
                ledger_dir,
                sensor_path,
                artifact,
                Some((providers_path, provider_name)),
            )
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

/// Process a list of files as a durable task, checkpointing after each. With
/// a numeric crash-after, the process exits without sealing once that many
/// steps are done, which is the kill the resume recovers from; `-` runs to
/// completion.
fn durable_run(
    ledger_dir: &str,
    task_id: &str,
    crash_after: &str,
    files: &[&str],
) -> Result<i32, Fault> {
    let policy = Policy::load(Path::new("config/policy.json"))?;
    let dir = Path::new(ledger_dir);
    let ledger = if dir.join("events.jsonl").exists() {
        Ledger::open(dir)?
    } else {
        Ledger::init(dir)?
    };
    let mut run = DurableRun::open(ledger, &policy, task_id, &durable_pin())?;
    let crash = if crash_after == "-" {
        None
    } else {
        Some(
            crash_after
                .parse::<usize>()
                .map_err(|_| usage_fault(format!("{crash_after} is not a step count or -")))?,
        )
    };
    for (i, file) in files.iter().enumerate() {
        let bytes = fs::read(file).map_err(|e| {
            Fault::new(
                format!("cannot read step file {file}: {e}"),
                "check the path; every durable step reads one file",
            )
        })?;
        let result = json!({
            "file": file,
            "bytes": bytes.len(),
            "hash": format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
        });
        run.checkpoint_step(i, file, result)?;
        println!(
            "[durable] step {i} done: {file} ({} bytes), checkpointed",
            bytes.len()
        );
        if crash == Some(i + 1) {
            // The kill: leave the run unsealed and exit non-zero. Everything
            // through this checkpoint is already on the append-only ledger.
            eprintln!("[durable] simulating a crash after step {i}; run left unsealed");
            process::exit(137);
        }
    }
    let head = run.seal("complete")?;
    println!("[durable] sealed at ledger size {}", head.size);
    Ok(0)
}

/// Continue a killed durable task from its last checkpoint on the ledger.
fn durable_resume(ledger_dir: &str, task_id: &str, files: &[&str]) -> Result<i32, Fault> {
    let policy = Policy::load(Path::new("config/policy.json"))?;
    let ledger = Ledger::open(Path::new(ledger_dir))?;
    let (mut run, restored) = DurableRun::resume(ledger, &policy, task_id, &durable_pin())?;
    println!(
        "[durable] resumed from {} at step {} ({} results restored)",
        restored.checkpoint_id,
        restored.next_step,
        restored.results.len()
    );
    for (i, file) in files.iter().enumerate().skip(restored.next_step) {
        let file = *file;
        let bytes = fs::read(file).map_err(|e| {
            Fault::new(
                format!("cannot read step file {file}: {e}"),
                "pass the same file list as the original run",
            )
        })?;
        let result = json!({
            "file": file,
            "bytes": bytes.len(),
            "hash": format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
        });
        run.checkpoint_step(i, file, result)?;
        println!(
            "[durable] step {i} done: {file} ({} bytes), checkpointed",
            bytes.len()
        );
    }
    let total = run.results().len();
    let head = run.seal("complete")?;
    println!(
        "[durable] sealed at ledger size {head_size} with {total} total steps",
        head_size = head.size
    );
    Ok(0)
}

/// Print the seam for a durable task: which run stopped where, which restored.
fn durable_show(ledger_dir: &str, task_id: &str) -> Result<i32, Fault> {
    let ledger = Ledger::open(Path::new(ledger_dir))?;
    let events = ledger.events_with_subjects()?;
    println!("durable task {task_id}:");
    for line in gantry::durable::seam(&events, task_id) {
        println!("  {line}");
    }
    Ok(0)
}

fn durable_pin() -> Pinning {
    let settings_path = Path::new(".claude/settings.json");
    Pinning {
        policy: "config/policy.json".into(),
        instructions: Path::new("instructions/pack.md").into(),
        settings: Some(settings_path).filter(|p| p.exists()).map(Into::into),
        diverged: settings_divergence(settings_path),
    }
}

/// Score a ledger against the rules, print the scorecard, emit a
/// score.snapshot onto that ledger, and optionally render an HTML console.
/// The scorer reads telemetry only, so the number derives from what ran.
fn score(ledger_dir: &str, rules_path: &str, console: Option<&str>) -> Result<i32, Fault> {
    let scoring = Scoring::load(Path::new(rules_path))?;
    let mut ledger = Ledger::open(Path::new(ledger_dir))?;
    let events = ledger.events_with_subjects()?;
    let snapshot = scoring.score(&events);
    print!("{}", snapshot.markdown());

    // Record the score on the ledger it scored: the platform observing
    // itself is itself an event.
    let policy = Policy::load(Path::new("config/policy.json"))?;
    let policy_version = policy.policy_version.clone().unwrap_or_default();
    let pin = durable_pin();
    let authority = pin.authority(&policy.profile, &policy_version)?;
    ledger.append(gantry::event::NewEvent {
        id: format!("score-{}", snapshot.events_scored),
        run_id: "run-scorer".to_string(),
        parent_id: None,
        seq: 0,
        ts: gantry::gateway::rfc3339_now(),
        kind: "score.snapshot".to_string(),
        actor: json!({"type": "system", "id": "system:scorer", "identity_source": "local", "rung": null}),
        authority,
        subject: snapshot.subject(),
        redacted: vec![],
        attestation: None,
    })?;

    if let Some(path) = console {
        fs::write(path, console_html(&snapshot)).map_err(|e| {
            Fault::new(
                format!("cannot write console {path}: {e}"),
                "check the directory is writable",
            )
        })?;
        println!("\nconsole written to {path}");
    }
    Ok(0)
}

/// A self-contained static console. The plan's UI is static assets the binary
/// serves; this is that asset, generated from the snapshot. Serving it is a
/// thin future add.
fn console_html(snapshot: &gantry::scorer::ScoreSnapshot) -> String {
    let overall = snapshot
        .overall
        .map(|n| n.to_string())
        .unwrap_or_else(|| "N/A".into());
    let mut rows = String::new();
    for p in &snapshot.scores {
        let (score, cls) = match p.score {
            Some(n) if n >= 4 => (n.to_string(), "good"),
            Some(n) if n >= 3 => (n.to_string(), "ok"),
            Some(n) => (n.to_string(), "low"),
            None => ("N/A".to_string(), "na"),
        };
        rows.push_str(&format!(
            "<tr class=\"{cls}\"><td>{:02}</td><td>{}</td><td class=\"score\">{score}</td><td>{}</td></tr>\n",
            p.primitive, p.name, p.evidence
        ));
    }
    format!(
        "<!doctype html><meta charset=utf-8><title>Gantry conformance</title>\
<style>body{{font:15px system-ui;margin:2rem;max-width:60rem}}table{{border-collapse:collapse;width:100%}}\
td,th{{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}}.score{{font-weight:700;text-align:center}}\
tr.good{{background:#e6f4ea}}tr.ok{{background:#fff8e1}}tr.low{{background:#fdecea}}tr.na{{color:#888}}\
.overall{{font-size:1.4rem;margin:1rem 0}}</style>\
<h1>Gantry conformance, scored from its own telemetry</h1>\
<p class=overall><b>Overall level: {overall}</b> (the minimum across scored primitives, not the average)</p>\
<table><tr><th>#</th><th>Primitive</th><th>Score</th><th>Evidence</th></tr>\n{rows}</table>\
<p>Rules {}, {} events scored. Overall is the minimum by rule: one weak layer caps the whole.</p>",
        snapshot.rules_version, snapshot.events_scored
    )
}

/// Resolve a skill package and record the verdict on the ledger. A broken
/// manifest, a missing step, or an unverifiable signature is refused here, at
/// resolve time, before any run consumes the skill. The refusal is on the
/// record too.
fn skill_resolve(ledger_dir: &str, package_dir: &str, extra_keys: &[String]) -> Result<i32, Fault> {
    let pkg = Path::new(package_dir);
    let manifest = SkillManifest::load(&pkg.join("skill.json"))?;
    // The managed registry is the tracked trust root; a key passed on the
    // command line is added to it for one resolution, not a replacement.
    let registry_path = Path::new("config/skill-keys.json");
    let mut registry: Vec<String> = if registry_path.exists() {
        gantry::skills::KeyRegistry::load(registry_path)?.key_hexes()
    } else {
        Vec::new()
    };
    registry.extend_from_slice(extra_keys);
    let dir = Path::new(ledger_dir);
    let mut ledger = if dir.join("events.jsonl").exists() {
        Ledger::open(dir)?
    } else {
        Ledger::init(dir)?
    };
    let outcome = manifest.resolve(pkg, &registry);
    let (verdict, reason, subject) = match &outcome {
        Ok(resolved) => ("resolved", None, resolved.subject()),
        Err(fault) => (
            "rejected",
            Some(fault.to_string()),
            json!({
                "id": manifest.id,
                "version": manifest.version,
                "verdict": "rejected",
                "reason": fault.to_string(),
            }),
        ),
    };
    append_system_event(&mut ledger, "system:resolver", "skill.resolve", subject)?;
    match outcome {
        Ok(resolved) => {
            println!(
                "skill {} v{} resolved: {} step(s), signature {}, scope {:?}",
                resolved.id,
                resolved.version,
                resolved.steps.len(),
                resolved.signature_state,
                resolved.scope
            );
            let _ = (verdict, reason);
            Ok(0)
        }
        Err(fault) => {
            eprintln!("{fault}");
            println!("rejection recorded on the ledger");
            Ok(1)
        }
    }
}

/// Resolve a skill, delegate a narrowed grant from the parent's, then
/// execute each step through the broker chokepoint as a sub-agent run. A
/// broken package refuses before anything executes; a step needing a
/// capability outside the grant is denied at the chokepoint with rule
/// r-delegation, and every request, decision and result is on the ledger.
fn skill_run(ledger_dir: &str, package_dir: &str, parent_caps: &str) -> Result<i32, Fault> {
    let pkg = Path::new(package_dir);
    let manifest = SkillManifest::load(&pkg.join("skill.json"))?;
    let registry_path = Path::new("config/skill-keys.json");
    let registry: Vec<String> = if registry_path.exists() {
        gantry::skills::KeyRegistry::load(registry_path)?.key_hexes()
    } else {
        Vec::new()
    };
    let dir = Path::new(ledger_dir);
    let mut ledger = if dir.join("events.jsonl").exists() {
        Ledger::open(dir)?
    } else {
        Ledger::init(dir)?
    };
    let resolved = match manifest.resolve(pkg, &registry) {
        Ok(r) => {
            append_system_event(&mut ledger, "system:resolver", "skill.resolve", r.subject())?;
            r
        }
        Err(fault) => {
            append_system_event(
                &mut ledger,
                "system:resolver",
                "skill.resolve",
                json!({
                    "id": manifest.id,
                    "version": manifest.version,
                    "verdict": "rejected",
                    "reason": fault.to_string(),
                }),
            )?;
            eprintln!("{fault}");
            println!("rejection recorded; nothing executed");
            return Ok(1);
        }
    };
    let parent: Vec<String> = parent_caps
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    let granted = gantry::skills::delegate(&parent, &resolved.scope)?;
    drop(ledger);

    let mut run = open_broker(ledger_dir, &format!("skill:{}", resolved.id))?;
    run.delegate_scope(&resolved.id, &resolved.version, &granted)?;
    let mut failures = 0u32;
    for step in &resolved.steps {
        let step_path = pkg.join("steps").join(format!("{step}.md"));
        match run.call("Read", &step_path.display().to_string()) {
            Ok(result) => println!(
                "step {step}: {} bytes read under the grant",
                result.content.len()
            ),
            Err(fault) => {
                eprintln!("step {step}: {fault}");
                failures += 1;
            }
        }
    }
    let sealed = run.seal(if failures == 0 { "complete" } else { "failed" })?;
    println!(
        "skill {} v{} ran {} step(s), {} refused, grant {:?} (ledger sealed at size {})",
        resolved.id,
        resolved.version,
        resolved.steps.len(),
        failures,
        granted,
        sealed.size
    );
    Ok(if failures == 0 { 0 } else { 1 })
}

/// A harness template is a bundle of policy, providers, sensors and signing
/// keys that must validate as a whole: every part loads through the same
/// validator the running system uses, so a template cannot ship a
/// configuration the platform would refuse at runtime. Returns the file list
/// for `template init` to copy.
fn template_validate(template_dir: &str) -> Result<Vec<std::path::PathBuf>, Fault> {
    let dir = Path::new(template_dir);
    let mut files = Vec::new();

    let policy_path = dir.join("policy.json");
    let policy = Policy::load(&policy_path)?;
    files.push(policy_path);

    let providers_path = dir.join("providers.json");
    let providers = gateway::load_providers(&providers_path)?;
    files.push(providers_path);

    let mut sensor_count = 0usize;
    let sensors_dir = dir.join("sensors");
    if sensors_dir.is_dir() {
        let entries = fs::read_dir(&sensors_dir).map_err(|e| {
            Fault::new(
                format!("cannot list {}: {e}", sensors_dir.display()),
                "check the sensors directory is readable",
            )
        })?;
        for entry in entries {
            let path = entry
                .map_err(|e| {
                    Fault::new(
                        format!("cannot read an entry in {}: {e}", sensors_dir.display()),
                        "check the sensors directory is readable",
                    )
                })?
                .path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                Sensor::load(&path)?;
                sensor_count += 1;
                files.push(path);
            }
        }
    }

    let keys_path = dir.join("skill-keys.json");
    let key_count = if keys_path.exists() {
        let n = gantry::skills::KeyRegistry::load(&keys_path)?.keys.len();
        files.push(keys_path);
        n
    } else {
        0
    };

    println!(
        "template {template_dir} validates: profile {}, {} capabilities, {} rules, {} provider(s), {} sensor(s), {} signing key(s)",
        policy.profile,
        policy.capabilities.len(),
        policy.rules.len(),
        providers.len(),
        sensor_count,
        key_count
    );
    Ok(files)
}

/// Copy a validated template into a new harness directory. Validation runs
/// first, so a broken bundle is refused before a single file lands, and an
/// existing file is never overwritten.
fn template_init(template_dir: &str, dest_dir: &str) -> Result<i32, Fault> {
    let files = template_validate(template_dir)?;
    let src_root = Path::new(template_dir);
    let dest_root = Path::new(dest_dir);
    for src in &files {
        let rel = src.strip_prefix(src_root).map_err(|_| {
            Fault::new(
                format!("{} is outside the template directory", src.display()),
                "report this as a bug; validate only returns paths under the template",
            )
        })?;
        let dest = dest_root.join(rel);
        if dest.exists() {
            return Err(Fault::new(
                format!("{} already exists", dest.display()),
                "init refuses to overwrite; move the existing file away or choose an empty destination",
            ));
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                Fault::new(
                    format!("cannot create {}: {e}", parent.display()),
                    "check the destination is writable",
                )
            })?;
        }
        fs::copy(src, &dest).map_err(|e| {
            Fault::new(
                format!("cannot copy {} to {}: {e}", src.display(), dest.display()),
                "check the destination is writable",
            )
        })?;
        println!("wrote {}", dest.display());
    }
    println!("harness initialised at {dest_dir} from template {template_dir}");
    Ok(0)
}

/// Sign a package's skill.json in place with the given ed25519 seed and print
/// the public key to register. A build helper for fixtures and publishing.
fn skill_sign(package_dir: &str, seed_hex: &str) -> Result<i32, Fault> {
    let manifest_path = Path::new(package_dir).join("skill.json");
    let manifest = SkillManifest::load(&manifest_path)?;
    let signed = manifest.signed_with(seed_hex)?;
    let json = serde_json::to_string_pretty(&signed).map_err(|e| {
        Fault::new(
            format!("signed manifest does not serialise: {e}"),
            "report this as a bug",
        )
    })?;
    fs::write(&manifest_path, json + "\n").map_err(|e| {
        Fault::new(
            format!("cannot write {}: {e}", manifest_path.display()),
            "check the package directory is writable",
        )
    })?;
    let seed: [u8; 32] = hex::decode(seed_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| usage_fault("seed is not 32 hex-encoded bytes"))?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pub_hex = hex::encode(sk.verifying_key().as_bytes());
    println!(
        "signed {}; register this public key: {pub_hex}",
        manifest_path.display()
    );
    Ok(0)
}

/// Show delegation narrowing a parent's grant by a skill's scope, refusing to
/// widen. Read-only; prints the granted set or the refusal.
fn skill_delegate(parent_caps: &str, package_dir: &str) -> Result<i32, Fault> {
    let manifest = SkillManifest::load(&Path::new(package_dir).join("skill.json"))?;
    let parent: Vec<String> = parent_caps
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    match gantry::skills::delegate(&parent, &manifest.scope.capabilities) {
        Ok(granted) => {
            println!(
                "delegation to skill {}: parent holds {:?}, skill scope {:?}, granted {:?}",
                manifest.id, parent, manifest.scope.capabilities, granted
            );
            Ok(0)
        }
        Err(fault) => {
            eprintln!("{fault}");
            Ok(1)
        }
    }
}

/// Append a system-actor event to a ledger with authority pinned the tracked
/// way, for the small out-of-run records (skill resolutions, scores).
fn append_system_event(
    ledger: &mut Ledger,
    actor_id: &str,
    kind: &str,
    subject: serde_json::Value,
) -> Result<(), Fault> {
    let policy = Policy::load(Path::new("config/policy.json"))?;
    let policy_version = policy.policy_version.clone().unwrap_or_default();
    let pin = durable_pin();
    let authority = pin.authority(&policy.profile, &policy_version)?;
    ledger.append(NewEvent {
        id: format!("{kind}-{}", ledger.size()),
        run_id: format!("run-{kind}"),
        parent_id: None,
        seq: 0,
        ts: gantry::gateway::rfc3339_now(),
        kind: kind.to_string(),
        actor: json!({"type": "system", "id": actor_id, "identity_source": "local", "rung": null}),
        authority,
        subject,
        redacted: vec![],
        attestation: None,
    })?;
    Ok(())
}

fn graph_build(graph_path: &str, files: &[&str]) -> Result<i32, Fault> {
    let paths: Vec<std::path::PathBuf> = files.iter().map(std::path::PathBuf::from).collect();
    let graph = Graph::build(&paths)?;
    graph.save(Path::new(graph_path))?;
    println!(
        "graph built: {} nodes, index {} bytes, saved to {graph_path}",
        graph.nodes.len(),
        graph.index_bytes()
    );
    Ok(0)
}

/// A ledgered retrieval: query the graph with staleness verification on and
/// record what it cost as a graph.query event, so context management is
/// telemetry, not prose. This is the production path; compare below is the
/// offline benchmark.
fn graph_query(ledger_dir: &str, graph_path: &str, symbol: &str) -> Result<i32, Fault> {
    let graph = Graph::load(Path::new(graph_path))?;
    let retrieval = graph.query(symbol, true)?;
    let dir = Path::new(ledger_dir);
    let mut ledger = if dir.join("events.jsonl").exists() {
        Ledger::open(dir)?
    } else {
        Ledger::init(dir)?
    };
    append_system_event(
        &mut ledger,
        "system:graph",
        "graph.query",
        json!({
            "graph": graph_path,
            "symbol": symbol,
            "hits": retrieval.hits,
            "bytes_read": retrieval.bytes_read,
            "index_bytes": graph.index_bytes(),
            "stale_reread": retrieval.stale_reread,
        }),
    )?;
    println!(
        "graph query {symbol}: {} hit(s), {} bytes read, {} stale re-read; ledgered as graph.query",
        retrieval.hits.len(),
        retrieval.bytes_read,
        retrieval.stale_reread.len()
    );
    Ok(0)
}

/// Answer the same symbol query two ways and print the token (byte) and
/// accuracy delta, including whether the graph lost to the flat scan.
fn graph_compare(graph_path: &str, symbol: &str, files: &[&str]) -> Result<i32, Fault> {
    let paths: Vec<std::path::PathBuf> = files.iter().map(std::path::PathBuf::from).collect();
    let graph = Graph::load(Path::new(graph_path))?;
    let flat = gantry::graph::flat_query(&paths, symbol)?;
    let graph_fast = graph.query(symbol, false)?;
    let graph_expired = graph.query(symbol, true)?;

    println!("query: {symbol}");
    println!(
        "  flat:          {} hit(s), {} bytes read",
        flat.hits.len(),
        flat.bytes_read
    );
    println!(
        "  graph (fast):  {} hit(s), {} bytes read",
        graph_fast.hits.len(),
        graph_fast.bytes_read
    );
    println!(
        "  graph (expiry):{} hit(s), {} bytes read, {} stale re-read",
        graph_expired.hits.len(),
        graph_expired.bytes_read,
        graph_expired.stale_reread.len()
    );
    let saved = flat.bytes_read as i64 - graph_fast.bytes_read as i64;
    println!("  byte delta (flat - graph fast): {saved}");
    if graph_fast.hits != flat.hits {
        println!(
            "  ACCURACY: the fast graph disagreed with flat (stale index). Correct answer is flat: {:?}",
            flat.hits
        );
        if graph_expired.hits == flat.hits {
            println!(
                "  expiry re-read recovered the correct answer at the cost of the stale files"
            );
        }
    } else {
        println!("  ACCURACY: fast graph agreed with flat");
    }
    Ok(0)
}

/// One orchestrated step against the tracked policy: run the capability's
/// sensor, record the outcome, and let the trust budget promote or demote.
/// The rung is recomputed from the ledger every step, so a reader can derive
/// it themselves.
fn orchestrate_step(
    ledger_dir: &str,
    capability: &str,
    sensor_path: &str,
    artifact: &str,
    approver: Option<&str>,
) -> Result<i32, Fault> {
    let sensor = Sensor::load(Path::new(sensor_path))?;
    let policy = Policy::load(Path::new("config/policy.json"))?;
    let dir = Path::new(ledger_dir);
    let ledger = if dir.join("events.jsonl").exists() {
        Ledger::open(dir)?
    } else {
        Ledger::init(dir)?
    };
    let settings_path = Path::new(".claude/settings.json");
    let pin = Pinning {
        policy: "config/policy.json".into(),
        instructions: Path::new("instructions/pack.md").into(),
        settings: Some(settings_path).filter(|p| p.exists()).map(Into::into),
        diverged: settings_divergence(settings_path),
    };
    let mut orch = Orchestrator::open(ledger, policy, &format!("orchestrate:{capability}"), &pin)?;
    let outcome = orch.step(capability, &sensor, Path::new(artifact), approver)?;
    orch.seal("complete")?;
    let change = outcome.change.map(|c| format!(", {c}")).unwrap_or_default();
    println!(
        "[orchestrate] {capability}: {} -> {} (sensor {:?}{change})",
        outcome.rung_before.schema_name(),
        outcome.rung_after.schema_name(),
        outcome.verdict
    );
    Ok(0)
}

/// Reads a sealed ledger and narrates one capability's rung arc as a story.
fn trust_history(ledger_dir: &str, capability: &str) -> Result<i32, Fault> {
    let ledger = Ledger::open(Path::new(ledger_dir))?;
    let events = ledger.events_with_subjects()?;
    let policy = Policy::load(Path::new("config/policy.json"))?;
    let start = policy
        .capabilities
        .iter()
        .find(|c| c.id == capability)
        .map(|c| c.rung)
        .ok_or_else(|| {
            Fault::new(
                format!("capability {capability} is not in config/policy.json"),
                "name a declared capability",
            )
        })?;
    let lines = gantry::trust::narrate(&events, capability);
    let state = gantry::trust::TrustState::replay(&events, capability, start);
    println!(
        "rung history for {capability} (started at {}):",
        start.schema_name()
    );
    if lines.is_empty() {
        println!("  (no rung changes recorded)");
    }
    for l in &lines {
        println!("  {l}");
    }
    println!(
        "now at {} with {} clean run(s) since entering it",
        state.rung.schema_name(),
        state.clean_since_rung
    );
    Ok(0)
}

/// Runs one sensor against an artifact and records the verdict. With a
/// provider, a blocking failure triggers one autonomous repair turn: the
/// model is given the artifact and the sensor's fix message, its output
/// replaces the artifact, and the sensor reruns. Both verdicts land on the
/// ledger, which is the "agent corrects on rerun, no human in the loop"
/// arc the proof needs.
fn sensor_gate(
    ledger_dir: &str,
    sensor_path: &str,
    artifact: &str,
    repair: Option<(&str, &str)>,
) -> Result<i32, Fault> {
    let sensor = Sensor::load(Path::new(sensor_path))?;
    let policy = Policy::load(Path::new("config/policy.json"))?;
    let policy_version = policy.policy_version.clone().unwrap_or_default();
    let dir = Path::new(ledger_dir);
    let ledger = if dir.join("events.jsonl").exists() {
        Ledger::open(dir)?
    } else {
        Ledger::init(dir)?
    };
    let settings_path = Path::new(".claude/settings.json");
    let pin = Pinning {
        policy: "config/policy.json".into(),
        instructions: Path::new("instructions/pack.md").into(),
        settings: Some(settings_path).filter(|p| p.exists()).map(Into::into),
        diverged: settings_divergence(settings_path),
    };
    let mut run = SensorRun::open(
        ledger,
        &policy.profile,
        &policy_version,
        &format!("sensor:{}", sensor.id),
        &pin,
    )?;

    let artifact_path = Path::new(artifact);
    let first = run.gate(&sensor, artifact_path)?;
    report_verdict("attempt 1", &first);

    let mut exit = verdict_exit(&first);
    if first.verdict == Verdict::Fail && first.blocked {
        if let Some((providers_path, provider_name)) = repair {
            println!("[bus] blocking failure; asking the model to repair the artifact");
            repair_artifact(&sensor, artifact_path, providers_path, provider_name)?;
            let second = run.gate(&sensor, artifact_path)?;
            report_verdict("attempt 2, after repair", &second);
            exit = verdict_exit(&second);
        }
    }
    let head = run.seal()?;
    println!("sealed at ledger size {}", head.size);
    Ok(exit)
}

fn verdict_exit(v: &gantry::sensor::SensorVerdict) -> i32 {
    match v.verdict {
        Verdict::Pass => 0,
        _ => 1,
    }
}

fn report_verdict(label: &str, v: &gantry::sensor::SensorVerdict) {
    let verdict = serde_json::to_value(v)
        .ok()
        .and_then(|j| j["verdict"].as_str().map(String::from))
        .unwrap_or_default();
    println!(
        "[{label}] sensor {} -> {verdict} (blocked: {})",
        v.sensor, v.blocked
    );
    if let Some(m) = &v.message {
        println!("    {m}");
    }
}

/// One repair turn through the gateway. The model never sees a tool; it is
/// asked to return the corrected artifact text, and its reply becomes the
/// new artifact. The sensor, not the model, decides whether the repair took.
fn repair_artifact(
    sensor: &Sensor,
    artifact: &Path,
    providers_path: &str,
    provider_name: &str,
) -> Result<(), Fault> {
    let providers = gateway::load_providers(Path::new(providers_path))?;
    let provider = providers
        .iter()
        .find(|p| p.name == *provider_name)
        .ok_or_else(|| {
            Fault::new(
                format!("no provider named {provider_name} in {providers_path}"),
                "name a provider present in the providers file",
            )
        })?;
    let broken = read_file(&artifact.display().to_string())?;
    let system = "You repair documents to satisfy an automated check. Return only the corrected document, no preamble, no code fences.";
    let user = format!(
        "A sensor rejected this document with the instruction: {}\n\nReturn the corrected document in full.\n\n--- document ---\n{}\n--- end ---",
        sensor.fix, broken
    );
    // A throwaway gateway run so the repair call is itself on a ledger; the
    // repair's evidence lives beside the sensor run rather than inside it.
    let dir = std::env::temp_dir().join(format!("gantry-repair-{}", std::process::id()));
    let ledger = Ledger::init(&dir)?;
    let mut grun = GatewayRun::open(
        ledger,
        "sensor-repair",
        &Pinning {
            policy: "config/policy.json".into(),
            instructions: Path::new("instructions/pack.md").into(),
            settings: None,
            diverged: vec![],
        },
    )?;
    let answer = grun.call(provider, &[msg("system", system), msg("user", &user)])?;
    grun.seal("complete")?;
    fs::write(artifact, answer.content.trim()).map_err(|e| {
        Fault::new(
            format!(
                "cannot write the repaired artifact {}: {e}",
                artifact.display()
            ),
            "check the artifact path is writable",
        )
    })?;
    Ok(())
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
