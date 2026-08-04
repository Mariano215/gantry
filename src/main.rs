//! Thin CLI over the ledger library. Every subcommand is one library call
//! plus printing; the verification logic lives in gantry::ledger so the
//! offline verifier is the library, not this file.

use gantry::event::NewEvent;
use gantry::ledger::{self, InclusionBundle, Ledger};
use gantry::Fault;
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
  gantry ledger expire <dir> <subject_hash>         (NewEvent JSON on stdin)";

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
        [] => Err(usage_fault("no subcommand given")),
        _ => Err(usage_fault(format!("unknown command: {}", args.join(" ")))),
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
