//! Execute-only host for the agb-rep program (no proving, no network, no PROVE spent).
//!
//!   cargo run --release -- --vectors ../../agentwork/vectors/supersede-v1.json
//!
//! For every scenario it runs the program in the SP1 executor and checks the public values
//! equal a native run of the same library, and that tips / counted workers match the
//! expectations agentwork's Python wrote into the vectors.
use alloy_sol_types::SolType;
use clap::Parser;
use agb_rep::{commit, scenario_view, RepCommitment};
use sp1_sdk::{blocking::{Prover, ProverClient}, include_elf, Elf, SP1Stdin};

const ELF: Elf = include_elf!("agb-rep-program");

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    vectors: String,
}

fn main() {
    let args = Args::parse();
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&args.vectors).unwrap()).unwrap();
    // CPU executor only; never the network prover.
    let client = ProverClient::builder().cpu().build();
    let mut failures = 0;
    for s in v["scenarios"].as_array().unwrap() {
        let name = s["name"].as_str().unwrap();
        let now = s["eval_ts"].as_u64().unwrap();
        let lines: Vec<String> = s["lines"].as_array().unwrap().iter().map(|l| l.as_str().unwrap().to_string()).collect();
        // the worker = payee of the first receipt in the scenario
        let worker = lines.iter().filter_map(|l| agb_rep::decode(l)).find(|m| m.t == "receipt")
            .and_then(|m| m.b["payee"].as_str().map(String::from)).unwrap();
        let (tips, counted) = scenario_view(&lines, now);
        let want_tip = s["expect"]["tip"].as_str().unwrap();
        let want_counted = s["expect"]["worker_counted"].as_bool().unwrap();
        let native = commit(&lines, now, &worker);
        let mut stdin = SP1Stdin::new();
        stdin.write(&lines);
        stdin.write(&now);
        stdin.write(&worker);
        let (out, report) = client.execute(ELF, stdin).run().expect("execute");
        let zk = RepCommitment::abi_decode(out.as_slice()).expect("decode public values");
        let same = RepCommitment::abi_encode(&zk) == RepCommitment::abi_encode(&native);
        let ok = same && tips == vec![want_tip.to_string()] && counted.contains(&worker) == want_counted
            && (zk.subjectScore > 0) == want_counted && zk.droppedMessages == 0;
        if !ok { failures += 1; }
        println!("{:<28} {} tip_ok={} counted={} (want {}) score_micro={} receipts={} cycles={} zk==native={}",
            name, if ok { "PASS" } else { "FAIL" }, tips == vec![want_tip.to_string()], counted.contains(&worker),
            want_counted, zk.subjectScore, zk.subjectReceipts, report.total_instruction_count(), same);
    }
    // tamper check: flip one byte of a signature -> message dropped, logRoot changes
    let s = &v["scenarios"][0];
    let now = s["eval_ts"].as_u64().unwrap();
    let mut lines: Vec<String> = s["lines"].as_array().unwrap().iter().map(|l| l.as_str().unwrap().to_string()).collect();
    let i = lines[4].find("\"sig\":\"").unwrap() + 8;
    let mut b = lines[4].clone().into_bytes();
    b[i] = if b[i] == b'A' { b'B' } else { b'A' };
    lines[4] = String::from_utf8(b).unwrap();
    let mut stdin = SP1Stdin::new();
    stdin.write(&lines);
    stdin.write(&now);
    stdin.write(&String::new());
    let (out, _) = client.execute(ELF, stdin).run().expect("execute");
    let zk = RepCommitment::abi_decode(out.as_slice()).unwrap();
    let tamper_ok = zk.droppedMessages == 1;
    if !tamper_ok { failures += 1; }
    println!("{:<28} {} dropped={}", "tampered-receipt-sig", if tamper_ok { "PASS" } else { "FAIL" }, zk.droppedMessages);
    if failures > 0 {
        eprintln!("{failures} failure(s)");
        std::process::exit(1);
    }
    println!("all scenarios pass in the SP1 executor (execute mode; no proof generated)");
}
