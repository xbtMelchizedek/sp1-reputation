//! agb-rep: verify agentwork (agb1) messages and compute an integer reputation score,
//! identically on a normal machine and inside the SP1 zkVM.
//!
//! What it checks for every input line (same rules as agentwork/codec.py, subset):
//!   * the line re-encodes byte-for-byte to its canonical form (sorted keys, ASCII-only)
//!   * cid = 0x + sha256("FLOP::agb::v1|" + canonical(envelope minus cid, sig))
//!   * sig = Ed25519(did:key in `from`, "agb1-sig|" + cid)
//! Lines that fail are dropped (and counted), like agentwork's `_valid`.
//!
//! Score: "rep-v0-int", an INTEGER approximation of agentwork reputation v0 so it is
//! deterministic in a zkVM. Same receipt eligibility and supersede-chain rule as
//! agentwork/reputation.py (main @ 307e52a); different arithmetic:
//!   base   = isqrt(amount_units * 1e12) / k            (k-th receipt for the same pair)
//!   base >>= floor(age / half_life)                      (step decay, not continuous)
//!   capped = sum_j min(c_j, total * cap_bps / 10000)
//!   score  = capped * counterparties / receipts          (micro-units, u128)
//! Flags and min_attester_score are NOT implemented. It is a prototype, not a replacement.

use alloy_sol_types::sol;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

sol! {
    /// Public values committed by the zkVM program (ABI-encoded for an EVM verifier).
    struct RepCommitment {
        bytes32 logRoot;        // sha256 over the sorted cids of all VALID input messages
        bytes32 paramsHash;     // sha256 of the scoring parameters string
        uint64  nowMs;          // scoring time
        bytes32 subject;        // sha256(subject DID)
        uint128 subjectScore;   // micro-units
        uint32  subjectReceipts;
        bytes32 scoresRoot;     // sha256 over (sha256(did) || score_be16) for every scored DID, sorted
        uint32  validMessages;
        uint32  droppedMessages;
    }
}

pub const PARAMS: &str = "rep-v0-int/1;FLOP=18;window=180d;half_life=90d;pair_window=90d;cap_bps=1000;claim_link=1";
const DAY: u64 = 86_400_000;
const WINDOW: u64 = 180 * DAY;
const HALF_LIFE: u64 = 90 * DAY;
const PAIR_WINDOW: u64 = 90 * DAY;
const CAP_BPS: u128 = 1000;

#[derive(Clone, Debug)]
pub struct Msg {
    pub cid: String,
    pub from: String,
    pub t: String,
    pub ts: u64,
    pub r#ref: Option<String>,
    pub b: Value,
}

fn esc(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04x}", u));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Canonical JSON (Python json.dumps(sort_keys, separators=(",",":"), ensure_ascii=True)).
pub fn canonical(v: &Value) -> Result<String, &'static str> {
    let mut s = String::new();
    enc(v, &mut s)?;
    Ok(s)
}

fn enc(v: &Value, out: &mut String) -> Result<(), &'static str> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            let i = n.as_i64().ok_or("float or out-of-range number")?;
            if i.unsigned_abs() > (1u64 << 53) - 1 {
                return Err("unsafe integer");
            }
            out.push_str(&i.to_string());
        }
        Value::String(s) => esc(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                enc(x, out)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            // serde_json's default Map is a BTreeMap: keys already sorted by bytes (keys are ASCII)
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                esc(out, k);
                out.push(':');
                enc(x, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn did_pubkey(did: &str) -> Option<[u8; 32]> {
    let z = did.strip_prefix("did:key:z")?;
    let raw = bs58::decode(z).into_vec().ok()?;
    if raw.len() != 34 || raw[0] != 0xed || raw[1] != 0x01 {
        return None;
    }
    raw[2..].try_into().ok()
}

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// Decode and fully verify one agb1 line. None = rejected.
pub fn decode(line: &str) -> Option<Msg> {
    let body = line.strip_prefix("agb1 ")?;
    if body.len() + 5 > 4096 {
        return None;
    }
    let v: Value = serde_json::from_str(body).ok()?;
    if canonical(&v).ok()? != body {
        return None; // one message, one spelling
    }
    let obj = v.as_object()?;
    let cid = obj.get("cid")?.as_str()?.to_string();
    let sig = obj.get("sig")?.as_str()?;
    let from = obj.get("from")?.as_str()?.to_string();
    let t = obj.get("t")?.as_str()?.to_string();
    if obj.get("s")?.as_str()? != format!("agb.{t}/1") {
        return None;
    }
    let mut core: Map<String, Value> = obj.clone();
    core.remove("cid");
    core.remove("sig");
    let mut pre = b"FLOP::agb::v1|".to_vec();
    pre.extend_from_slice(canonical(&Value::Object(core)).ok()?.as_bytes());
    if format!("0x{}", hex::encode(sha(&pre))) != cid {
        return None;
    }
    use base64::Engine;
    let sigb = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig).ok()?;
    let vk = VerifyingKey::from_bytes(&did_pubkey(&from)?).ok()?;
    let mut m = b"agb1-sig|".to_vec();
    m.extend_from_slice(cid.as_bytes());
    vk.verify(&m, &Signature::from_slice(&sigb).ok()?).ok()?;
    Some(Msg {
        cid,
        from,
        t,
        ts: obj.get("ts")?.as_u64()?,
        r#ref: obj.get("ref").and_then(|r| r.as_str()).map(String::from),
        b: obj.get("b")?.clone(),
    })
}

fn bstr<'a>(m: &'a Msg, k: &str) -> Option<&'a str> {
    m.b.get(k).and_then(|v| v.as_str())
}

/// Current receipt per (payer, ref, payee): the explicit `supersedes` chain rule.
pub fn receipt_tips(idx: &BTreeMap<String, Msg>, now: u64) -> BTreeMap<(String, String, String), Msg> {
    let mut groups: BTreeMap<(String, String, String), Vec<Msg>> = BTreeMap::new();
    for m in idx.values() {
        if m.t == "receipt" && m.ts <= now {
            let key = (m.from.clone(), m.r#ref.clone().unwrap_or_default(), bstr(m, "payee").unwrap_or("").to_string());
            groups.entry(key).or_default().push(m.clone());
        }
    }
    let mut tips = BTreeMap::new();
    for (key, mut rs) in groups {
        rs.sort_by(|a, b| (a.ts, &a.cid).cmp(&(b.ts, &b.cid)));
        let Some(mut tip) = rs.iter().find(|r| r.b.get("supersedes").is_none()).cloned() else { continue };
        while let Some(n) = rs.iter().find(|r| bstr(r, "supersedes") == Some(tip.cid.as_str()) && (r.ts, &r.cid) > (tip.ts, &tip.cid)) {
            tip = n.clone();
        }
        tips.insert(key, tip);
    }
    tips
}

/// Receipts that carry weight at `now` (agentwork reputation v0 eligibility, no params).
pub fn qualifying(idx: &BTreeMap<String, Msg>, now: u64) -> Vec<Msg> {
    let tips = receipt_tips(idx, now);
    let mut att: BTreeMap<String, Vec<&Msg>> = BTreeMap::new();
    for m in idx.values() {
        if m.t == "attest" {
            if let Some(r) = &m.r#ref {
                att.entry(r.clone()).or_default().push(m);
            }
        }
    }
    let mut out = vec![];
    for tip in tips.values() {
        let payee = bstr(tip, "payee").unwrap_or("");
        let amount = tip.b.get("amount");
        let asset = amount.and_then(|a| a.get("asset")).and_then(|v| v.as_str()).unwrap_or("");
        let amt: u128 = amount.and_then(|a| a.get("amt")).and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
        if bstr(tip, "outcome") != Some("settled") || tip.from == payee || bstr(tip, "railRef").unwrap_or("").trim().is_empty() {
            continue;
        }
        if asset != "FLOP" || amt == 0 || tip.ts + WINDOW < now {
            continue;
        }
        match tip.r#ref.as_ref().and_then(|r| idx.get(r)) {
            Some(c) if c.t == "claim" && c.from == payee => {}
            _ => continue,
        }
        let (mut good, mut bad) = (BTreeSet::new(), BTreeSet::new());
        for a in att.get(&tip.cid).into_iter().flatten() {
            if a.from == tip.from || a.from == payee {
                continue;
            }
            if bstr(a, "verdict") == Some("valid") { good.insert(&a.from); } else { bad.insert(&a.from); }
        }
        if good.is_empty() || bad.len() >= good.len() {
            continue;
        }
        out.push(tip.clone());
    }
    out.sort_by(|a, b| (a.ts, &a.cid).cmp(&(b.ts, &b.cid)));
    out
}

fn isqrt(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// rep-v0-int scores in micro-units, plus counted receipts per payee.
pub fn scores(receipts: &[Msg], now: u64) -> BTreeMap<String, (u128, u32)> {
    let mut contrib: BTreeMap<String, BTreeMap<String, u128>> = BTreeMap::new();
    let mut count: BTreeMap<String, u32> = BTreeMap::new();
    let mut pair: BTreeMap<(String, String), Vec<u64>> = BTreeMap::new();
    for r in receipts {
        let payee = bstr(r, "payee").unwrap().to_string();
        let amt: u128 = r.b["amount"]["amt"].as_str().unwrap().parse().unwrap();
        let hist = pair.entry((r.from.clone(), payee.clone())).or_default();
        hist.retain(|t| r.ts - t <= PAIR_WINDOW);
        let k = hist.len() as u128 + 1;
        hist.push(r.ts);
        // sqrt(units) * 1e6 = isqrt(amt * 1e12 / 1e18) = isqrt(amt / 1e6)
        let mut base = isqrt(amt / 1_000_000) / k;
        let halvings = (now.saturating_sub(r.ts)) / HALF_LIFE;
        base >>= halvings.min(127);
        *contrib.entry(payee.clone()).or_default().entry(r.from.clone()).or_default() += base;
        *count.entry(payee).or_default() += 1;
    }
    let mut out = BTreeMap::new();
    for (did, by) in contrib {
        let total: u128 = by.values().sum();
        let capped: u128 = by.values().map(|c| (*c).min(total * CAP_BPS / 10_000)).sum();
        let n = count[&did];
        out.insert(did, (capped * by.len() as u128 / n as u128, n));
    }
    out
}

/// Full pipeline: verify lines, score, commit.
pub fn commit(lines: &[String], now: u64, subject: &str) -> RepCommitment {
    let mut idx = BTreeMap::new();
    let mut dropped = 0u32;
    for l in lines {
        match decode(l) {
            Some(m) => {
                idx.entry(m.cid.clone()).or_insert(m);
            }
            None => dropped += 1,
        }
    }
    let mut lr = Sha256::new();
    lr.update(b"agb-rep/log|");
    for cid in idx.keys() {
        lr.update(cid.as_bytes());
    }
    let sc = scores(&qualifying(&idx, now), now);
    let mut sr = Sha256::new();
    sr.update(b"agb-rep/scores|");
    let mut leaves: Vec<([u8; 32], u128)> = sc.iter().map(|(d, (s, _))| (sha(d.as_bytes()), *s)).collect();
    leaves.sort();
    for (h, s) in &leaves {
        sr.update(h);
        sr.update(s.to_be_bytes());
    }
    let (subj_score, subj_n) = sc.get(subject).copied().unwrap_or((0, 0));
    RepCommitment {
        logRoot: <[u8; 32]>::from(lr.finalize()).into(),
        paramsHash: sha(PARAMS.as_bytes()).into(),
        nowMs: now,
        subject: sha(subject.as_bytes()).into(),
        subjectScore: subj_score,
        subjectReceipts: subj_n,
        scoresRoot: <[u8; 32]>::from(sr.finalize()).into(),
        validMessages: idx.len() as u32,
        droppedMessages: dropped,
    }
}

/// Helper for tests: the tip cid of the receipt chain(s) and whether the worker counts.
pub fn scenario_view(lines: &[String], now: u64) -> (Vec<String>, BTreeSet<String>) {
    let idx: BTreeMap<String, Msg> = lines.iter().filter_map(|l| decode(l)).map(|m| (m.cid.clone(), m)).collect();
    let tips = receipt_tips(&idx, now).values().map(|m| m.cid.clone()).collect();
    let counted = qualifying(&idx, now).iter().filter_map(|m| bstr(m, "payee").map(String::from)).collect();
    (tips, counted)
}
