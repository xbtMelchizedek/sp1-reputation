//! zkVM program: verify agb1 messages (sha256 cids + Ed25519 sigs), apply the receipt
//! supersede-chain rule, compute rep-v0-int, and commit roots + one subject's score.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use agb_rep::{commit, RepCommitment};

pub fn main() {
    let lines = sp1_zkvm::io::read::<Vec<String>>();
    let now = sp1_zkvm::io::read::<u64>();
    let subject = sp1_zkvm::io::read::<String>();
    let c = commit(&lines, now, &subject);
    sp1_zkvm::io::commit_slice(&RepCommitment::abi_encode(&c));
}
