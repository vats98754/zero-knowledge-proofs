# zero-knowledge-proofs
I wanted to understand the important zero-knowledge commitment schemes (for my learning) that have provided prover and verifier optimizations in the field of zk.

Each feature branch implements one complete, tested, and benchmarked proof system. The main branch is the integration branch that merges every feature branch together and provides unified cross-backend tests, integration examples, and combined benchmarks.

Branch convention (one branch per architecture):
1. main — merged integration of everything (golden CI + nightly benchmark runs)
2. groth16 — pairing-based Groth16 (trusted setup)
3. plonk — universal PLONK implementation (KZG default)
4. marlin — Marlin / Sonic (universal IOP variants)
5. stark — STARK (FRI-based transparent proofs)
6. halo / halo2 — recursion-friendly Halo family
7. bulletproofs — inner-product / Bulletproofs
8. nova — Nova incremental/recursive folding
9. spartan — AlgebraicIOP / Spartan

## Repo Layout
```bash
/crates/             # each branch will own its set of crates; main integrates them
  groth16/
  plonk/
  marlin/
  stark/
  halo/
  bulletproofs/
  nova/
  spartan/
  zkvm/
  twist-and-shout/
/benches/            # integration & end-to-end benchmark harnesses
/.github/workflows/  # CI and bench workflows (below)
README.md
```

## Run this locally
```git
git clone git@github.com:yourorg/zero-knowledge-proofs.git
cd zero-knowledge-proofs

# Build all crates
cargo build --workspace --release

# Run unit & property tests (fast)
cargo test --workspace

# Run a subset of benchmarks (locally; heavy)
cargo bench --manifest-path crates/<crate>/Cargo.toml
# or run a single bench:
cargo bench --bench end_to_end --manifest-path crates/integration/Cargo.toml
```
