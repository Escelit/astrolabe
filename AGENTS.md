# AGENTS.md

Instructions for AI coding agents working in the **Astrolabe** repository.
Humans: this file is also a good summary of how we work.

## 1. Project Summary

Astrolabe is an open-source toolkit for moving zero-knowledge proofs from
proof-generation toolchains (Circom/snarkjs first, then Noir and RISC Zero)
into Soroban smart contracts on Stellar, using the Protocol 25 BN254 host
functions.

The **source of truth** is `spec/spec.md` (the Astrolabe Canonical Format, ACF).
Code implements the spec. The spec does not follow the code.

## 2. Read This First

Before changing anything:

1. Read `spec/spec.md` fully.
2. Read this file fully.
3. Check `spec/spec.md` Section 15 (Open Questions) and every **[VERIFY]** tag.
4. Run the build and test commands in Section 5 to learn the current state.

## 3. Non-Negotiable Rules

1. **Never edit `spec/spec.md`** unless the user explicitly asks. If the spec
   is ambiguous, wrong, or marked **[VERIFY]**, **stop and ask**. Do not guess.
2. **Never invent cryptographic constants, test vectors, or byte orderings.**
   Constants come from the spec, a cited library, or a recorded on-chain
   transaction. If you cannot source a value, say so and stop.
3. **No silent fixes.** If a test fails, do not change the expected value to
   make it pass without explaining why the expected value was wrong.
4. **Do not weaken validation.** Never remove or loosen range checks,
   on-curve checks, subgroup checks, or length checks to make something work.
5. **Do not reduce values silently.** Scalars `>= r` and field elements `>= p`
   are rejected, never reduced modulo.
6. **No secrets or witness handling.** These libraries only process public
   data. Do not add code that handles private keys, witnesses, or toxic waste.
7. **Keep changes small and reviewable.** One phase or task at a time. Do not
   refactor unrelated code.
8. **Do not add dependencies** without stating why, what it costs in WASM size,
   and whether it is `no_std` compatible. Prefer none.

## 4. Repository Layout

```
.
├── AGENTS.md
├── spec/
│   ├── spec.md              # Source of truth. Read-only for agents.
│   └── vectors/             # Conformance test vectors (JSON)
│       ├── valid/
│       ├── invalid-length/
│       ├── invalid-field/
│       ├── invalid-curve/
│       ├── invalid-subgroup/
│       ├── infinity/
│       ├── public-input-count/
│       └── onchain/
├── crates/
│   ├── astrolabe-core/      # Rust, no_std. Encoding, validation, errors.
│   ├── astrolabe-verifier/  # Soroban contract helpers and verifier template
│   └── astrolabe-cli/       # CLI (export, gen-verifier, verify, doctor)
├── packages/
│   └── astrolabe-ts/        # TypeScript SDK (browser + Node)
├── examples/
│   └── circom-multiplier/   # End-to-end Circom -> testnet example
├── scripts/                 # Dev scripts (vector generation, cross-checks)
└── .github/workflows/       # CI
```

If a directory above does not exist yet, create it only when your current task
needs it.

## 5. Commands

> These are the intended commands. If one does not exist yet, tell the user
> rather than inventing a replacement.

**Rust**

```
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build -p astrolabe-core --target wasm32v1-none --release   # no_std check
```

**TypeScript**

```
pnpm install
pnpm -r lint
pnpm -r test
pnpm -r build
```

**Cross-implementation conformance**

```
make vectors-check     # Rust and TS must both pass every vector
make differential      # Rust vs TS vs snarkjs byte-for-byte comparison
```

**Rule:** run the relevant commands and confirm they pass before saying a task
is done. Report the actual output, not an assumption.

## 6. Coding Standards

### Rust

- `astrolabe-core` is `#![no_std]`. Use `core::` and, only if unavoidable,
  `alloc::`. No `std::`.
- No `unwrap()`, `expect()`, `panic!`, or unchecked indexing in library code.
  Return `Result<T, AcfError>`.
- Error variants map one-to-one to the error codes in spec Section 11, with
  stable string representations.
- The `Fp2` component order lives in **one named constant**. Do not hardcode
  the order in multiple places.
- Public APIs get doc comments that cite the spec section they implement.

### TypeScript

- Strict mode on. No `any`. No implicit `any`.
- Use `bigint` for field elements. Never use `number` for field values.
- Pure functions for encode/decode. No global state.
- Same error codes and messages as the Rust implementation.
- Browser-safe: no Node-only APIs in `src/` except behind clearly separated
  entry points.

### General

- Prefer clarity over cleverness. This is security-sensitive code.
- Comment **why**, not what, especially around ordering, negation, and checks.
- Deterministic output: same input produces the same bytes on every run.

## 7. Testing Rules

- **Vector-first.** Write or update test vectors before the implementation
  they cover.
- Every implementation must pass **every** applicable vector.
- Every spec validation rule (Section 9) needs at least one failing-input
  vector proving it is enforced.
- **Independent sources.** Do not generate both the vector and the code from
  your own assumptions. At least one vector set must come from an independent
  source, such as real snarkjs output, a reference library, or a recorded
  on-chain transaction. Record the source in the vector's `description`.
- Property tests are welcome for round trips (`decode(encode(x)) == x`) but do
  not replace known-answer vectors.
- Never delete a failing test. If a test is wrong, explain why and get
  confirmation.

## 8. Known Unknowns (Do Not Guess)

The following are unresolved and must be confirmed by a human against CAP-0074,
the `soroban-sdk`, and a real testnet transaction before implementation relies
on them:

1. Fp2 component order for G2 encoding (`c1 || c0` assumed).
2. Whether host functions validate on-curve and subgroup membership.
3. Infinity point encoding accepted by host functions.
4. Scalar input type and reduction behavior for `bn254_g1_mul`.
5. Exact `soroban-sdk` BN254 type names and conversions.

If your task depends on any of these and the spec still shows **[VERIFY]**:
**stop and ask the user.** Offer to build a small testnet experiment to
determine the answer instead of assuming.

## 9. Workflow

Work in phases. Finish and verify each before starting the next.

| Phase | Deliverable |
| ----- | ----------- |
| 0 | Scaffold: workspace, CI, lint, empty crates and packages |
| 1 | Resolve [VERIFY] items via a manual Circom-to-testnet run (human-led) |
| 2 | Primitives: Fp/Fr/G1/G2 encode, decode, validate (Rust + TS) with vectors |
| 3 | Groth16 objects and envelope (proof, VK, public inputs) |
| 4 | snarkjs adapter, plus the differential test against snarkjs |
| 5 | Verifier contract template and CLI (`export`, `gen-verifier`, `verify`, `doctor`) |
| 6 | Testnet example and docs |
| 7+ | Noir adapter, RISC Zero adapter, `profile`, templates, CI action |

For each task:

1. Restate the task and which spec sections it covers.
2. List assumptions and anything marked **[VERIFY]** that touches it.
3. Write or update vectors.
4. Implement.
5. Run the commands in Section 5.
6. Summarize: files changed, tests run with results, open questions.

## 10. Definition of Done

A task is done only when all of these hold:

- [ ] Code implements the cited spec sections and nothing speculative.
- [ ] Relevant vectors added or updated, with sources recorded.
- [ ] `fmt`, `clippy` (zero warnings), and tests pass, with output shown.
- [ ] `no_std` build passes for `astrolabe-core`.
- [ ] No new dependencies, or each one justified.
- [ ] Public APIs documented with spec references.
- [ ] No changes to `spec/spec.md`.
- [ ] Remaining uncertainties listed explicitly for the human reviewer.

## 11. Security Review Hotspots

Flag these for line-by-line human review in your summary whenever you touch
them:

- Point negation of `A` (`y -> p - y`) and the infinity edge cases
- G2 subgroup membership check
- Canonical-range checks for `Fp` and `Fr`
- Public-input count validation
- Fp2 ordering and snarkjs-to-ACF conversion
- Any code that builds or consumes the multi-pairing input

## 12. Communication Style

- Be direct about uncertainty. "I could not verify X" is a good answer.
- Do not claim something works unless you ran it.
- Ask one focused question at a time when blocked.
- When you make a judgment call, say so and say why.

## 13. Out of Scope for Agents (Ask First)

- Changing the spec, envelope layout, or error codes
- Publishing packages or crates
- Deploying to mainnet, or handling real funds or keys
- Adding new proof systems or curves
- Changing the license