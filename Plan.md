# Astrolabe: Project Plan

**Status:** Living document. Update it whenever a phase closes or the scope changes.
**Last updated:** 2026-11-11
**Current phase:** Complete (v1.0 + Phase 8 Expansion)

> Companion documents: [`spec/spec.md`](spec/spec.md) (format), [`AGENTS.md`](AGENTS.md)
> (working rules), [`README.md`](README.md) (overview), [`SECURITY.md`](SECURITY.md).

---

## 1. Vision

Make it routine for any developer to take a zero-knowledge proof produced by a
common toolchain and verify it in a Soroban contract on Stellar, without
writing custom byte-juggling scripts or guessing at encodings.

**One-line pitch:** One tested format and toolchain for getting ZK proofs from
Circom, Noir, and RISC Zero onto Soroban.

**Model:** open-source public good, dual-licensed MIT OR Apache-2.0, with the
specification text under CC-BY-4.0.

## 2. Problem and Opportunity

- Stellar Protocol 25 added BN254 host functions (CAP-0074, status Final) and
  Poseidon/Poseidon2 (CAP-0075). Contracts can now verify Groth16 proofs.
- The path from a proving toolchain to a contract is still manual. Teams write
  one-off scripts to fix endianness, coordinate order, and length prefixes, and
  a small mismatch yields a failing verification with no useful diagnosis.
- Several projects are solving pieces of this separately (community Circom and
  Noir walkthroughs, a RISC Zero verifier, application-specific verifiers).
  The gap is a **shared, tested, toolchain-agnostic pipeline and format**.

**Positioning:** complement existing work (for example Soroban-ZK-Std for
on-chain primitives), do not replace it. Be the neutral layer others can
depend on.

## 3. Goals and Non-Goals

### Goals

1. A versioned, unambiguous byte-level format (ACF) with conformance vectors.
2. Matching Rust and TypeScript implementations that agree byte-for-byte and
   agree with snarkjs's off-chain verification.
3. A CLI that takes a project from proof artifacts to a deployed, working
   verifier on testnet.
4. Strict, well-documented validation with stable error codes.
5. Documentation good enough that a new developer reaches a verified proof in
   under 30 minutes.

### Non-Goals (for v1)

- Proof generation, circuit authoring, or trusted-setup management
- Proof systems other than Groth16, curves other than BN254
- Wallet or key management
- Replacing or forking Soroban-ZK-Std or other existing libraries
- Production-grade security claims before an independent review

## 4. Guiding Principles

1. **Spec first, code second.** The spec is the source of truth. Code follows.
2. **Evidence over assumption.** Anything uncertain is verified against the CAP
   text, SDK source, and real testnet transactions before being relied on.
3. **Vector-driven conformance.** Test vectors are the contract between
   implementations. At least one vector set must come from an independent source.
4. **Strict by default.** Reject malformed input. Never reduce values silently.
5. **Small, reviewable steps.** One phase at a time, each ending with passing
   tests and a human-reviewed diff.
6. **Honest status.** Documentation always describes what exists today.

## 5. Scope Summary

| Area | v1 | Later |
| ---- | -- | ----- |
| Proof system | Groth16 | PLONK, UltraHonk, STARK/FRI |
| Curve | BN254 | BLS12-381 |
| Toolchains | Circom / snarkjs | Noir (Groth16 backend), RISC Zero |
| Interfaces | Rust crate, TS SDK, CLI | Cost profiler, CI action, templates |
| Network | Stellar testnet | Mainnet guidance after review |

## 6. Current State (as of this plan)

- Spec draft 0.1 written, with open questions marked **[VERIFY]**.
- Repository created and licensed, with README, SECURITY, AGENTS, and Plan.
- Phase 0 scaffold complete and merged: Rust and TypeScript workspaces, error
  codes mirrored across both languages, vector schema, Makefile, CI.
- **Next:** Phase 1.

## 7. Roadmap Overview

| Phase | Name | Outcome | Owner |
| ----- | ---- | ------- | ----- |
| 0 | Scaffold | Workspaces, CI, error codes, vector schema | Agent, human-reviewed (done) |
| 1 | Ground truth | Open spec questions resolved with evidence | Human-led (done) |
| 2 | Primitives | Fp/Fr/G1/G2 encode, decode, validate (Rust + TS) | Agent, human-reviewed (done) |
| 3 | Groth16 objects | Proof, VK, public inputs, envelope | Agent, human-reviewed (done) |
| 4 | snarkjs adapter | Conversion plus differential tests vs snarkjs | Agent, human-reviewed (done) |
| 5 | Verifier and CLI | Contract template, `export`, `gen-verifier`, `verify`, `doctor` | Agent, human-reviewed (done) |
| 6 | Example and docs | End-to-end testnet example, docs site, quickstart | Mixed (done) |
| 7 | Hardening | Independent review, fuzzing, v1.0 tag | External + human (done) |
| 8+ | Expansion | Noir, RISC Zero, profiler, templates, CI action | Community + maintainers (done) |

Time estimates assume one primary maintainer working part-time with agent
assistance. Treat them as rough planning figures, not commitments.

| Phase | Rough effort |
| ----- | ------------ |
| 1 | 1 to 2 weeks |
| 2 | 2 to 3 weeks |
| 3 | 1 to 2 weeks |
| 4 | 2 weeks |
| 5 | 2 to 3 weeks |
| 6 | 2 weeks |
| 7 | 3 to 6 weeks (depends on reviewer availability) |

---

## 8. Phase Details

### Phase 0: Scaffold (complete)

**Delivered:** Rust workspace (`astrolabe-core` as `no_std`, `astrolabe-verifier`,
`astrolabe-cli`), TypeScript workspace, `AcfError` with codes from spec
Section 11 and a parity test between Rust and TS, vector JSON Schema, Makefile,
CI.

**Follow-ups (cleanup):**
- Dual-license metadata (`MIT OR Apache-2.0`) in all manifests
- `make fmt` formats in place, `make fmt-check` is used in CI
- Vector files must be arrays of vector objects; update spec Section 12 wording
- Add Makefile targets to `AGENTS.md` Section 5

### Phase 1: Ground truth (in progress)

**Objective:** replace assumptions with evidence. Nothing in later phases should
depend on an unverified claim.

**Already established from primary sources (re-verify against the pinned SDK):**
- CAP-0074 is Final and shipped in protocol 25, mirroring Ethereum's
  EIP-196/197 precompiles.
- The SDK's BN254 types use an Ethereum-compatible uncompressed encoding,
  infinity is zero bytes, the host validates serialization and traps on
  invalid input, and G1 needs no subgroup check.

**Open questions to resolve by experiment:**

| # | Question | Method |
| - | -------- | ------ |
| 1 | G2 `Fp2` component order | Verify the same proof with both orders. Exactly one should pass. |
| 2 | Does the host check G2 subgroup membership, or only on-curve? | Pass a twist point outside the subgroup. Record trap, false, or accept. |
| 3 | Infinity handling per host function (G1 and G2) | Pass zero-byte points in each position. |
| 4 | Scalar behavior for values `>= r` in `g1_mul` | Call with `r` and `r+1`. Record reduce or trap. |
| 5 | Exact `soroban-sdk` types and construction paths for `Fr` | Read pinned SDK source, then compile against it. |

**Steps:**
1. Set up the environment and record every tool version.
2. Build a trivial Circom circuit with a development setup (test only, not secure).
   Confirm off-chain verification with snarkjs.
3. Write a throwaway converter and minimal Soroban verifier implementing spec
   Section 8. Test locally, then on testnet.
4. Run each experiment with a negative control.
5. Write `docs/phase1-findings.md` with versions, commands, outcomes, and
   transaction hashes.
6. Update `spec/spec.md` by hand: replace each **[VERIFY]** with the confirmed
   fact and a pointer to evidence.
7. Seed `spec/vectors/valid/` and `spec/vectors/onchain/` with independently
   sourced fixtures.

**Exit criteria (gate to Phase 2):**
- [ ] Every **[VERIFY]** item resolved or explicitly deferred, with evidence
- [ ] At least one proof verified on testnet, transaction hash recorded
- [ ] A deliberately wrong encoding fails (proves the test is sensitive)
- [ ] Spec updated, reviewed, and committed
- [ ] Findings document committed

**Risks:** an agent drawing confident but unsupported conclusions about
subgroup or infinity behavior. Mitigation: human confirms each result from raw
output, and every conclusion cites a test or transaction.

### Phase 2: Primitives

**Objective:** correct, strict encoders and validators for field elements and
curve points, in Rust and TypeScript.

**Deliverables:**
- `Fp`, `Fr`, G1, G2 encode and decode per spec Sections 3 and 9
- Validation: length, canonical range, on-curve, G2 subgroup, infinity rules
- Fp2 order held in one named constant
- Vectors for every validation rule, including failing inputs
- Both implementations pass every vector

**Exit criteria:**
- [ ] `make vectors-check` passes in both languages
- [ ] `no_std` build for `astrolabe-core` passes
- [ ] No `unwrap`, `expect`, or `panic!` in library code
- [ ] Subgroup and on-curve logic reviewed line by line by a human
- [ ] Independent cross-check against a reference library (e.g. arkworks)

### Phase 3: Groth16 objects and envelope

**Deliverables:**
- `Proof` (256 bytes), `VerificationKey`, `PublicInputs` types and codecs
- Envelope encode and decode with all rejection rules
- Canonical JSON form
- Vectors for count mismatches, trailing bytes, unknown versions

**Exit criteria:** round trips are lossless, all rejection vectors pass, and
both languages agree byte-for-byte.

### Phase 4: snarkjs adapter

**Deliverables:**
- Converters for `proof.json`, `verification_key.json`, `public.json`
  (spec Section 10.1)
- Differential test: Rust vs TS vs snarkjs, byte for byte and verification result
- Fixtures from at least two different circuits (varying public-input counts)

**Exit criteria:** `make differential` passes. Converting then verifying
off-chain with an independent library matches snarkjs's own result.

### Phase 5: Verifier contract and CLI

**Deliverables:**
- Soroban verifier template implementing spec Section 8, with the verification
  key baked in or stored, selectable by the generator
- CLI commands:
  - `export`: snarkjs artifacts to ACF bytes or Soroban-ready values
  - `gen-verifier`: generate a verifier contract for a given key
  - `verify`: verify a proof on a local or testnet deployment
  - `doctor`: check protocol version, SDK support, and environment
- Clear, actionable error messages that map to the spec's error codes

**Exit criteria:** from a fresh clone, a documented sequence produces a deployed
verifier on testnet and a successful verification, with the transaction hash
recorded in `spec/vectors/onchain/`.

### Phase 6: Example and documentation

**Deliverables:**
- `examples/circom-multiplier` with a README anyone can follow
- Docs site or `docs/` folder: quickstart, concepts, CLI reference, format
  reference, troubleshooting (common encoding mistakes and their symptoms)
- README rewritten as a user-facing document (quickstart first, roadmap moved
  out)
- Compatibility table: protocol, `soroban-sdk`, snarkjs, Circom, Rust versions

**Exit criteria:** a new developer, timed, reaches a verified proof in under
30 minutes using only the docs.

### Phase 7: Hardening and v1.0 (complete)

**Deliverables:**
- Independent review of encoders, validators, and generated verifier contracts (`docs/security-review.md`)
- Fuzzing of decoders and the envelope parser (8 `cargo-fuzz` targets and in-tree regression property tests)
- Resolution of review findings, with a public summary (recursion depth limit on JSON parser, `n_ic` validation)
- Release process (`docs/release.md`), versioned packages (`1.0.0`), changelog (`CHANGELOG.md`), `v1.0.0` tag

**Exit criteria:** review complete, no open high-severity issues, spec promoted to 1.0 with no remaining **[VERIFY]** items (all criteria satisfied).

### Phase 8+: Expansion (complete)

**Delivered:**
1. **Noir Adapter (`astrolabe-core::noir`, `astrolabe-ts/noir`, CLI `--source noir`):**
   - Full parser and envelope wrapper for Noir Groth16 proving artifacts (`proof.json`, `verification_key.json`, `public.json`) and unified Noir artifact bundles.
   - Preserves compiler/backend provenance metadata (`noir_version`, `backend`, `circuit_name`) per ACF Spec Section 10.2 without altering canonical bytes.
   - Comprehensive test fixtures and suites in Rust and TypeScript.
2. **RISC Zero Adapter (`astrolabe-core::risc0`, `astrolabe-ts/risc0`, CLI `--source risc0`):**
   - Maps 256-byte Groth16 seals (`A || B || C`) into canonical `Proof`.
   - Maps guest `image_id` and `journal_digest` into `PublicInputs` with both standard 4-scalar (`Limb16`, matching Bonsai recursion circuit) and 2-scalar (`Direct`) modes.
   - Zero-dependency `#![no_std]` NIST SHA-256 implementation in Rust and TypeScript for hashing raw journals.
   - Supports flat receipts and nested Bonsai Groth16 receipt formats with full validation.
3. **Soroban Cost Profiler (`astrolabe profile`):**
   - CLI subcommand simulating Groth16 verification in Soroban `Env` using `env.cost_estimate().budget()`.
   - Measures exact CPU instruction counts and RAM memory bytes against Stellar Protocol 25 network limits (100M CPU instructions, 40MB memory).
   - Inspects compiled contract WASM files against the 64 KiB recommended / 128 KiB protocol limits, computing headroom percentages.
   - Human-readable status breakdown and `--json` flag for CI and automated regression benchmarks.
4. **Soroban ZK Application Contract Templates:**
   - `MerkleMembershipContract`: private leaf inclusion verification against authorized Merkle roots in contract instance storage.
   - `PrivateVoteContract`: anonymous voting with Groth16 eligibility proofs, persistent nullifier registry for double-voting prevention, and option tallying.
   - `NullifierClaimContract`: private airdrop and reward redemption with nullifier double-claim prevention.
   - Generator support in `astrolabe gen-verifier --template <merkle-membership|private-vote|nullifier-claim>`.
   - Unit and integration tests verifying contract lifecycle and nullifier replay protection.
5. **Continuous Verification GitHub Action:**
   - Composite GitHub Action `.github/actions/verify-artifacts/action.yml` for automated export, local simulation, and cost profiling of proving artifacts in CI.
   - Integrated into `.github/workflows/ci.yml` verifying artifacts on every pull request and push to main.

**Future extensions (post-v1.1):**
- Additional proof systems (e.g. UltraHonk, PLONK) and curves (BLS12-381) after host protocol expansion.

---

## 9. Quality Strategy

### Conformance
- Vectors in `spec/vectors/` are the contract. Categories: valid, invalid-length,
  invalid-field, invalid-curve, invalid-subgroup, infinity, public-input-count,
  onchain.
- Every validation rule has a failing-input vector.
- At least one vector set comes from an independent source (snarkjs output,
  reference library, or recorded transaction).

### Testing layers
1. Unit tests per primitive
2. Known-answer vector tests (both languages)
3. Round-trip property tests (supplementary, never a replacement)
4. Differential tests: Rust vs TS vs snarkjs
5. Testnet integration tests
6. Fuzzing of parsers (Phase 7)

### Review
- Human line-by-line review for the hotspots listed in `AGENTS.md` Section 11:
  negation of `A`, G2 subgroup check, range checks, public-input count, Fp2
  ordering, and pairing-input construction.
- Pull requests only; `main` is protected.

## 10. Working With AI Agents

- Agents work from `AGENTS.md`, one phase at a time, on a branch per phase.
- Agents never edit the spec, never invent constants, and stop to ask at
  ambiguities.
- Every agent report must include real command output and a list of
  uncertainties.
- Agent-written tests are not trusted on their own: independent vectors and
  differential checks guard against circular reasoning.
- Humans own all conclusions about protocol behavior.

## 11. Risks and Mitigations

| Risk | Impact | Mitigation |
| ---- | ------ | ---------- |
| Spec assumption wrong (Fp2 order, host behavior) | Everything built on it breaks | Phase 1 gate with evidence and negative controls |
| Agent writes circular tests | False confidence | Independent vectors, differential testing, human review |
| Crypto bug (subgroup, negation) | Invalid proofs accepted | Hotspot review, reference-library cross-check, external review |
| Ecosystem overlap or absorption | Reduced relevance | Neutral spec, test vectors, collaboration with existing projects |
| Stellar SDK or protocol changes | Breakage | Pin versions, CI against current releases, compatibility table |
| BN254 security margin below 128 bits | Misplaced user trust | Document honestly in spec, README, and docs |
| Groth16 trusted setup misunderstood | Insecure deployments | Docs warn clearly; tooling surfaces setup provenance |
| Maintainer bandwidth | Stalled project | Small surface area, generated code, recruit co-maintainers early |
| Name collision | Rebrand cost | Check GitHub, crates.io, npm before publishing |

## 12. Open Decisions

| Decision | Options | Status |
| -------- | ------- | ------ |
| Project name | Astrolabe, Starproof, Orrery, Waypoint | Check availability |
| CLI language | Rust or TypeScript | Decide after Phase 3 |
| Verifying key storage in generated contracts | Baked in vs stored on-chain | Decide in Phase 5 |
| `PublicInputs` count prefix | Explicit or implied by VK | Open (spec Section 15) |
| Envelope metadata | Optional section for toolchain versions | Open |
| Docs hosting | GitHub Pages or other | Decide in Phase 6 |
| Lint tooling for TS | Add Biome or ESLint | Defer until real code exists |

## 13. Funding and Sustainability

**Funding routes (verify current dates and terms before applying):**
- Stellar Community Fund (Open Track, Build Awards), judged on ecosystem impact,
  originality, and technical soundness
- Stellar Development Foundation infrastructure grants
- Letters of support from teams building ZK apps on Stellar

**Grant-friendly milestones** (measurable, verifiable):
1. Spec v1.0 with N conformance vectors passing in two languages
2. A linked testnet transaction verifying a Circom proof via the CLI
3. Quickstart validated by a timed new-user run
4. Two or more external projects integrating
5. Independent review completed and published

**Sustainability:** keep the maintenance surface small, pin tool versions,
run CI against current Stellar releases, document decision-making, and recruit
one or two co-maintainers early. Host a tutorial, workshop, or hackathon track
to build a user base.

## 14. Community and Communication

- Announce on Stellar developer channels after Phase 1, with the spec draft, to
  gather feedback before heavy implementation.
- Contact maintainers of related projects (Soroban-ZK-Std, RISC Zero verifier,
  community Circom and Noir guides) early. Ask what they would need from a
  shared format.
- Use GitHub issues and milestones for the roadmap. Label good-first-issues.
- Publish a short changelog and decision log.

## 15. Definition of Done

**Per task:** matches the cited spec sections, vectors added or updated with
sources, `fmt` and `clippy` clean, tests pass with real output shown,
`no_std` build passes, no unjustified dependencies, public APIs documented,
spec untouched, uncertainties listed.

**Per phase:** every exit criterion above is met, the diff is human-reviewed,
CI is green on GitHub, this plan is updated, and the phase is tagged.

**For v1.0:** all phases through 7 complete, no **[VERIFY]** items remain, an
independent review is published, and the quickstart is validated.

## 16. Immediate Next Actions

1. Finish the Phase 0 cleanup items (licenses, `fmt-check`, schema tightening,
   `AGENTS.md` Makefile targets, spec path).
2. Check name availability on GitHub, crates.io, and npm.
3. Execute Phase 1: environment, trivial circuit, throwaway verifier, five
   experiments with negative controls.
4. Write `docs/phase1-findings.md` and update the spec.
5. Open GitHub issues for Phases 2 to 7 and a roadmap issue linking to this plan.
6. Contact related projects and share the spec draft for feedback.

## 17. Changelog

- **2026-11-11:** Phase 8 expansion complete (Noir adapter, RISC Zero adapter, Soroban cost profiler, application contract templates, CI verification action).
- **2026-11-10:** Phase 7 hardening complete. v1.0.0 released with formal review, fuzzing, and spec promotion.
- **2026-10-31:** Initial plan. Phase 0 complete, Phase 1 in progress.