# Astrolabe

**The navigation toolkit for getting zero-knowledge proofs onto Stellar.**

> **Status: early draft. Not implemented, not audited, not for production use.**
> The format spec is a working draft with open questions. Do not use any of this
> to secure real funds.

Astrolabe is an open-source, toolchain-neutral pipeline for moving ZK proofs
from tools like Circom/snarkjs, Noir, and RISC Zero into Soroban smart contracts
using the Stellar Protocol 25 BN254 host functions.

## The problem

Protocol 25 gave Soroban native BN254 and Poseidon support, so contracts can
verify ZK proofs. Getting a proof from a proving toolchain into a contract is
still manual and error-prone. Developers write one-off scripts to fix
endianness, coordinate order, and byte layouts, and a small mismatch makes
verification fail with no useful error. Every team repeats this work.

## What Astrolabe will provide

- **A canonical format spec with test vectors.** One versioned, unambiguous
  byte-level encoding for proofs, verification keys, and public inputs.
  See [`spec/spec.md`](spec/spec.md).
- **A TypeScript SDK** for browser and Node, including Web Worker proving and
  Freighter integration.
- **A Rust crate** (`no_std` core) that does the same encoding and acts as a
  differential-testing oracle.
- **A CLI** with `export`, `gen-verifier`, `verify`, and `doctor` commands.
- **Toolchain adapters.** Circom/snarkjs first, then Noir (via a Groth16
  backend), then RISC Zero.

## Scope of v1

1. Format spec and golden test vectors
2. TypeScript and Rust encoders, tested against each other and against snarkjs
3. CLI: `export`, `gen-verifier`, `verify`, `doctor`
4. A documented end-to-end Circom to Stellar testnet example

Later: Noir and RISC Zero adapters, cost profiling, starter templates, and a CI
action. See the roadmap below.

## Roadmap

| Phase | Goal | Status |
| ----- | ---- | ------ |
| 0 | Repo scaffold, CI, lint | Not started |
| 1 | Resolve open spec questions with a manual testnet run | Not started |
| 2 | Primitive encoders and validators (Rust + TS) | Not started |
| 3 | Groth16 objects and envelope | Not started |
| 4 | snarkjs adapter and differential tests | Not started |
| 5 | Verifier contract template and CLI | Not started |
| 6 | Testnet example and documentation | Not started |
| 7+ | Noir, RISC Zero, profiling, templates, CI action | Planned |

## Repository layout (planned)

```
spec/          Format spec and conformance test vectors
crates/        Rust: core library, verifier helpers, CLI
packages/      TypeScript SDK
examples/      End-to-end examples
scripts/       Dev and cross-check scripts
```

## Related work

Astrolabe is meant to complement, not replace, existing Stellar ZK work,
including:

- [Soroban-ZK-Std](https://github.com/georgegoldman/Soroban-ZK-Std): on-chain
  field arithmetic and cryptographic primitives
- The Groth16 verifier example in `stellar/soroban-examples`
- Community walkthroughs and scripts for Circom and Noir on Stellar
- Nethermind's RISC Zero Groth16 verifier for Soroban

If your project is solving the same encoding problem separately, we would like
to hear from you.

## Contributing

Contributions are welcome, especially in these areas:

- Reviewing the spec against the Stellar CAP-0074 text and real transactions
- Independent test vectors from other libraries
- Adapters for additional toolchains

Please read [`AGENTS.md`](AGENTS.md) for the project's working rules. They apply
to human contributors as well as AI coding agents. Open an issue before starting
large changes.

AI-assisted contributions are fine, but you are responsible for reviewing and
understanding every line you submit. Cryptographic code gets extra scrutiny.

## Security

This project handles cryptographic code. See [`SECURITY.md`](SECURITY.md) for
how to report vulnerabilities. Please do not open public issues for security
problems.

## License

Licensed under 
- MIT license ([LICENSE-MIT](LICENSE-MIT))
