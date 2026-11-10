# Astrolabe Release Process

This document defines the release engineering procedure for tagging and publishing versions of Astrolabe.

---

## 1. Prerequisites and Verification Checklist

Before tagging any release (e.g. `v1.0.0`), all quality and security gates MUST pass with zero warnings or errors:

```bash
# 1. Format check
make fmt-check

# 2. Strict linter check (Rust clippy zero warnings, TypeScript typecheck)
make lint

# 3. Complete test suite (unit tests, integration tests, fuzz regressions)
make test

# 4. WASM compilation check (astrolabe-core #![no_std] wasm32v1-none)
make build-wasm

# 5. Cross-implementation vector conformance check (101 vectors)
make vectors-check

# 6. Cross-implementation 3-way differential check (Rust == TS == snarkjs)
make differential

# 7. Codec fuzzing check
make fuzz
```

---

## 2. Version Bumping Procedure

When preparing a new release `X.Y.Z`:

1. **Rust Workspace (`Cargo.toml`):**
   Update `[workspace.package] version = "X.Y.Z"`.
2. **TypeScript SDK (`packages/astrolabe-ts/package.json`):**
   Update `"version": "X.Y.Z"`.
3. **Internal Path Dependencies:**
   Check `examples/*/contract/Cargo.toml` to ensure dependency version strings match `X.Y.Z`.
4. **Changelog (`CHANGELOG.md`):**
   Add section `## [X.Y.Z] - YYYY-MM-DD` detailing Added, Changed, Fixed, and Security notes.
5. **Project Plan (`Plan.md`):**
   Update status, last updated date, and current phase milestone.

---

## 3. Git Tagging

Create an annotated, signed (or standard) git tag:

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

---

## 4. Package Artifacts (Future Publishing)

When publishing to package registries:

- **crates.io:**
  ```bash
  cargo publish -p astrolabe-core
  cargo publish -p astrolabe-verifier
  cargo publish -p astrolabe-cli
  ```
- **npm:**
  ```bash
  cd packages/astrolabe-ts
  pnpm build
  pnpm publish --access public
  ```
