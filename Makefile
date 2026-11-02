.PHONY: fmt fmt-check lint test build-wasm vectors-check differential

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --all-features -- -D warnings
	pnpm -r lint

test:
	cargo test --workspace
	pnpm -r test

build-wasm:
	cargo build -p astrolabe-core --target wasm32v1-none --release

vectors-check:
	cargo test -p astrolabe-core --test vectors
	pnpm -r --filter astrolabe-ts test -- test/vectors.test.ts

differential:
	@echo "not implemented yet"
	@exit 1
