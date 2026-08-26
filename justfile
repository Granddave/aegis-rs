default: build test lint format docs

build:
  cargo build --all-targets

test:
  cargo test --all-targets

lint:
  cargo clippy --all-targets -- -D warnings

format:
  cargo fmt --all -- --check

docs:
  cargo doc --no-deps --all-features
