default: build test lint format

build:
  cargo build

test:
  cargo test

lint:
  cargo clippy

format:
  cargo fmt --all -- --check
