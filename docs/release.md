# Release process

This document describes the release process of Aegis-rs.

## Prerequisites

Install [Cargo release](https://github.com/crate-ci/cargo-release):

```bash
cargo install cargo-release
```

## Actions

1. Start of with a clean repo on the master branch
2. Dry-run the release for the next version, e.g.
    - `cargo release patch`
    - `cargo release minor`
    - `cargo release major`
3. Release the next version by providing the `-x` flag, e.g.
    - `cargo release patch -x`
    - `cargo release minor -x`
    - `cargo release major -x`
4. Wait for the CI to both build the binaries and to create a release draft on GitHub
5. Fill out the release notes
6. Publish the release on GitHub

