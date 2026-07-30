default:
    @just --list

check:
    cargo check --locked --workspace --all-targets --all-features

test:
    cargo test --locked --workspace --all-features

package:
    cargo xtask package-msi
