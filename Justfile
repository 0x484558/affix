set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

prefix := "/usr/local"
bindir := prefix + "/bin"
system_unit_dir := prefix + "/lib/systemd/system"
share_dir := prefix + "/share/affix"
man5_dir := prefix + "/share/man/man5"
man8_dir := prefix + "/share/man/man8"
binary := "target/release/affix"

build:
    cargo build --release

install: build
    sudo install -Dm0755 {{binary}} {{bindir}}/affix
    sudo rm -f {{prefix}}/lib/systemd/user/affix.service
    sudo rm -f {{share_dir}}/affix-images.toml
    sudo rm -f {{share_dir}}/images.example.toml
    sudo rm -f {{man5_dir}}/affix-images.toml.5
    sudo install -Dm0644 systemd/system/affix.service {{system_unit_dir}}/affix.service
    sudo install -Dm0644 config/linux/affix.example.toml {{share_dir}}/affix.example.toml
    sudo install -Dm0644 man/man5/affix.toml.5 {{man5_dir}}/affix.toml.5
    sudo install -Dm0644 man/man8/affix.8 {{man8_dir}}/affix.8
    if command -v systemctl >/dev/null 2>&1; then sudo systemctl daemon-reload; fi
    if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then systemctl --user daemon-reload; fi
