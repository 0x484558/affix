# Affix

Affix is a CPU placement policy daemon. It applies per-process CPU affinity and process mode policy on Windows and Linux, with optional policy variants selected by the operating system power profile.

On Linux, Affix watches process creation events and enforces affinity through systemd runtime `AllowedCPUs=` where ownership is clear, or through Affix-owned cgroup v2 cpuset cgroups where a process is eligible for safe fallback ownership. On Windows, Affix runs as a Windows service and applies the corresponding Windows process policy APIs.

This README is the primary human-readable reference. The manpages under `man/` are installable copies for systems that expect manpage documentation.

## Commands

```text
affix
affix install
```

`affix` runs the daemon. Under systemd this is the command used by the installed service unit.

`affix install` installs the Windows service. It is not implemented on Linux; use the project install recipe or the Arch package there.

Unsupported extra command-line arguments are rejected.

## Configuration Files

Affix reads `affix.toml`.

On Windows:

- Configuration: `C:\ProgramData\Affix\affix.toml`
- Persistent decision database: `C:\ProgramData\Affix\applications.sqlite`
- The Windows service creates the default configuration file when it is missing or empty.

On Linux as root or as a system service:

- Configuration: `/etc/affix/affix.toml`
- Persistent decision database: `/var/lib/affix/applications.sqlite`
- The Linux daemon does not create the active configuration file automatically.

On Linux as a user service or foreground user process:

- Configuration: `$XDG_CONFIG_HOME/affix/affix.toml`
- Fallback configuration: `$HOME/.config/affix/affix.toml`
- Persistent decision database: `$XDG_STATE_HOME/affix/applications.sqlite`
- Fallback database: `$HOME/.local/state/affix/applications.sqlite`

Empty or relative `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, and `HOME` values are ignored. If no valid absolute user base exists, Affix falls back to the Linux system paths.

The Linux install recipe installs an example configuration at `/usr/local/share/affix/affix.example.toml`. Copy it to `/etc/affix/affix.toml` to make it active for the system service.

## Top-Level Settings

```toml
heuristics = true
```

`heuristics` enables or disables database-backed heuristic classification. If omitted, it defaults to `true`.

When Affix is built without the `heuristics` feature, only built-in database-backed static defaults are available.

## Process Rules

Each process rule is a TOML table. The table name is the image selector.

```toml
["Game.exe"]
mode = "realtime"
affinity = "P+E"
```

On Linux, a selector that contains at least one `/` is matched as a full executable path against `/proc/<pid>/exe`.

```toml
["/usr/lib/systemd/systemd-journald"]
affinity = "2+3"
mode = "normal"
```

On Linux, a selector without `/` is intentionally broad: it matches the truncated `/proc/<pid>/comm` name or the basename of `/proc/<pid>/exe`.

```toml
[systemd-journald]
affinity = "E+LPE"
mode = "efficiency"
```

On Windows, selectors are image names from the configured process rule set.

Windows-style dotted executable names may also be expressed with an `exe` subtable:

```toml
[game]
exe = { affinity = "P" }
```

That is equivalent to a rule for `game.exe`.

The top-level `[exe]` table is invalid. Put fields inside an image rule such as `[game.exe]` or use an `exe` subtable under a non-empty prefix.

## Rule Fields

### `affinity`

`affinity` is a portable or numeric affinity expression.

```toml
affinity = "P+E"
```

Terms are separated with `+`.

Portable terms:

- `P`: performance cores.
- `E`: efficient cores.
- `LPE`: low-power efficient cores.
- `LP-E`: alias for `LPE`.
- `C`: cache-preferred core set.
- `X3D`: alias for `C`.

Decimal numeric terms select logical processor indexes directly:

```toml
affinity = "0+1+6+7"
```

Terms may be combined:

```toml
affinity = "P+E+LPE"
```

`P+E+LPE` is equivalent to allowing all known portable core tiers when those tiers exist.

### `affinity_mask`

`affinity_mask` is an explicit affinity bitmask. It may be a TOML integer, a decimal string, or a hexadecimal string with a `0x` or `0X` prefix.

```toml
affinity_mask = 8
affinity_mask = "0x3"
```

Zero is invalid.

If both `affinity_mask` and `affinity` are set in the same rule table, the later parser conversion stores `affinity`; do not set both in normal configuration.

### `mode`

`mode` selects process mode.

```toml
mode = "normal"
mode = "efficiency"
mode = "performance"
mode = "realtime"
```

Valid values:

- `normal`: do not request efficiency, performance, or realtime mode. This is the default. The alias `none` is also accepted.
- `efficiency`: request efficiency mode. If `affinity` and `affinity_mask` are omitted, Affix assigns the portable affinity expression `E+LPE`.
- `performance`: request performance mode. If `affinity` and `affinity_mask` are omitted, Affix assigns the portable affinity expression `P+E+C`.
- `realtime`: request realtime mode. If `affinity` and `affinity_mask` are omitted, Affix assigns the portable affinity expression `P+C`.

On Windows, `efficiency` applies EcoQoS and uses idle priority; `performance` uses above-normal priority; `realtime` uses realtime priority. On Linux, process priority policy is not currently the power-slider mechanism; Linux affinity enforcement is cgroup cpuset based.

## Power Profiles

Affix supports profile-specific rule tables for:

- `efficiency`
- `balanced`
- `performance`

Profile-specific tables are partial overlays over the top-level rule for the same image. The selected profile-specific rule supplies any fields it defines; missing fields fall back to the top-level rule. If a field is still absent after merging, Affix uses OS default behavior for that field, except that `mode = "efficiency"` without affinity defaults to `E+LPE`, `mode = "performance"` without affinity defaults to `P+E+C`, and `mode = "realtime"` without affinity defaults to `P+C`.

This means:

```toml
["Game.exe"]
mode = "realtime"

["Game.exe".performance]
affinity = "P+E"
```

When the active power profile is `performance`, `Game.exe` receives `mode = "realtime"` from the top-level rule and `affinity = "P+E"` from the performance overlay.

When the active power profile is not `performance`, the top-level rule still applies and realtime mode supplies its default `P+C` affinity.

A profile-specific rule may override top-level mode:

```toml
[App.exe]
mode = "realtime"
affinity = "P"

[App.exe.performance]
mode = "normal"
```

When the active power profile is `performance`, the effective rule is `mode = "normal"` plus `affinity = "P"`.

Profile-specific-only rules are valid:

```toml
[App.exe.performance]
mode = "efficiency"
affinity = "P"
```

This creates only a performance-specific rule. It does not create a default rule for `App.exe`.

Power profile names can be written as quoted dotted TOML tables or unquoted dotted tables when TOML syntax allows it:

```toml
["app.exe".performance]
affinity = "E"

[app.exe.performance]
mode = "normal"
```

## Power Profile Mapping

On Windows, Affix subscribes to modern effective power mode notifications with `PowerRegisterForEffectivePowerModeNotifications`. It targets the modern Windows 11 power slider behavior, not legacy `powercfg` plans.

Windows mapping:

- `EffectivePowerModeBatterySaver` and `EffectivePowerModeBetterBattery` -> `efficiency`
- `EffectivePowerModeBalanced` -> `balanced`
- `EffectivePowerModeHighPerformance`, `EffectivePowerModeMaxPerformance`, `EffectivePowerModeGameMode`, and `EffectivePowerModeMixedReality` -> `performance`

On Linux, Affix watches the system D-Bus service `org.freedesktop.UPower.PowerProfiles` at `/org/freedesktop/UPower/PowerProfiles` and reads the `ActiveProfile` property from interface `org.freedesktop.UPower.PowerProfiles`.

Linux mapping:

- `power-saver` -> `efficiency`
- `balanced` -> `balanced`
- `performance` -> `performance`

Affix reacts to power-profile change events by reconciling processes against the active effective rules. There is no loop polling for power mode changes.

## Effective Policy Semantics

Affix resolves policy in two layers.

Configuration resolution decides which rule applies:

- The active operating-system power profile selects one of `efficiency`, `balanced`, or `performance`.
- If an image has a matching profile-specific table, that table overlays the top-level table for the same image.
- Missing fields in the profile-specific table inherit from the top-level table.
- Missing fields after that merge mean OS-default behavior for that field.
- If `mode = "efficiency"` is present and both `affinity` and `affinity_mask` are absent, Affix supplies the default portable affinity `E+LPE`.
- If `mode = "performance"` is present and both `affinity` and `affinity_mask` are absent, Affix supplies the default portable affinity `P+E+C`.
- If `mode = "realtime"` is present and both `affinity` and `affinity_mask` are absent, Affix supplies the default portable affinity `P+C`.

Runtime reconciliation decides what to do to the live process tree:

- A process with no matching rule family is ignored. Affix must not apply OS-default policy to unrelated system processes.
- A process with a matching rule family but no effective affinity is OS-default for affinity. Untouched processes are left where they are.
- A process previously moved by Affix into an Affix-owned cgroup is moved back to its recorded origin cgroup when the effective affinity becomes OS-default.
- A systemd unit whose runtime `AllowedCPUs` was changed by Affix is restored to the recorded original `AllowedCPUs` byte-array value when the effective affinity becomes OS-default.
- Affix does not preserve or replay arbitrary pre-existing per-process affinity or priority. Its reset model is OS default or the other effective policy that applies now, not historical reversal.

Process-tree traversal is independent per process. A parent match supplies an inherited target to descendants, but every child is resolved against the rule set before that inherited target is used. If `steam` has one rule and a child `game` has a more specific applicable rule, the child and its subtree use the `game` target.

Priority and mode are independent from the power-slider mechanism. Power-profile-specific tables may contain `mode`, but a power slider change does not imply that priority should be derived from the slider. It only causes Affix to reconcile the tree against the effective rule for the active profile.

## Linux Cgroups

On Linux, Affix enforces affinity through cgroup v2 cpusets. The daemon is intended to run as root when cpuset enforcement is required, because creating cpuset cgroups, migrating processes, and adjusting system units require privileges on the cgroup hierarchy and systemd D-Bus.

Linux enforcement has three possible outcomes for a process with an effective affinity:

- A specific service unit containing the matched process, or a specific app/scope unit that matches the process identity, receives runtime `AllowedCPUs=`.
- A process under desktop app/background lineage but without a matching app-specific unit is moved to an Affix-owned cpuset cgroup.
- A broad or unrelated systemd-owned context is skipped rather than mutated too broadly.

This is deliberate. In cgroup v2, systemd owns most of the process hierarchy on normal desktop and service systems. Moving arbitrary processes out of their original unit can bypass service accounting, cleanup, resource controls, and ownership semantics. Mutating a broad unit such as a session scope can affect far more processes than the image rule matched. Affix therefore prefers systemd's own runtime resource-control API when the process maps to a coherent unit, and only falls back to Affix-owned cgroups for narrower desktop/user-launched cases.

### Systemd Unit Targeting

When a process maps to a specific systemd unit, Affix first asks systemd to set runtime `AllowedCPUs=` on that unit. For system services this uses the system manager. For desktop app scopes under `user@UID.service`, Affix connects to `/run/user/UID/bus` and adjusts the user manager unit. Affix records the unit's original `AllowedCPUs` value in memory and restores it when the active policy for that unit becomes OS-default.

Affix does not require service unit names to match the binary name. A matched process contained in `systemd-journald-blahblah.service` can target that specific service even when the executable is `systemd-journald`. For desktop app scopes and app slices, Affix does require the unit name to match the process identity. For example, `app-org.kde.konsole-*.scope` can be adjusted for `konsole` itself, but an unrelated binary launched inside Konsole is not allowed to mutate the whole Konsole app scope.

Systemd exposes `AllowedCPUs` on D-Bus as a byte-array CPU bitmap, not as the textual CPU list accepted by `systemctl set-property`. Affix converts its normalized CPU mask to that bitmap and calls runtime `SetUnitProperties`, so the change is not persisted in unit files.

For a service like `/system.slice/systemd-journald-blahblah.service`, a matching rule for the contained `systemd-journald` process can reasonably target `systemd-journald-blahblah.service`. For a desktop app like `/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.kde.konsole-123.scope`, a matching rule for `konsole` can reasonably target `app-org.kde.konsole-123.scope` through the user manager.

### Affix-Owned Fallback Cgroups

If the process is under a desktop app/background lineage but does not have a matching app-specific unit of its own, Affix can fall back to an Affix-owned cpuset cgroup. Affix-owned cgroups are allocated by normalized effective CPU mask, and distinct rules that resolve to the same effective CPU mask share a cgroup. Affix-owned cpuset cgroups use the `affix-` prefix.

Broad session or service-manager cgroups are not blindly split or mutated. A process under a broad `session-*.scope`, `user@UID.service`, or unrelated system service is skipped unless it maps to a specific matching systemd unit or to a desktop app lineage eligible for the Affix-owned fallback.

Before creating an Affix cpuset for a process, Affix intersects the requested mask with the process origin cgroup's `cpuset.cpus.effective` and the process scheduler affinity mask. This makes Affix respect administrative CPU envelopes from systemd `AllowedCPUs=` and scheduler-affinity defaults such as systemd `CPUAffinity=`.

If a matching rule family exists but no affinity applies under the active power profile, Affix does not move an untouched process into an Affix cgroup. For a process that Affix already moved, the daemon records the origin cgroup in memory and moves the process back there when the active policy becomes OS-default. This is placement state, not policy restoration state; Affix still does not preserve or replay pre-existing non-default affinity policy.

During process-tree traversal, each process is resolved independently. A child process that has its own applicable rule is not forced into its parent's cgroup merely because the parent rule matched first.

### Systemd Envelopes

`AllowedCPUs=` and `CPUAffinity=` are different systemd mechanisms:

- `AllowedCPUs=` is a cgroup v2 cpuset resource-control property. Its effective value is limited by parent units and is visible through `EffectiveCPUs=`.
- `CPUAffinity=` is scheduler affinity inherited by executed processes. It is not the same as cpuset membership.

The kernel schedules a thread only on the intersection of scheduler affinity, cpuset constraints, and online CPUs. A cgroup that allows `0-31` does not make CPUs `0-15` usable if the process inherited `CPUAffinity=16-31`. Affix intentionally respects both axes: Affix-owned cpuset leaves are clamped by `cpuset.cpus.effective` and by `sched_getaffinity(pid)`.

If the administrator wants a global administrative envelope, configure it in systemd. Affix should operate inside that envelope rather than undo it.

### Broad Slice Policy

Some useful policies are broader than Affix's image-rule model. For example, an administrator might want every process in a desktop background slice to run only on efficient cores. That is a systemd slice policy, not a per-image Affix policy.

Prefer setting it directly in systemd:

```bash
systemctl --user set-property --runtime background.slice AllowedCPUs=8-15
```

or persist it with a user-manager drop-in if the policy is intended to survive restarts. In that case there is no need for Affix to "restore" the slice, because Affix did not own the slice policy in the first place. This is also more honest semantically: every process in the slice is affected because the slice was selected, not because a particular executable image happened to match.

Do not approximate a broad slice policy by writing a broad Affix image rule that happens to match many children in a session scope. That risks either doing nothing, because Affix refuses broad ownership, or splitting processes out of useful systemd accounting when the fallback lineage permits it.

### Failure Behavior

If systemd D-Bus targeting fails for a specific unit, Affix logs the failure. If the process is also eligible for Affix-owned fallback, Affix may still enforce the affinity through its own cpuset. If it is not eligible, the process is skipped. This avoids turning a failed narrow unit update into a broad session mutation.

If Affix restarts, in-memory records of Affix-owned process origins and systemd unit original `AllowedCPUs` values are lost. Affix can still reconcile current rules for live processes, but it cannot restore unit or process placement state that was only known to the previous daemon process.

The installed Linux systemd system unit runs `/usr/local/bin/affix` as root by default and includes service hardening options. The Linux install recipe does not enable or start the systemd service; enable or start it explicitly with `systemctl`.

## Examples

Broad Linux rule matching both system and user `dbus-daemon` instances:

```toml
[dbus-daemon]
affinity = "2+3"
mode = "normal"
```

Portable low-power rule for journald:

```toml
[systemd-journald]
affinity = "E+LPE"
mode = "efficiency"
```

Windows default-style rules:

```toml
heuristics = true

["steam.exe"]
mode = "efficiency"
affinity = "P+E"

["Moonlight.exe"]
mode = "realtime"
affinity = "E"
```

Power-profile-specific rules:

```toml
["Game.exe"]
mode = "realtime"

["Game.exe".performance]
affinity = "P+E"

["App.exe".efficiency]
affinity = "LPE"

["App.exe".balanced]
affinity = "E+LPE"
```

## Building

Affix uses the Rust toolchain selected by the environment. The repository has `rust-toolchain.toml` with `channel = "nightly"` because the current Cargo configuration uses nightly options.

Build:

```bash
cargo build --release
```

Run tests:

```bash
cargo test --locked
```

Build with the optional heuristic classifier feature:

```bash
cargo build --release --features heuristics
```

## Linux Install

The local install recipe uses `/usr/local`:

```bash
just install
```

It installs:

- `/usr/local/bin/affix`
- `/usr/local/lib/systemd/system/affix.service`
- `/usr/local/share/affix/affix.example.toml`
- `/usr/local/share/man/man5/affix.toml.5`
- `/usr/local/share/man/man8/affix.8`

The recipe reloads systemd when `systemctl` is available, but it does not enable or start the service.

Typical system-service activation:

```bash
sudo install -Dm0644 /usr/local/share/affix/affix.example.toml /etc/affix/affix.toml
sudo systemctl enable --now affix.service
```

## Arch Package

The Arch packaging lives under `packaging/arch/affix-git`.

It depends on `cargo`, not specifically `rustup`, so it can build with either distro Rust/Cargo or a rustup-managed Cargo frontend. The package recipe does not export `RUSTUP_TOOLCHAIN`; toolchain selection is left to the installed Rust frontend and the repository toolchain file.

## Windows Install

The legacy manual deployment script is `deploy.ps1`. It copies `target\release\affix.exe` to `C:\Windows\affix.exe` and runs `affix.exe install`.

The preferred Windows packaging path is MSI:

```powershell
cargo xtask package-msi
```

The MSI is written to:

```text
target\wix\affix-0.1.0-x86_64.msi
```

The MSI installs:

- Binary: `C:\Program Files\Affix\affix.exe`
- Service name: `affix`
- Display name: `Affix Process Monitor`
- Service account: `LocalSystem`
- Start type: automatic

The MSI uses WiX v4+ schema and the modern WiX CLI. `cargo-wix` must expose `--toolset modern`. If the crates.io build does not, install the pinned upstream build used by this repository:

```powershell
cargo install --git https://github.com/volks73/cargo-wix --rev fde983c2e901970267e76b8fd68120fdd5457a57 cargo-wix --force
```

WiX 7 requires OSMF EULA acceptance before non-interactive packaging:

```powershell
wix eula accept wix7
```

The MSI smoke test is intentionally a PowerShell script, not an xtask subcommand, because it mutates machine service state:

```powershell
sudo powershell -ExecutionPolicy Bypass -File .\packaging\windows\smoke-msi.ps1
```

The smoke test stops and deletes an existing `affix` service, removes `C:\Windows\affix.exe` if present, performs a quiet MSI install, and verifies that the MSI-installed service is running from `C:\Program Files\Affix\affix.exe`.

## Manpages

Installed manpages:

```bash
man 8 affix
man 5 affix.toml
```

From the repository checkout:

```bash
man -l ./man/man8/affix.8
man -l ./man/man5/affix.toml.5
```

## Attribution and License

Coparight © Vladyslav "Hex" Yamkovyi, 2026.

Affix is licensed under the European Union Public License (EUPL) version 1.2; see [LICENSE](LICENSE) file for more info.
