# Affix

Affix is a Windows service that applies process affinity, priority and EcoQoS policies from the 64-bit machine registry. Each normalized image basename has a subkey directly under `HKEY_LOCAL_MACHINE\SOFTWARE\Affix`.

The service opens registry keys for reading only. A missing root, an empty root, or an unmatched image causes no process policy writes. The service never imports defaults or creates registry keys. The application catalog is the external [affix.reg](affix.reg) file; it is not embedded in the executable.

## Registry policy

```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Affix\steam.exe]
"Mode"="efficiency"
"Affinity"="P+E"

[HKEY_LOCAL_MACHINE\SOFTWARE\Affix\moonlight.exe]
"Affinity"="LPE"
```

The parent Affix key can also hold values. No intermediate Applications key is used.

| Value | Registry type | Meaning |
| --- | --- | --- |
| Mode | REG_SZ | normal, efficiency, performance, or realtime |
| Affinity | REG_SZ | A portable or numeric CPU expression, such as E+LPE or 8+9+10+11 |

Mode and affinity are optional. An empty image subkey requests no changes. Unknown image names have no fallback policy. Invalid names, types, mode strings, or affinity expressions are logged and skipped.

An omitted Mode leaves process mode untouched. Efficiency mode supplies affinity E+LPE only when Affinity is absent. Every explicit affinity remains authoritative, including P+E+LPE. Normal, performance and realtime modes leave omitted affinity untouched.

| Mode | Priority class | EcoQoS |
| --- | --- | --- |
| normal | Normal | Disabled |
| efficiency | Idle | Enabled |
| performance | Above normal | Disabled |
| realtime | Realtime | Disabled |

Image matching uses normalized, case-insensitive basenames. Registry subkeys must be a single basename of at most 255 UTF-16 code units. Invalid path separators and embedded NULs are rejected.

Affinity terms are joined by +:

- P: performance cores.
- E: efficiency cores.
- LPE: low-power efficiency cores.
- C: the selected large-cache CPU island.
- Non-negative decimal numbers: 0-based OS logical processor indices.

For example, P+2 combines performance cores with logical processor 2. P+E+LPE allows all known portable tiers. Existing topology selection, usable-CPU filtering and mask validation apply.

Registry reads are uncached. A new policy selection sees current values, while tracked processes retain their resolved policy during bounded checks. Restart the service after editing or importing policies to deterministically apply changes to already-running processes. Removing a value stops future enforcement of that setting; Affix does not restore an unknown historical value.

## Application catalog

[affix.reg](affix.reg) contains the 63 application policies, including the edits made during the registry migration. Moonlight retains its affinity-only LPE rule. FFXIV and javaw use 8+9+10+11; the compiler rules use P. WorkloadsSessionHost.exe is intentionally absent.

Edit the external catalog or registry policies independently of the executable. Tests cover registry access and policy semantics without asserting the catalog's contents.

## Installation and manual import

The MSI installs affix.exe, affix.reg and import-policies.ps1. Before starting the service, it runs the importer with machine privileges in the 64-bit registry view. Only missing image subkeys are imported. Existing complete, partial and empty subkeys are retained as-is, including during upgrades and repairs. Registry policies are retained on uninstall.

To seed missing policies manually from an elevated PowerShell session in the repository:

```powershell
.\packaging\windows\import-policies.ps1 -RegFile .\affix.reg
```

From the installed directory, the importer finds affix.reg beside itself:

```powershell
.\import-policies.ps1
```

Standard Windows import is also supported:

```powershell
reg.exe import .\affix.reg /reg:64
```

A standard import overwrites the values explicitly listed in the file. Omitted values already present in the registry remain present. Use the supplied importer to preserve existing image policies, or remove unwanted values explicitly when using Registry Editor or reg.exe.

For a manual binary deployment:

```powershell
.\affix.exe install
Start-Service affix
```

The install command registers the service. Importing policies is a separate administrator action. A manual binary deployment with no registry entries performs no application policy changes.

## Process tracking and bounded reconciliation

Windows process-start ETW is the primary enforcement path. Processes are identified by PID plus creation time and a normalized image name, protecting against PID reuse. Classic and modern events are supported, with event-loss handling and orderly shutdown.

For each tracked process instance, the coordinator performs three later PID-local checks. Each one-shot timer expires after 60 seconds with up to 30 seconds of Windows coalescing slack. The worker uses Windows background mode and parks after all tracked instances exhaust their checks.

Checks query only policy components configured for that process: affinity, priority and EcoQoS. Confirmed drift repairs only the affected components. Independent query or setter failures do not suppress other components. Confirmed exit, creation-time mismatch or image mismatch can trigger one coalesced full reconciliation after PID-local locks are released. An unresolved PID with an unsignaled retained process handle consumes a check without causing a global scan.

New tracked processes join the current timer batch without resetting its deadline. Removal does not wake the coordinator. Removing the last pending instance cancels the timer. Counters belong to process instances and saturate at three; power-profile notifications do not reset them. Enforcement is best-effort after that limit.

Power-profile notifications still cause reconciliation. Process policy comes from registry values and is not inferred from the Windows power slider.

Affix applies its existing low-impact policy to its own service process. With no application rules, the monitoring service stays available while leaving other processes untouched.

## Debug diagnostics

Debug builds publish coordinator diagnostics through the paging-file-backed mapping:

```text
Global\0x484558.Affix.Diagnostics.v1
```

`affix diagnostics` opens it read-only and prints phase, inventory, timer/pass counts, drift, repairs and worker failures as key=value lines. The mapping exists while the service holds it; reading a service-owned global mapping may require elevation. Release builds omit the mapping and diagnostics command.

## Building and packaging

The repository uses the nightly Rust toolchain. The default build includes registry policy support unconditionally.

```powershell
cargo build --release --locked
cargo check --locked --workspace --all-targets --all-features
cargo test --locked --workspace --all-features
```

The only optional runtime feature is priority-job, which enables Windows job-object priority enforcement:

```powershell
cargo build --release --locked --features priority-job
```

Build the MSI with WiX 4 or newer installed:

```powershell
cargo xtask package-msi
cargo xtask package-msi-debug
```

The release package is target\wix\affix-<version>-x86_64.msi. The debug package has a -debug suffix and exposes diagnostics for live verification. MSI product codes are regenerated per package; the stable upgrade code supports major upgrades.

The packaging helper invokes the native WiX CLI directly. It finds wix.exe on PATH or in the standard Program Files WiX installation directories. The existing [MSI smoke script](packaging/windows/smoke-msi.ps1) exercises installation and service lifecycle and requires an elevated test machine.

Registry behavior tests use unique temporary HKCU subtrees and remove them afterwards.
