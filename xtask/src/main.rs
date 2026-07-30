use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".to_owned());

    match command.as_str() {
        "package-msi" => package_msi(true),
        "package-msi-debug" => package_msi(false),
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        other => Err(format!(
            "unknown xtask command `{other}`. Run `cargo xtask help`."
        )),
    }
}

fn package_msi(release: bool) -> Result<(), String> {
    require_windows_host()?;
    ensure_wix_project_metadata()?;
    let wix = wix_executable()?;
    ensure_wix_cli(&wix)?;
    let version = affix_version()?;

    let mut build = Command::new("cargo");
    build.arg("build");
    if release {
        build.arg("--release");
    }
    build.args(["--locked", "--package", "affix"]);
    run_checked(
        &mut build,
        if release {
            "cargo build --release --locked --package affix"
        } else {
            "cargo build --locked --package affix"
        },
    )?;

    let msi = default_msi_path(&version, release);
    if let Some(parent) = msi.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create `{}`: {error}", parent.display()))?;
    }

    run_checked(
        Command::new(&wix)
            .arg("build")
            .arg("wix/main.wxs")
            .args(["-arch", "x64"])
            .arg("-d")
            .arg(format!("Version={version}"))
            .arg("-d")
            .arg(format!(
                "CargoTargetBinDir={}",
                if release {
                    "target/release"
                } else {
                    "target/debug"
                }
            ))
            .arg("-o")
            .arg(&msi),
        "wix build wix/main.wxs",
    )?;

    println!("MSI written to {}", msi.display());
    Ok(())
}

fn wix_executable() -> Result<PathBuf, String> {
    if let Some(paths) = env::var_os("PATH") {
        for directory in env::split_paths(&paths) {
            let candidate = directory.join("wix.exe");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    // A running shell may still have the PATH from before the WiX installation.
    if let Some(program_files) = env::var_os("ProgramFiles") {
        for version in [7, 6, 5, 4] {
            let candidate = PathBuf::from(&program_files)
                .join(format!("WiX Toolset v{version}.0"))
                .join("bin")
                .join("wix.exe");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err("WiX CLI was not found. Install WiX 4 or newer and add its bin directory to PATH.".into())
}

fn ensure_wix_cli(wix: &Path) -> Result<(), String> {
    let version = output_checked(Command::new(wix).arg("--version"), "wix --version")?;
    let version = version.trim();
    if version.starts_with('4')
        || version.starts_with('5')
        || version.starts_with('6')
        || version.starts_with('7')
    {
        Ok(())
    } else {
        Err(format!(
            "modern WiX CLI 4 or newer is required; `wix --version` returned `{version}`"
        ))
    }
}

fn default_msi_path(version: &str, release: bool) -> PathBuf {
    Path::new("target").join("wix").join(if release {
        format!("affix-{version}-x86_64.msi")
    } else {
        format!("affix-{version}-debug-x86_64.msi")
    })
}

fn affix_version() -> Result<String, String> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| "xtask manifest has no workspace parent".to_owned())?
        .join("Cargo.toml");
    let contents = fs::read_to_string(&manifest)
        .map_err(|error| format!("failed to read `{}`: {error}", manifest.display()))?;
    let mut in_package = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_package = trimmed == "[package]";
            continue;
        }
        if in_package && let Some(value) = trimmed.strip_prefix("version =") {
            let version = value.trim().trim_matches('"');
            if !version.is_empty() {
                return Ok(version.to_owned());
            }
        }
    }
    Err(format!(
        "package version not found in `{}`",
        manifest.display()
    ))
}

fn ensure_wix_project_metadata() -> Result<(), String> {
    let source = fs::read_to_string(Path::new("wix").join("main.wxs"))
        .map_err(|error| format!("failed to read wix/main.wxs: {error}"))?;
    if !source.contains("Manufacturer=\"0x484558\"") {
        return Err("wix/main.wxs must identify 0x484558 as Manufacturer".to_owned());
    }
    if !source.contains("Version=\"$(var.Version)\"") {
        return Err(
            "wix/main.wxs must use $(var.Version) so Cargo package version reaches MSI".to_owned(),
        );
    }
    if !source.contains("ProductCode=\"*\"") {
        return Err("wix/main.wxs must auto-generate ProductCode for major upgrades".to_owned());
    }
    if !source.contains("UpgradeCode=\"E5524B92-1EF5-4A69-B2D5-7A239CB5D3BF\"") {
        return Err("wix/main.wxs UpgradeCode must remain stable across releases".to_owned());
    }
    if !source.contains("<MajorUpgrade ") {
        return Err("wix/main.wxs must retain MajorUpgrade for in-place upgrades".to_owned());
    }
    if !source.contains("Guid=\"3D866AD6-D3A1-492A-A395-1B0AC1F873A2\"") {
        return Err("wix/main.wxs service component GUID must remain stable".to_owned());
    }
    Ok(())
}

fn require_windows_host() -> Result<(), String> {
    if cfg!(windows) {
        Ok(())
    } else {
        Err("this xtask command must be run on Windows".to_owned())
    }
}

fn run_checked(command: &mut Command, label: &str) -> Result<(), String> {
    let status =
        run_status(command).map_err(|error| format!("failed to run `{label}`: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`{label}` failed with status {status}"))
    }
}

fn run_status(command: &mut Command) -> std::io::Result<ExitStatus> {
    command.status()
}

fn output_checked(command: &mut Command, label: &str) -> Result<String, String> {
    let output = command
        .output()
        .map_err(|error| format!("failed to run `{label}`: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "`{label}` failed with status {}:\n{}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn print_help() {
    println!(
        "affix xtask\n\nCommands:\n  package-msi        Build release MSI with the native WiX CLI\n  package-msi-debug  Build diagnostic debug MSI with the native WiX CLI\n"
    );
}
