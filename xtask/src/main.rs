use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

const CARGO_WIX_MAIN_REV: &str = "fde983c2e901970267e76b8fd68120fdd5457a57";

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
        "package-msi" => package_msi(),
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        other => Err(format!(
            "unknown xtask command `{other}`. Run `cargo xtask help`."
        )),
    }
}

fn package_msi() -> Result<(), String> {
    require_windows_host()?;
    ensure_modern_cargo_wix()?;
    ensure_wix_cli()?;

    run_checked(
        Command::new("cargo").args(["build", "--release", "--locked", "--package", "affix"]),
        "cargo build --release --locked --package affix",
    )?;

    let msi = default_msi_path();
    if let Some(parent) = msi.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create `{}`: {error}", parent.display()))?;
    }

    run_checked(
        Command::new("cargo")
            .arg("wix")
            .args(["--toolset", "modern"])
            .args(["--migrate", "none"])
            .arg("--no-build")
            .args(["--target-bin-dir", "target\\release"])
            .args(["--package", "affix"])
            .arg("--nocapture")
            .arg("--output")
            .arg(&msi),
        "cargo wix --toolset modern --migrate none --no-build --target-bin-dir target\\release --package affix",
    )?;

    println!("MSI written to {}", msi.display());
    Ok(())
}

fn ensure_modern_cargo_wix() -> Result<(), String> {
    let help = output_checked(
        Command::new("cargo").args(["wix", "--help"]),
        "cargo wix --help",
    )?;
    let init_help = output_checked(
        Command::new("cargo").args(["wix", "init", "--help"]),
        "cargo wix init --help",
    )?;

    if help.contains("--toolset <toolset>")
        && help.contains("--migrate <migrate>")
        && init_help.contains("--schema <schema>")
    {
        return Ok(());
    }

    Err(format!(
        "installed cargo-wix does not expose modern WiX support. Install the pinned upstream build with: cargo install --git https://github.com/volks73/cargo-wix --rev {CARGO_WIX_MAIN_REV} cargo-wix --force"
    ))
}

fn ensure_wix_cli() -> Result<(), String> {
    let version = output_checked(Command::new("wix").arg("--version"), "wix --version")?;
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

fn default_msi_path() -> PathBuf {
    Path::new("target")
        .join("wix")
        .join("affix-0.1.0-x86_64.msi")
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
        "affix xtask\n\nCommands:\n  package-msi       Build target\\wix\\affix-0.1.0-x86_64.msi with cargo-wix and modern WiX\n"
    );
    println!(
        "Pinned cargo-wix main install:\n  cargo install --git https://github.com/volks73/cargo-wix --rev {CARGO_WIX_MAIN_REV} cargo-wix --force"
    );
}
