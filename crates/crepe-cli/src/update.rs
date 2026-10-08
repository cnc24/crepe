//! Official stable archive updates. Download/verify/stage before atomic replacement.
use crepe_core::{Error, Result};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    process::Command,
};
const REPOSITORY: &str = "https://api.github.com/repos/cnc24/crepe/releases/latest";
const DOWNLOADS: &str = "https://github.com/cnc24/crepe/releases/download/";
const MAX_BYTES: u64 = 256 * 1024 * 1024;
fn error(message: impl std::fmt::Display) -> Error {
    Error::new("CREPE-UPD-001", message)
}
fn download(url: &str, destination: &Path) -> Result<()> {
    if url != REPOSITORY && !url.starts_with(DOWNLOADS) {
        return Err(error("unexpected release URL"));
    }
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            "15",
            "--max-time",
            "180",
            "--max-filesize",
            "268435456",
            "--user-agent",
            "crepe-updater",
            "--output",
        ])
        .arg(destination)
        .arg(url)
        .output()
        .map_err(|e| error(format!("curl is required for updates: {e}")))?;
    if !output.status.success() {
        return Err(error(format!(
            "download failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}
fn asset<'a>(release: &'a serde_json::Value, name: &str) -> Result<&'a serde_json::Value> {
    release["assets"]
        .as_array()
        .and_then(|a| a.iter().find(|v| v["name"] == name))
        .ok_or_else(|| error(format!("official release has no {name} asset")))
}
fn version(text: &str) -> Result<semver::Version> {
    semver::Version::parse(text.trim_start_matches('v')).map_err(error)
}
fn managed(path: &Path) -> bool {
    path.parent()
        .and_then(Path::parent)
        .is_some_and(|root| root.join(".crates2.json").is_file())
        || path.starts_with("/usr/bin")
        || path.starts_with("/bin")
        || path.components().any(|c| {
            c.as_os_str() == "Cellar" || c.as_os_str() == "target" || c.as_os_str() == ".cargo"
        })
}
pub fn run(check: bool, output: Option<&Path>) -> Result<()> {
    let temp = tempfile::tempdir().map_err(error)?;
    let metadata = temp.path().join("release.json");
    crate::report!("Checking the latest stable Crepe release...");
    download(REPOSITORY, &metadata)?;
    if fs::metadata(&metadata).map_err(error)?.len() > 2 * 1024 * 1024 {
        return Err(error("release metadata exceeds 2 MiB"));
    }
    let release: serde_json::Value =
        serde_json::from_slice(&fs::read(metadata).map_err(error)?).map_err(error)?;
    if release["draft"] != false || release["prerelease"] != false {
        return Err(error("expected a published stable release"));
    }
    let tag = release["tag_name"]
        .as_str()
        .ok_or_else(|| error("missing release version"))?;
    let latest = version(tag)?;
    let current = version(env!("CARGO_PKG_VERSION"))?;
    if !latest.pre.is_empty() {
        return Err(error("expected a stable release version"));
    }
    if latest <= current {
        crate::report!("Crepe {current}; latest stable release is {latest}. No update needed.");
        return Ok(());
    }
    crate::report!("Update available: {current} -> {latest}.");
    if check {
        return Ok(());
    }
    let executable = std::env::current_exe().map_err(error)?;
    if output.is_none() && managed(&executable) {
        return Err(error("This installation is managed by a package manager or Cargo. Update through that installer, or use crepe update --output NEW_PATH for a standalone binary."));
    }
    let platform = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "darwin-arm64",
        ("linux", "x86_64") => "linux-x86_64",
        _ => return Err(error("no official update archive for this OS/architecture")),
    };
    let name = format!("crepe-{latest}-{platform}.tar.gz");
    let archive_asset = asset(&release, &name)?;
    let checksum_name = format!("{name}.sha256");
    let checksum_asset = asset(&release, &checksum_name)?;
    let archive = temp.path().join(&name);
    let checksum = temp.path().join(&checksum_name);
    for (item, file) in [(archive_asset, &archive), (checksum_asset, &checksum)] {
        let url = item["browser_download_url"]
            .as_str()
            .ok_or_else(|| error("missing asset URL"))?;
        if !url.starts_with(&format!("{DOWNLOADS}{tag}/")) {
            return Err(error("asset does not belong to the selected release"));
        }
        download(url, file)?;
    }
    let checksum_text = fs::read_to_string(checksum).map_err(error)?;
    let parts: Vec<_> = checksum_text.split_whitespace().collect();
    if parts.len() != 2 || parts[1].trim_start_matches('*') != name {
        return Err(error("invalid checksum manifest"));
    }
    let digest = parts[0];
    if archive_asset["digest"].as_str() != Some(format!("sha256:{digest}").as_str()) {
        return Err(error(
            "GitHub asset digest disagrees with checksum manifest",
        ));
    }
    let destination = output.unwrap_or(&executable);
    install(
        &archive,
        digest,
        destination,
        output.is_none(),
        Some(&latest.to_string()),
    )?;
    crate::report!(
        "Installed Crepe {latest} at {}. Restart any running Crepe sessions to use it.",
        destination.display()
    );
    Ok(())
}
fn install(
    archive: &Path,
    digest: &str,
    destination: &Path,
    replace: bool,
    expected_version: Option<&str>,
) -> Result<()> {
    let mut file = fs::File::open(archive).map_err(error)?;
    if file.metadata().map_err(error)?.len() > MAX_BYTES {
        return Err(error("archive too large"));
    }
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(error)?;
    if format!("{:x}", hasher.finalize()) != digest {
        return Err(error("SHA-256 mismatch; installation unchanged"));
    }
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut stage = tempfile::NamedTempFile::new_in(parent).map_err(error)?;
    let gzip = flate2::read::GzDecoder::new(fs::File::open(archive).map_err(error)?);
    let mut tar = tar::Archive::new(gzip.take(MAX_BYTES + 1));
    let mut found = false;
    for entry in tar.entries().map_err(error)? {
        let entry = entry.map_err(error)?;
        if entry.path().map_err(error)?.as_ref() != Path::new("crepe") {
            continue;
        }
        if found
            || !entry.header().entry_type().is_file()
            || entry.size() == 0
            || entry.size() > MAX_BYTES
        {
            return Err(error("invalid executable archive entry"));
        }
        std::io::copy(&mut entry.take(MAX_BYTES + 1), &mut stage).map_err(error)?;
        found = true;
    }
    if !found {
        return Err(error("archive contains no crepe executable"));
    }
    stage.flush().map_err(error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        stage
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))
            .map_err(error)?;
    }
    stage.as_file().sync_all().map_err(error)?;
    let stage = stage.into_temp_path();
    if let Some(version) = expected_version {
        let output = Command::new(&stage)
            .arg("--version")
            .output()
            .map_err(error)?;
        if !output.status.success()
            || String::from_utf8_lossy(&output.stdout).trim() != format!("crepe {version}")
        {
            return Err(error(
                "downloaded binary cannot run or has an unexpected version; installation unchanged",
            ));
        }
    }
    if replace {
        stage.persist(destination).map_err(error)?;
    } else {
        stage.persist_noclobber(destination).map_err(error)?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn versions_and_managed_installs() {
        assert!(version("v1.10.0").unwrap() > version("v1.9.0").unwrap());
        assert!(version("../../evil").is_err());
        assert!(managed(Path::new("/usr/bin/crepe")));
        assert!(managed(Path::new("/project/target/release/crepe")));
        assert!(managed(Path::new("/home/user/.cargo/bin/crepe")));
        assert!(!managed(Path::new("/home/user/.local/bin/crepe")));
    }
    #[test]
    fn verified_atomic_install_and_failures_preserve_old_binary() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("release.tar.gz");
        let gz = flate2::write::GzEncoder::new(
            fs::File::create(&archive).unwrap(),
            flate2::Compression::default(),
        );
        let mut tar = tar::Builder::new(gz);
        let mut header = tar::Header::new_gnu();
        header.set_size(3);
        header.set_mode(0o755);
        header.set_cksum();
        tar.append_data(&mut header, "crepe", &b"new"[..]).unwrap();
        tar.into_inner().unwrap().finish().unwrap();
        let digest = format!("{:x}", Sha256::digest(fs::read(&archive).unwrap()));
        let target = root.path().join("crepe");
        fs::write(&target, b"old").unwrap();
        assert!(install(&archive, "bad", &target, true, None).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert!(install(&archive, &digest, &target, false, None).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"old");
        install(&archive, &digest, &target, true, None).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
    }
}
