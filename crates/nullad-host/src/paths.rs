//! Filesystem locations NullAD uses.

use std::path::PathBuf;

use crate::HostError;

/// Result type for this module.
type Result<T> = std::result::Result<T, HostError>;

/// Application directory name used under the user's config/data locations.
pub const APP_DIR: &str = "nullad";

/// Validates the opt-in root without changing the process environment.
fn validate_home(value: &str) -> Result<PathBuf> {
    if value.trim().is_empty() || !std::path::Path::new(value).is_absolute() {
        return Err(HostError::Config(
            "NULLAD_HOME must be a non-empty absolute path".into(),
        ));
    }
    Ok(PathBuf::from(value))
}

fn isolated_dir(child: &str) -> Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os("NULLAD_HOME") else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .ok_or_else(|| HostError::Config("NULLAD_HOME is not a valid Unicode path".into()))?;
    let dir = validate_home(value)?.join(child);
    std::fs::create_dir_all(&dir)
        .map_err(|e| HostError::Config(format!("{}: {e}", dir.display())))?;
    Ok(Some(dir))
}

/// Returns the per-user configuration directory, creating it if needed.
pub fn config_dir() -> Result<PathBuf> {
    if let Some(dir) = isolated_dir("config")? {
        return Ok(dir);
    }
    let base = dirs::config_dir()
        .ok_or_else(|| HostError::Config("no per-user configuration directory".into()))?;
    let dir = base.join(APP_DIR);
    std::fs::create_dir_all(&dir)
        .map_err(|e| HostError::Config(format!("{}: {e}", dir.display())))?;
    Ok(dir)
}

/// Returns the per-user data directory, creating it if needed.
pub fn data_dir() -> Result<PathBuf> {
    if let Some(dir) = isolated_dir("data")? {
        return Ok(dir);
    }
    let base =
        dirs::data_dir().ok_or_else(|| HostError::Config("no per-user data directory".into()))?;
    let dir = base.join(APP_DIR);
    std::fs::create_dir_all(&dir)
        .map_err(|e| HostError::Config(format!("{}: {e}", dir.display())))?;
    Ok(dir)
}

/// Returns the per-user log directory, creating it if needed.
pub fn log_dir() -> Result<PathBuf> {
    if let Some(dir) = isolated_dir("logs")? {
        return Ok(dir);
    }
    let base = dirs::data_local_dir()
        .ok_or_else(|| HostError::Config("no local data directory".into()))?;
    let dir = base.join(APP_DIR).join("logs");
    std::fs::create_dir_all(&dir)
        .map_err(|e| HostError::Config(format!("{}: {e}", dir.display())))?;
    Ok(dir)
}

/// Path of the settings file.
pub fn settings_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("settings.json"))
}

/// Path of the change journal file.
pub fn journal_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("change-journal.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolated_home_rejects_empty_and_relative_paths() {
        for path in ["", " ", "nullad-qa", "./nullad"] {
            assert!(validate_home(path).is_err());
        }
        let absolute = std::env::current_dir().unwrap().join("isolated-home");
        assert_eq!(validate_home(absolute.to_str().unwrap()).unwrap(), absolute);
    }
}
