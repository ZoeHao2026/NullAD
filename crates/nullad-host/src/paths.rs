//! Filesystem locations NullAD uses.

use std::path::PathBuf;

use crate::HostError;

/// Result type for this module.
type Result<T> = std::result::Result<T, HostError>;

/// Application directory name used under the user's config/data locations.
pub const APP_DIR: &str = "nullad";

/// Returns the per-user configuration directory, creating it if needed.
pub fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir()
        .ok_or_else(|| HostError::Config("no per-user configuration directory".into()))?;
    let dir = base.join(APP_DIR);
    std::fs::create_dir_all(&dir)
        .map_err(|e| HostError::Config(format!("{}: {e}", dir.display())))?;
    Ok(dir)
}

/// Returns the per-user data directory, creating it if needed.
pub fn data_dir() -> Result<PathBuf> {
    let base =
        dirs::data_dir().ok_or_else(|| HostError::Config("no per-user data directory".into()))?;
    let dir = base.join(APP_DIR);
    std::fs::create_dir_all(&dir)
        .map_err(|e| HostError::Config(format!("{}: {e}", dir.display())))?;
    Ok(dir)
}

/// Returns the per-user log directory, creating it if needed.
pub fn log_dir() -> Result<PathBuf> {
    let base =
        dirs::data_local_dir().ok_or_else(|| HostError::Config("no local data directory".into()))?;
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
