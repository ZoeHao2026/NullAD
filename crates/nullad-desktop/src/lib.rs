//! NullAD desktop application.
//!
//! This crate is the only part of NullAD that knows what a window is. It reads
//! state from `nullad-core`, exposes it to the web UI through a small command
//! surface, and owns the tray icon. It contains no filtering logic, no rule
//! parsing, and no sockets of its own — which is what makes the UI replaceable.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![warn(missing_debug_implementations)]

pub mod commands;
pub mod logging;
pub mod tray;

use std::sync::{Arc, Mutex};

use nullad_core::{AppHandle, AppSettings, AppState};
use tauri::{Emitter, Manager};

/// Handles to the running interceptor tasks.
///
/// Task handles live here rather than in `nullad-core` so that the core stays
/// free of any async runtime, and so that "stop" is one place that aborts
/// everything it started.
#[derive(Debug, Default)]
pub struct RunningTasks {
    /// Abort handles for the spawned proxy and DNS tasks.
    handles: Mutex<Vec<tauri::async_runtime::JoinHandle<()>>>,
}

impl RunningTasks {
    /// Records a newly spawned task.
    pub fn push(&self, handle: tauri::async_runtime::JoinHandle<()>) {
        match self.handles.lock() {
            Ok(mut guard) => guard.push(handle),
            Err(poisoned) => poisoned.into_inner().push(handle),
        }
    }

    /// Aborts every recorded task and clears the list.
    ///
    /// Returns how many tasks were stopped.
    pub fn abort_all(&self) -> usize {
        let mut handles = match self.handles.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let count = handles.len();
        for handle in handles.drain(..) {
            handle.abort();
        }
        count
    }

    /// Number of tasks currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        match self.handles.lock() {
            Ok(guard) => guard.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// Returns `true` when nothing is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The application's managed state, as Tauri sees it.
#[derive(Debug)]
pub struct DesktopState {
    /// Shared application handle.
    pub app: AppHandle,
    /// Handles to the running interceptor tasks.
    pub tasks: RunningTasks,
}

impl DesktopState {
    /// Wraps an application handle for Tauri.
    #[must_use]
    pub fn new(app: AppHandle) -> Self {
        Self {
            app,
            tasks: RunningTasks::default(),
        }
    }
}

/// Builds and runs the desktop application, returning Tauri's exit code.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() -> i32 {
    let settings = AppSettings::load();
    logging::init(&settings.log_level);

    // WebView2 keeps its user-data folder under the local app data directory by
    // default. Allowing that path to be overridden makes the application usable
    // in restricted environments (and in this project's own sandboxed test
    // runs), where the default location is not writable.
    if let Ok(override_dir) = std::env::var("NULLAD_WEBVIEW_DATA_DIR") {
        std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", override_dir);
    }

    let state = Arc::new(AppState::bootstrap(settings));
    let app_handle = AppHandle::new(Arc::clone(&state));

    let result = tauri::Builder::default()
        .manage(DesktopState::new(app_handle.clone()))
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::recent_decisions,
            commands::list_lists,
            commands::list_rules,
            commands::check_url,
            commands::get_settings,
            commands::update_settings,
            commands::reload_lists,
            commands::set_list_enabled,
            commands::set_custom_rules,
            commands::get_custom_rules,
            commands::start_protection,
            commands::stop_protection,
            commands::pending_changes,
            commands::restore_system_changes,
            commands::clear_log,
            commands::benchmark,
            commands::platform_info,
        ])
        .setup(move |app| {
            // The tray is a nicety, not a requirement: a machine where the tray
            // cannot be created (locked-down desktops, some remote sessions)
            // should still get a working window and a working filter engine.
            // Failing the whole application because an icon was refused would be
            // a poor trade.
            if let Err(err) = tray::install(app.handle()) {
                tracing::warn!(
                    error = %err,
                    "the system tray could not be created; NullAD will run window-only"
                );
            }

            // Surface anything an earlier run left applied, so the user can put
            // their system back without hunting for it.
            let pending = nullad_core::AppSettings::pending_changes();
            if pending > 0 {
                tracing::warn!(
                    count = pending,
                    "the change journal holds unreverted system changes from an earlier run"
                );
            }

            // Push a status tick so the UI has data immediately rather than
            // waiting a full polling interval.
            let handle = app.handle().clone();
            let ticker_handle = app_handle.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    let status = ticker_handle.status();
                    if handle.emit("nullad://status", &status).is_err() {
                        // The window closed; stop pushing.
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                }
            });

            // Bring the main window up explicitly, so a build without a
            // pre-declared window still presents a usable application.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window hides it; NullAD keeps filtering in the tray,
            // which is the behaviour a user of a background blocker expects.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!());

    match result {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("NullAD failed to start: {err}");
            1
        }
    }
}
