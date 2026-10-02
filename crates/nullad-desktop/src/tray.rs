//! The system tray icon and its menu.
//!
//! The tray is how a background blocker stays usable: the window can be closed
//! and filtering continues, with the tray icon as the visible state indicator
//! and the only way back to the window.

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Runtime};

/// Menu item identifiers, shared between construction and event handling.
mod ids {
    pub const SHOW: &str = "show";
    pub const START: &str = "start";
    pub const STOP: &str = "stop";
    pub const RELOAD: &str = "reload";
    pub const QUIT: &str = "quit";
}

/// Installs the tray icon and its menu.
///
/// Returns an error only if Tauri rejects the icon or menu, which would indicate
/// a packaging problem worth surfacing rather than ignoring.
pub fn install<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, ids::SHOW, "Show NullAD", true, None::<&str>)?;
    let start = MenuItem::with_id(app, ids::START, "Start protection", true, None::<&str>)?;
    let stop = MenuItem::with_id(app, ids::STOP, "Stop protection", true, None::<&str>)?;
    let reload = MenuItem::with_id(app, ids::RELOAD, "Reload filter lists", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, ids::QUIT, "Quit NullAD", true, None::<&str>)?;

    let menu = Menu::with_items(
        app,
        &[&show, &separator, &start, &stop, &reload, &separator, &quit],
    )?;

    TrayIconBuilder::with_id("main-tray")
        .icon(app.default_window_icon().cloned().unwrap_or_else(|| {
            // A missing default icon is not fatal; the tray simply has no icon
            // until one is packaged.
            tauri::image::Image::new_owned(Vec::new(), 0, 0)
        }))
        .tooltip("NullAD")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            ids::SHOW => show_window(app),
            ids::START => {
                // The command surface is the single place that starts servers,
                // so the tray triggers the same path rather than duplicating it
                // by emitting an event the UI may not be listening for yet.
                let _ = app.emit_to_status("nullad://request-start");
            }
            ids::STOP => {
                let _ = app.emit_to_status("nullad://request-stop");
            }
            ids::RELOAD => {
                let _ = app.emit_to_status("nullad://request-reload");
            }
            ids::QUIT => {
                // Restore system changes before exiting, so quitting from the
                // tray cannot strand the machine's proxy settings.
                if let Some(state) = app.try_state::<crate::DesktopState>() {
                    state.app.runtime().restore_system_changes();
                }
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            // Left click restores the window, which is what every other tray
            // application does and therefore what users expect.
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_window(tray.app_handle());
            }
        })
        .build(app)?;

    Ok(())
}

/// Shows and focuses the main window, creating nothing if it is missing.
fn show_window<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Emits an event to the main window, if it exists.
///
/// A small helper so the tray code stays readable; the event is dropped when
/// the window is not open, which is acceptable because the window re-reads full
/// state on load rather than relying on events alone.
trait EmitToStatus<R: Runtime> {
    fn emit_to_status(&self, event: &str) -> tauri::Result<()>;
}

impl<R: Runtime> EmitToStatus<R> for AppHandle<R> {
    fn emit_to_status(&self, event: &str) -> tauri::Result<()> {
        use tauri::Emitter;
        if let Some(window) = self.get_webview_window("main") {
            window.emit(event, ())?;
        }
        Ok(())
    }
}
