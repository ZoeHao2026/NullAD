//! Native tray operations use the same serialized lifecycle as IPC.
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Runtime};

fn menu<R: Runtime>(app: &AppHandle<R>, language: &str) -> tauri::Result<Menu<R>> {
    let labels = if language == "en" {
        [
            "Show NullAD",
            "Start protection",
            "Stop protection",
            "Reload filter lists",
            "Quit NullAD",
        ]
    } else {
        [
            "显示 NullAD",
            "启动防护",
            "停止防护",
            "更新规则",
            "退出 NullAD",
        ]
    };
    let show = MenuItem::with_id(app, "show", labels[0], true, None::<&str>)?;
    let start = MenuItem::with_id(app, "start", labels[1], true, None::<&str>)?;
    let stop = MenuItem::with_id(app, "stop", labels[2], true, None::<&str>)?;
    let reload = MenuItem::with_id(app, "reload", labels[3], true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", labels[4], true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    Menu::with_items(
        app,
        &[&show, &separator, &start, &stop, &reload, &separator, &quit],
    )
}

pub fn set_language<R: Runtime>(app: &AppHandle<R>, language: &str) -> tauri::Result<()> {
    if let Some(tray) = app.tray_by_id("main-tray") {
        tray.set_menu(Some(menu(app, language)?))?;
    }
    Ok(())
}

pub fn install<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let language = app
        .state::<crate::DesktopState>()
        .app
        .state()
        .settings()
        .ui_language;
    let icon = app
        .default_window_icon()
        .cloned()
        .ok_or_else(|| tauri::Error::AssetNotFound("tray icon".into()))?;
    TrayIconBuilder::with_id("main-tray")
        .icon(icon)
        .tooltip("NullAD")
        .menu(&menu(app, &language)?)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => show_window(app),
            "start" | "stop" => {
                let start = event.id().as_ref() == "start";
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let state = app.state::<crate::DesktopState>();
                    let result = if start {
                        crate::runtime::start(&state).await
                    } else {
                        crate::runtime::stop(&state).await
                    };
                    if let Err(error) = result {
                        tracing::error!(%error, "tray lifecycle operation failed");
                    }
                });
            }
            "reload" => {
                let app = app.state::<crate::DesktopState>().app.clone();
                tauri::async_runtime::spawn_blocking(move || app.reload());
            }
            "quit" => crate::request_exit(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
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

fn show_window<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}
