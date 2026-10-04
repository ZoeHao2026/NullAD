use nullad_core::{AppHandle, AppSettings, AppState};
use nullad_desktop_lib::{runtime, DesktopState};
use std::net::TcpListener;
use std::sync::Arc;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// One isolated process: never apply a real system setting in lifecycle tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn serialized_desktop_lifecycle_rolls_back_and_releases_ports() {
    let home = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join(format!("lifecycle-home-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    std::env::set_var("NULLAD_HOME", &home);
    let settings = AppSettings {
        lists: Vec::new(),
        proxy_port: free_port(),
        dns_enabled: true,
        dns_port: free_port(),
        intercept_system_proxy: false,
        ..AppSettings::default()
    };
    let state = Arc::new(DesktopState::new(AppHandle::new(Arc::new(
        AppState::bootstrap(settings.clone()),
    ))));
    for _ in 0..20 {
        runtime::start(&state).await.unwrap();
        runtime::start(&state).await.unwrap(); // Idempotent start must not toggle.
        assert!(state.app.status().protection.is_active());
        assert_eq!(state.app.status().proxy_port, Some(settings.proxy_port));
        runtime::stop(&state).await.unwrap();
        runtime::stop(&state).await.unwrap();
        let proxy = TcpListener::bind(("127.0.0.1", settings.proxy_port)).unwrap();
        let dns = TcpListener::bind(("127.0.0.1", settings.dns_port)).unwrap();
        drop((proxy, dns));
    }
    let mut operations = tokio::task::JoinSet::new();
    for n in 0..40 {
        let state = state.clone();
        operations.spawn(async move {
            if n % 2 == 0 {
                runtime::start(&state).await
            } else {
                runtime::stop(&state).await
            }
        });
    }
    while let Some(result) = operations.join_next().await {
        result.unwrap().unwrap();
    }
    runtime::stop(&state).await.unwrap();
    let proxy = TcpListener::bind(("127.0.0.1", settings.proxy_port)).unwrap();
    let dns = TcpListener::bind(("127.0.0.1", settings.dns_port)).unwrap();
    drop((proxy, dns));
    // Occupied second listener must release the first binding transactionally.
    let occupied = TcpListener::bind(("127.0.0.1", settings.dns_port)).unwrap();
    assert!(runtime::start(&state).await.is_err());
    assert_eq!(state.app.status().proxy_port, None);
    assert!(state.app.status().last_error.is_some());
    assert!(!state.app.status().protection.is_active());
    let released = TcpListener::bind(("127.0.0.1", settings.proxy_port)).unwrap();
    drop((occupied, released));
    std::env::remove_var("NULLAD_HOME");
    std::fs::remove_dir_all(home).unwrap();
}
