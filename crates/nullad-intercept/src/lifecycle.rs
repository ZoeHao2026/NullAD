//! Shared shutdown handling for owned interception tasks.

use std::io;

use tokio::sync::watch;
use tokio::task::JoinSet;

/// A closed sender is also a stop request: its owner can no longer supervise us.
pub(crate) async fn stopped(stop: &mut watch::Receiver<bool>) {
    loop {
        if *stop.borrow_and_update() || stop.changed().await.is_err() {
            return;
        }
    }
}

/// Wait for cancellation to finish before the listener reports that it stopped.
pub(crate) async fn stop_children(children: &mut JoinSet<io::Result<()>>) {
    children.abort_all();
    while children.join_next().await.is_some() {}
}
