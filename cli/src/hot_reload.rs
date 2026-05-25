use notify_debouncer_mini::{new_debouncer, DebouncedEventKind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

pub struct HotReloadWatcher {
    _debouncer: notify_debouncer_mini::Debouncer<notify::RecommendedWatcher>,
    _watcher_thread: Option<std::thread::JoinHandle<()>>,
}

pub fn spawn_hot_reload_watcher(
    project_dir: &Path,
    reload_flag: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
) -> anyhow::Result<HotReloadWatcher> {
    let (tx, rx) = std::sync::mpsc::channel();

    let mut debouncer = new_debouncer(Duration::from_millis(500), tx)?;

    debouncer
        .watcher()
        .watch(project_dir, notify::RecursiveMode::Recursive)?;

    let project_dir = project_dir.to_path_buf();

    let watcher_thread = std::thread::spawn(move || {
        watcher_loop(&project_dir, rx, &reload_flag, &stop_flag);
    });

    Ok(HotReloadWatcher {
        _debouncer: debouncer,
        _watcher_thread: Some(watcher_thread),
    })
}

fn is_sol_event(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext == "sol")
        && !path
            .components()
            .any(|c| c.as_os_str() == "out" || c.as_os_str() == "node_modules" || c.as_os_str() == "cache")
}

fn watcher_loop(
    project_dir: &PathBuf,
    rx: std::sync::mpsc::Receiver<Result<Vec<notify_debouncer_mini::DebouncedEvent>, notify::Error>>,
    reload_flag: &AtomicBool,
    stop_flag: &AtomicBool,
) {
    loop {
        match rx.recv() {
            Ok(Ok(events)) => {
                let has_sol_change = events
                    .iter()
                    .any(|e| matches!(e.kind, DebouncedEventKind::Any) && is_sol_event(&e.path));

                if !has_sol_change {
                    continue;
                }

                // Already reloading or already stopped — skip
                if reload_flag.load(Ordering::Relaxed) || stop_flag.load(Ordering::Relaxed) {
                    continue;
                }

                info!("Solidity file change detected, recompiling...");

                let output = std::process::Command::new("forge")
                    .arg("build")
                    .arg("--build-info")
                    .arg("-o")
                    .arg("out")
                    .current_dir(project_dir)
                    .output();

                match output {
                    Ok(result) if result.status.success() => {
                        info!("Recompilation successful, triggering hot reload...");
                        reload_flag.store(true, Ordering::SeqCst);
                        stop_flag.store(true, Ordering::SeqCst);
                    }
                    Ok(result) => {
                        let stderr = String::from_utf8_lossy(&result.stderr);
                        warn!("Recompilation failed (will retry on next change):\n{}", stderr);
                    }
                    Err(e) => {
                        warn!("Failed to run forge build: {}", e);
                    }
                }
            }
            Ok(Err(e)) => {
                warn!("File watcher error: {:?}", e);
            }
            Err(_) => {
                // Channel closed, watcher is being dropped
                break;
            }
        }
    }
}
