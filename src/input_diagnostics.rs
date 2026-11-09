//! Experimental, opt-in KMDF event diagnostics. No driver/protocol changes.
//! Hot-path calls only enqueue to a bounded channel; disk I/O stays on a worker.
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CHANNEL_CAPACITY: usize = 8192;
const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
const KEEP_FILES: usize = 5;
const BEFORE: Duration = Duration::from_secs(10);
const AFTER: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Off,
    Anomalies,
    Full,
}

impl std::str::FromStr for Mode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "off" => Ok(Self::Off),
            "anomalies" => Ok(Self::Anomalies),
            "full" => Ok(Self::Full),
            _ => Err(format!("invalid --input-diag value {s:?}; expected off|anomalies|full")),
        }
    }
}

struct Event {
    when: Instant,
    line: String,
    trigger: bool,
}

struct Diagnostics {
    start: Instant,
    next_seq: AtomicU64,
    dropped: AtomicU64,
    disabled: Arc<AtomicBool>,
    tx: SyncSender<Event>,
}

static STATE: OnceLock<Diagnostics> = OnceLock::new();

fn default_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("TEMP"))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("Kanata")
        .join("diagnostics")
}

/// Called once, before starting Kanata input threads.
/// Failure is reported by the caller and leaves diagnostics disabled.
pub fn init(mode: Mode, directory: Option<PathBuf>) -> io::Result<Option<PathBuf>> {
    if mode == Mode::Off {
        return Ok(None);
    }
    if STATE.get().is_some() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "diagnostics already initialized"));
    }
    let dir = directory.unwrap_or_else(default_dir);
    fs::create_dir_all(&dir)?;
    // Verify path permissions before enabling high-frequency instrumentation.
    let mut writer = RotatingWriter::open(&dir)?;
    writer.write("START input diagnostics; timestamps are milliseconds since process diagnostic start\n")?;
    writer.flush()?;
    let (tx, rx) = mpsc::sync_channel::<Event>(CHANNEL_CAPACITY);
    let disabled = Arc::new(AtomicBool::new(false));
    let worker_disabled = disabled.clone();
    std::thread::Builder::new()
        .name("kanata-input-diagnostics".into())
        .spawn(move || {
            let mut history: VecDeque<Event> = VecDeque::new();
            let mut active_until: Option<Instant> = None;
            let mut was_active = false;
            while let Ok(ev) = rx.recv() {
                if mode == Mode::Full {
                    if writer.write(&ev.line).is_err() {
                        log::error!("input diagnostics: cannot write log; stopping diagnostic writer");
                        worker_disabled.store(true, Ordering::Relaxed);
                        break;
                    }
                } else {
                    if let Some(end) = active_until {
                        if ev.when <= end {
                            if writer.write(&ev.line).is_err() {
                                log::error!("input diagnostics: cannot write log; stopping diagnostic writer");
                                worker_disabled.store(true, Ordering::Relaxed);
                                break;
                            }
                        } else {
                            active_until = None;
                            was_active = false;
                        }
                    }
                    if ev.trigger {
                        if !was_active {
                            let since = ev.when.checked_sub(BEFORE).unwrap_or(ev.when);
                            for past in history.iter().filter(|p| p.when >= since && p.when <= ev.when) {
                                if writer.write(&past.line).is_err() {
                                    log::error!("input diagnostics: cannot write history; stopping diagnostic writer");
                                    worker_disabled.store(true, Ordering::Relaxed);
                                    return;
                                }
                            }
                        }
                        active_until = Some(ev.when + AFTER);
                        if !was_active && writer.write(&ev.line).is_err() {
                            log::error!("input diagnostics: cannot write trigger; stopping diagnostic writer");
                            worker_disabled.store(true, Ordering::Relaxed);
                            break;
                        }
                        was_active = true;
                    }
                    history.push_back(ev);
                    let cutoff = history.back().and_then(|e| e.when.checked_sub(BEFORE));
                    if let Some(cutoff) = cutoff {
                        while history.front().is_some_and(|e| e.when < cutoff) {
                            history.pop_front();
                        }
                    }
                    while history.len() > CHANNEL_CAPACITY {
                        history.pop_front();
                    }
                    continue;
                }
            }
            let _ = writer.flush();
        })?;
    STATE.set(Diagnostics {
        start: Instant::now(),
        next_seq: AtomicU64::new(1),
        dropped: AtomicU64::new(0),
        disabled,
        tx,
    }).map_err(|_| io::Error::new(io::ErrorKind::AlreadyExists, "diagnostics already initialized"))?;
    Ok(Some(dir))
}

pub fn enabled() -> bool {
    STATE.get().is_some_and(|s| !s.disabled.load(Ordering::Relaxed))
}

pub fn next_seq() -> u64 {
    STATE.get().map_or(0, |s| s.next_seq.fetch_add(1, Ordering::Relaxed))
}

/// Records never block keyboard processing. 'trigger' marks a suspect, not a proven defect.
pub fn record(stage: &str, detail: impl std::fmt::Display, trigger: bool) {
    let Some(s) = STATE.get() else { return; };
    if s.disabled.load(Ordering::Relaxed) { return; }
    let now = Instant::now();
    let line = format!("{:012.3} {:<15} {}\n", now.duration_since(s.start).as_secs_f64()*1000.0, stage, detail);
    let dropped = s.dropped.swap(0, Ordering::Relaxed);
    if dropped != 0 {
        let note = Event { when: now, line: format!("DIAGNOSTIC_LOSS records={dropped}\n"), trigger: true };
        if s.tx.try_send(note).is_err() {
            s.dropped.fetch_add(dropped, Ordering::Relaxed);
        }
    }
    match s.tx.try_send(Event { when: now, line, trigger }) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
            s.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct RotatingWriter {
    dir: PathBuf,
    stem: String,
    part: usize,
    bytes: u64,
    file: BufWriter<File>,
}

impl RotatingWriter {
    fn open(dir: &Path) -> io::Result<Self> {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)
            .unwrap_or_default().as_millis();
        let stem = format!("input-diag-{stamp}-{}", std::process::id());
        let file = OpenOptions::new().write(true).create_new(true).open(dir.join(format!("{stem}-0.log")))?;
        Self::prune(dir);
        Ok(Self { dir: dir.into(), stem, part: 0, bytes: 0, file: BufWriter::new(file) })
    }

    fn write(&mut self, line: &str) -> io::Result<()> {
        if self.bytes + line.len() as u64 > MAX_LOG_BYTES {
            self.file.flush()?;
            self.part += 1;
            let file = OpenOptions::new().write(true).create_new(true)
                .open(self.dir.join(format!("{}-{}.log", self.stem, self.part)))?;
            self.file = BufWriter::new(file);
            self.bytes = 0;
            Self::prune(&self.dir);
        }
        self.file.write_all(line.as_bytes())?;
        self.bytes += line.len() as u64;
        self.file.flush() // survive process failures; writer thread only
    }

    fn flush(&mut self) -> io::Result<()> { self.file.flush() }

    fn prune(dir: &Path) {
        let Ok(entries) = fs::read_dir(dir) else { return; };
        let mut files: Vec<_> = entries.flatten()
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with("input-diag-") && name.ends_with(".log")
            })
            .map(|entry| entry.path())
            .collect();
        files.sort_by_key(|path| {
            fs::metadata(path).and_then(|m| m.modified()).unwrap_or(UNIX_EPOCH)
        }); // keep the five most recently modified diagnostic logs
        let to_delete = files.len().saturating_sub(KEEP_FILES);
        for file in files.into_iter().take(to_delete) {
            let _ = fs::remove_file(file);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_modes() {
        assert_eq!("off".parse::<Mode>().unwrap(), Mode::Off);
        assert_eq!("anomalies".parse::<Mode>().unwrap(), Mode::Anomalies);
        assert_eq!("full".parse::<Mode>().unwrap(), Mode::Full);
        assert!("invalid".parse::<Mode>().is_err());
    }
}
