//! Windows KMDF kernel-filter backend for reading/writing input events.
//!
//! Communicates with `kanata-kbdflt.sys` via two IOCTLs:
//!   - `IOCTL_KANATA_READ_EVENTS`   - blocking read of suppressed key events
//!   - `IOCTL_KANATA_INJECT_EVENTS` - inject remapped key events back through kbdclass
//!
//! Mouse events are handled via `SendInput` (the driver is keyboard-only).
//!
//! The driver raw PDO is opened by enumerating GUID_DEVINTERFACE_KBFILTER.
//!
//! Selected by `--features kmdf_driver`.
//!
//! NOTE: This backend is intended as a modern, high-performance replacement for the
//! Interception driver. It reuses the same configuration parameters (e.g. HWID filtering)
//! to ensure a seamless transition for users.

use std::collections::{HashSet, VecDeque};
use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, SP_DEVICE_INTERFACE_DATA,
    SP_DEVICE_INTERFACE_DETAIL_DATA_W, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInterfaces,
    SetupDiGetClassDevsW, SetupDiGetDeviceInterfaceDetailW,
};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_IO_PENDING, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::{
    CancelIoEx, DeviceIoControl, GetOverlappedResult, OVERLAPPED,
};
use windows_sys::Win32::System::Threading::CreateEventW;

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::sync::{Arc, Weak};

use crate::kanata::CalculatedMouseMove;
use crate::oskbd::KeyValue;
use crate::oskbd::osc_to_u16;
use crate::oskbd::u16_to_osc;
use kanata_parser::cfg::HWID_ARR_SZ;
use kanata_parser::custom_action::*;
use kanata_parser::keys::*;

// ---------------------------------------------------------------------------
// IOCTL constants — mirror kanata_shared.h
// ---------------------------------------------------------------------------

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

const KANATA_IOCTL_BASE: u32 = 0x8000;
const METHOD_BUFFERED: u32 = 0;
const FILE_READ_DATA_ACC: u32 = 0x0001;
const FILE_WRITE_DATA_ACC: u32 = 0x0002;

const IOCTL_KANATA_READ_EVENTS: u32 = ctl_code(
    KANATA_IOCTL_BASE,
    0x800,
    METHOD_BUFFERED,
    FILE_READ_DATA_ACC,
);
const IOCTL_KANATA_INJECT_EVENTS: u32 = ctl_code(
    KANATA_IOCTL_BASE,
    0x801,
    METHOD_BUFFERED,
    FILE_WRITE_DATA_ACC,
);

const KANATA_KEY_MAKE: u16 = 0x0000;
const KANATA_KEY_BREAK: u16 = 0x0001;
const KANATA_KEY_E0: u16 = 0x0002;
const KANATA_KEY_E1: u16 = 0x0004;

// ---------------------------------------------------------------------------
// Wire-format (8 bytes packed — matches _KANATA_KEY_EVENT in the driver)
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
struct KanataWireEvent {
    make_code: u16,
    flags: u16,
    timestamp: u32,
}

// ---------------------------------------------------------------------------
// InputEvent — what the Kanata engine sees
// ---------------------------------------------------------------------------

/// Key event received from the KMDF filter driver.
#[derive(Debug, Clone, Copy)]
pub struct InputEvent {
    pub make_code: u16,
    pub flags: u16,
}

impl std::fmt::Display for InputEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl InputEvent {
    pub fn from_oscode(code: OsCode, val: KeyValue) -> Result<Self, io::Error> {
        let sc = osc_to_u16(code).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("no scancode for {code:?}"),
            )
        })?;

        let mut flags: u16 = match val {
            KeyValue::Press | KeyValue::Repeat => KANATA_KEY_MAKE,
            KeyValue::Release => KANATA_KEY_BREAK,
            KeyValue::Tap | KeyValue::WakeUp => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid KeyValue for injection: {val:?}"),
                ));
            }
        };

        match sc >> 8 {
            0xE0 => flags |= KANATA_KEY_E0,
            0xE1 => flags |= KANATA_KEY_E1,
            _ => {}
        }

        Ok(Self {
            make_code: sc & 0x00FF,
            flags,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UnknownInputEvent {
    pub make_code: u16,
    pub normalized_make_code: u16,
    pub flags: u16,
    pub full_scancode: u16,
}

impl UnknownInputEvent {
    pub fn is_fake_shift(&self) -> bool {
        // E0 2A and E0 36 are "fake shifts" emitted by Windows for extended keys.
        self.full_scancode == 0xE02A || self.full_scancode == 0xE036
    }
}

impl TryFrom<InputEvent> for crate::oskbd::KeyEvent {
    type Error = UnknownInputEvent;

    fn try_from(ev: InputEvent) -> Result<Self, UnknownInputEvent> {
        use crate::oskbd::{KeyEvent, KeyValue};

        let is_break = (ev.flags & KANATA_KEY_BREAK) != 0;
        let is_e0 = (ev.flags & KANATA_KEY_E0) != 0;
        let is_e1 = (ev.flags & KANATA_KEY_E1) != 0;

        let full_sc: u16 = if is_e0 {
            0xE000 | ev.make_code
        } else if is_e1 {
            0xE100 | ev.make_code
        } else {
            ev.make_code
        };

        let osc = u16_to_osc(full_sc).ok_or_else(|| UnknownInputEvent {
            make_code: ev.make_code,
            normalized_make_code: ev.make_code,
            flags: ev.flags,
            full_scancode: full_sc,
        })?;

        Ok(KeyEvent {
            code: osc,
            value: if is_break {
                KeyValue::Release
            } else {
                KeyValue::Press
            },
        })
    }
}

impl TryFrom<crate::oskbd::KeyEvent> for InputEvent {
    type Error = io::Error;

    fn try_from(ev: crate::oskbd::KeyEvent) -> Result<Self, Self::Error> {
        Self::from_oscode(ev.code, ev.value)
    }
}

// ---------------------------------------------------------------------------
// Driver I/O
// ---------------------------------------------------------------------------

const GUID_DEVINTERFACE_KBFILTER: windows_sys::core::GUID = windows_sys::core::GUID {
    data1: 0x3fb7299d,
    data2: 0x6847,
    data3: 0x4490,
    data4: [0xb0, 0xc9, 0x99, 0xe0, 0x98, 0x6a, 0xb8, 0x86],
};

fn open_driver_path(path: *const u16) -> anyhow::Result<OwnedHandle> {
    let handle = unsafe {
        CreateFileW(
            path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        anyhow::bail!("{}", io::Error::last_os_error());
    }

    // SAFETY: handle is valid and we now own it.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as _) })
}

fn path_to_string(path: &[u16]) -> String {
    let len = path.iter().position(|&c| c == 0).unwrap_or(path.len());
    String::from_utf16_lossy(&path[..len])
}

fn path_to_hwid_bytes(path: &[u16]) -> [u8; HWID_ARR_SZ] {
    let mut out = [0u8; HWID_ARR_SZ];
    let mut o = 0usize;

    for &w in path.iter().take_while(|&&w| w != 0) {
        if o + 1 >= HWID_ARR_SZ {
            break;
        }
        let bytes = w.to_le_bytes();
        out[o] = bytes[0];
        out[o + 1] = bytes[1];
        o += 2;
    }

    out
}

fn hwid_bytes_to_lossy_string(bytes: &[u8; HWID_ARR_SZ]) -> String {
    // KMDF interface paths are stored here as UTF-16LE bytes by path_to_hwid_bytes().
    // Do not search for the first zero *byte*: ASCII UTF-16LE has a zero high byte
    // after every character, so that would truncate "\\?\..." to just "\\".
    let looks_utf16le_ascii = bytes.len() >= 4 && bytes[1] == 0 && bytes[3] == 0;

    if looks_utf16le_ascii {
        let words = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .take_while(|&w| w != 0)
            .collect::<Vec<_>>();

        return String::from_utf16_lossy(&words);
    }

    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

fn hwid_entry_matches(candidate: &[u8; HWID_ARR_SZ], configured: &[u8; HWID_ARR_SZ]) -> bool {
    if candidate == configured {
        return true;
    }

    let candidate_s = hwid_bytes_to_lossy_string(candidate).to_ascii_uppercase();
    let configured_s = hwid_bytes_to_lossy_string(configured).to_ascii_uppercase();

    !configured_s.is_empty()
        && (candidate_s.contains(&configured_s) || configured_s.contains(&candidate_s))
}

fn kmdf_interface_allowed(
    hwid: &[u8; HWID_ARR_SZ],
    allowed_hwids: &Option<Vec<[u8; HWID_ARR_SZ]>>,
    excluded_hwids: &Option<Vec<[u8; HWID_ARR_SZ]>>,
) -> bool {
    match (allowed_hwids, excluded_hwids) {
        (None, None) => true,
        (Some(allowed), None) => {
            let allowed: &Vec<[u8; HWID_ARR_SZ]> = allowed;
            allowed
                .iter()
                .any(|configured| hwid_entry_matches(hwid, configured))
        }
        (None, Some(excluded)) => {
            let excluded: &Vec<[u8; HWID_ARR_SZ]> = excluded;
            !excluded
                .iter()
                .any(|configured| hwid_entry_matches(hwid, configured))
        }
        (Some(_), Some(_)) => {
            log::warn!(
                "kanata-kbdflt: both include and exclude HWID filters are set; rejecting interface"
            );
            false
        }
    }
}

fn enumerate_driver_interface_paths() -> anyhow::Result<Vec<Vec<u16>>> {
    let dev_info = unsafe {
        SetupDiGetClassDevsW(
            &GUID_DEVINTERFACE_KBFILTER,
            ptr::null(),
            0,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
    };
    if dev_info == INVALID_HANDLE_VALUE {
        anyhow::bail!(
            "SetupDiGetClassDevsW(GUID_DEVINTERFACE_KBFILTER) failed: {}",
            io::Error::last_os_error()
        );
    }

    let mut paths = Vec::new();
    let mut index = 0;

    loop {
        let mut iface = SP_DEVICE_INTERFACE_DATA {
            cbSize: size_of::<SP_DEVICE_INTERFACE_DATA>() as u32,
            ..unsafe { std::mem::zeroed() }
        };

        let ok = unsafe {
            SetupDiEnumDeviceInterfaces(
                dev_info,
                ptr::null_mut(),
                &GUID_DEVINTERFACE_KBFILTER,
                index,
                &mut iface,
            )
        };
        if ok == 0 {
            break;
        }

        let mut required = 0u32;
        #[allow(clippy::unnecessary_mut_passed)]
        unsafe {
            SetupDiGetDeviceInterfaceDetailW(
                dev_info,
                &mut iface,
                ptr::null_mut(),
                0,
                &mut required,
                ptr::null_mut(),
            );
        }
        if required == 0 {
            index += 1;
            continue;
        }

        let words = (required as usize).div_ceil(size_of::<usize>());
        let mut detail_buf = vec![0usize; words];
        let detail = detail_buf.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
        unsafe {
            (*detail).cbSize = size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
        }

        #[allow(clippy::unnecessary_mut_passed)]
        let ok = unsafe {
            SetupDiGetDeviceInterfaceDetailW(
                dev_info,
                &mut iface,
                detail,
                required,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if ok != 0 {
            unsafe {
                let p = (*detail).DevicePath.as_ptr();
                let mut len = 0usize;
                while *p.add(len) != 0 {
                    len += 1;
                }
                paths.push(std::slice::from_raw_parts(p, len + 1).to_vec());
            }
        }

        index += 1;
    }

    unsafe {
        SetupDiDestroyDeviceInfoList(dev_info);
    }

    if paths.is_empty() {
        anyhow::bail!(
            "no present kanata-kbdflt device interface found: {}",
            io::Error::last_os_error()
        );
    }

    Ok(paths)
}

static KMDF_SESSIONS: Lazy<SessionRegistry> = Lazy::new(SessionRegistry::default);

#[derive(Default)]
struct SessionRegistry {
    sessions: Mutex<Vec<Weak<KmdfSession>>>,
}

impl SessionRegistry {
    fn register(&self, session: &Arc<KmdfSession>) {
        self.sessions.lock().push(Arc::downgrade(session));
    }

    fn pick(&self) -> Option<Arc<KmdfSession>> {
        let mut sessions = self.sessions.lock();
        sessions.retain(|s| s.strong_count() > 0);
        sessions.iter().find_map(|s| s.upgrade())
    }

    fn cancel_all(&self) {
        let sessions = self.sessions.lock();
        for weak in sessions.iter() {
            if let Some(session) = weak.upgrade() {
                session.cancel_io();
            }
        }
    }
}

struct OwnedEvent(HANDLE);

impl OwnedEvent {
    fn new() -> io::Result<Self> {
        let h = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if h == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(h))
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedEvent {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

pub(crate) struct KmdfSession {
    handle: OwnedHandle,
    label: String,
    hwid: [u8; HWID_ARR_SZ],
    inject_lock: Mutex<()>,
}

impl KmdfSession {
    pub(crate) fn open(path: Vec<u16>) -> anyhow::Result<Self> {
        let handle = open_driver_path(path.as_ptr())?;
        let label = path_to_string(&path);
        let hwid = path_to_hwid_bytes(&path);
        Ok(Self {
            handle,
            label,
            hwid,
            inject_lock: Mutex::new(()),
        })
    }

    pub(crate) fn hwid(&self) -> &[u8; HWID_ARR_SZ] {
        &self.hwid
    }


    fn raw(&self) -> isize {
        self.handle.as_raw_handle() as isize
    }

    fn cancel_io(&self) {
        unsafe {
            CancelIoEx(self.raw() as _, ptr::null_mut());
        }
    }

    fn ioctl_overlapped(
        &self,
        code: u32,
        in_buf: *const core::ffi::c_void,
        in_len: u32,
        out_buf: *mut core::ffi::c_void,
        out_len: u32,
    ) -> io::Result<u32> {
        let event = OwnedEvent::new()?;
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = event.raw();

        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.raw(),
                code,
                in_buf as *mut _,
                in_len,
                out_buf,
                out_len,
                &mut returned,
                &mut overlapped,
            )
        };

        if ok != 0 {
            return Ok(returned);
        }

        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
            return Err(err);
        }

        let ok = unsafe { GetOverlappedResult(self.raw(), &mut overlapped, &mut returned, 1) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(returned)
    }

    pub(crate) fn read_events(&self) -> anyhow::Result<Vec<InputEvent>> {
        const CAP: usize = 32;
        let mut buf = [KanataWireEvent::default(); CAP];

        let returned = self.ioctl_overlapped(
            IOCTL_KANATA_READ_EVENTS,
            ptr::null(),
            0,
            buf.as_mut_ptr() as *mut _,
            (size_of::<KanataWireEvent>() * CAP) as u32,
        )?;

        let count = returned as usize / size_of::<KanataWireEvent>();
        Ok(buf[..count]
            .iter()
            .map(|e| InputEvent {
                make_code: e.make_code,
                flags: e.flags,
            })
            .collect())
    }

    pub(crate) fn inject_events(&self, events: &[InputEvent]) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let _guard = self.inject_lock.lock();
        let wire: Vec<KanataWireEvent> = events
            .iter()
            .map(|e| KanataWireEvent {
                make_code: e.make_code,
                flags: e.flags,
                timestamp: 0,
            })
            .collect();

        self.ioctl_overlapped(
            IOCTL_KANATA_INJECT_EVENTS,
            wire.as_ptr() as *const _,
            (size_of::<KanataWireEvent>() * wire.len()) as u32,
            ptr::null_mut(),
            0,
        )?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// KbdIn — used by Kanata's read loop
// ---------------------------------------------------------------------------

pub(crate) struct SourcedInputEvent {
    pub event: InputEvent,
    pub session: Arc<KmdfSession>,
}

pub struct KbdIn {
    rx: Receiver<SourcedInputEvent>,
    pending: VecDeque<SourcedInputEvent>,
    shutdown: Arc<AtomicBool>,
    manager: Option<JoinHandle<()>>,
}

impl Drop for KbdIn {
    fn drop(&mut self) {
        log::info!("kanata-kbdflt: stopping input interface manager and readers");
        self.shutdown.store(true, Ordering::SeqCst);
        KMDF_SESSIONS.cancel_all();

        if let Some(h) = self.manager.take() {
            let _ = h.join();
        }
    }
}

#[derive(Debug)]
enum ReaderExit {
    Stopped { label: String },
}

impl KbdIn {
    pub fn new() -> anyhow::Result<Self> {
        Self::new_filtered(None, None)
    }

    pub fn new_filtered(
        allowed_hwids: Option<Vec<[u8; HWID_ARR_SZ]>>,
        excluded_hwids: Option<Vec<[u8; HWID_ARR_SZ]>>,
    ) -> anyhow::Result<Self> {
        log::info!("kanata-kbdflt: starting input interface manager");

        let (event_tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let manager_shutdown = shutdown.clone();

        let manager = std::thread::spawn(move || {
            input_interface_manager(event_tx, manager_shutdown, allowed_hwids, excluded_hwids)
        });

        Ok(Self {
            rx,
            pending: VecDeque::new(),
            shutdown,
            manager: Some(manager),
        })
    }

    /// Blocking read; returns one event at a time from any attached keyboard stack.
    pub(crate) fn read_sourced(&mut self) -> anyhow::Result<SourcedInputEvent> {
        if let Some(event) = self.pending.pop_front() {
            return Ok(event);
        }

        self.rx
            .recv()
            .map_err(|e| anyhow::anyhow!("kanata-kbdflt: all input reader threads stopped: {e}"))
    }

    pub fn read(&mut self) -> anyhow::Result<InputEvent> {
        self.read_sourced().map(|s| s.event)
    }
}

fn input_interface_manager(
    event_tx: Sender<SourcedInputEvent>,
    shutdown: Arc<AtomicBool>,
    allowed_hwids: Option<Vec<[u8; HWID_ARR_SZ]>>,
    excluded_hwids: Option<Vec<[u8; HWID_ARR_SZ]>>,
) {
    let (exit_tx, exit_rx) = mpsc::channel::<ReaderExit>();
    let mut active = HashSet::<String>::new();
    let mut first_success = false;

    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        while let Ok(exit) = exit_rx.try_recv() {
            match exit {
                ReaderExit::Stopped { label } => {
                    active.remove(&label);
                    log::warn!(
                        "kanata-kbdflt: input reader stopped for {label}; will rescan interfaces"
                    );
                }
            }
        }

        let paths = match enumerate_driver_interface_paths() {
            Ok(paths) => paths,
            Err(e) => {
                if !first_success {
                    log::warn!("kanata-kbdflt: no input interfaces yet ({e}); retrying");
                } else {
                    log::warn!("kanata-kbdflt: input interface rescan failed ({e}); retrying");
                }
                std::thread::sleep(Duration::from_secs(2));
                continue;
            }
        };

        let present = paths
            .iter()
            .map(|p| path_to_string(p))
            .collect::<HashSet<_>>();

        // If an interface disappeared, forget its old state. A replug usually creates a new
        // device path, and this also lets a formerly busy path become eligible after removal.
        active.retain(|label| present.contains(label));

        let mut opened_this_scan = 0usize;
        for path in paths {
            let label = path_to_string(&path);
            if active.contains(&label) {
                continue;
            }

            match KmdfSession::open(path) {
                Ok(session) => {
                    let session = Arc::new(session);
                    if !kmdf_interface_allowed(session.hwid(), &allowed_hwids, &excluded_hwids) {
                        log::info!(
                            "kanata-kbdflt: skipping input interface not matching HWID filters: {label}"
                        );
                        active.insert(label.clone()); // Mark as seen but ignored
                        continue;
                    }
                    KMDF_SESSIONS.register(&session);
                    active.insert(label.clone());
                    opened_this_scan += 1;
                    spawn_input_reader(session, event_tx.clone(), exit_tx.clone(), shutdown.clone());
                }
                Err(e) => {
                    log::warn!("kanata-kbdflt: open input interface {label} failed: {e}");
                }
            }
        }

        if opened_this_scan > 0 {
            first_success = true;
            log::info!(
                "kanata-kbdflt: opened {opened_this_scan} new input interface(s); active={}",
                active.len()
            );
        }

        if active.is_empty() {
            log::warn!("kanata-kbdflt: no active input readers");
        }

        // Polling is deliberate: SetupDi enumeration is cheap here, and this avoids needing
        // a hidden message window for WM_DEVICECHANGE in the console/service process.
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn spawn_input_reader(
    session: Arc<KmdfSession>,
    event_tx: Sender<SourcedInputEvent>,
    exit_tx: Sender<ReaderExit>,
    shutdown: Arc<AtomicBool>,
) {
    std::thread::spawn(move || input_reader_thread(session, event_tx, exit_tx, shutdown));
}

fn input_reader_thread(
    session: Arc<KmdfSession>,
    event_tx: Sender<SourcedInputEvent>,
    exit_tx: Sender<ReaderExit>,
    shutdown: Arc<AtomicBool>,
) {
    log::info!(
        "kanata-kbdflt: input reader started for {} (hwid/path {})",
        session.label,
        hwid_bytes_to_lossy_string(session.hwid())
    );

    loop {
        match session.read_events() {
            Ok(events) => {
                for event in events {
                    let sourced = SourcedInputEvent {
                        event,
                        session: session.clone(),
                    };
                    if event_tx.send(sourced).is_err() {
                        log::info!(
                            "kanata-kbdflt: input reader exiting for {}; receiver closed",
                            session.label
                        );
                        return;
                    }
                }
            }
            Err(e) => {
                if shutdown.load(Ordering::SeqCst) {
                    return;
                }
                log::warn!(
                    "kanata-kbdflt: read error on {} ({e}); reader stopped, manager will rescan",
                    session.label
                );
                let _ = exit_tx.send(ReaderExit::Stopped {
                    label: session.label.clone(),
                });
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// KbdOut — used by Kanata to inject the remapped result
// ---------------------------------------------------------------------------

#[cfg(all(not(feature = "simulated_output"), not(feature = "passthru_ahk")))]
pub struct KbdOut {
    /// The driver session that most recently produced an input event.
    ///
    /// NOTE: Using a global preferred session can lead to theoretical race conditions
    /// where output is routed to the wrong device if multiple keyboards are used
    /// simultaneously. However, Windows kbdclass.sys aggregates input state
    /// globally, so in practice this does not lead to stuck keys or broken logic
    /// in standard user scenarios. Explicit per-key session tracking was considered
    /// but deferred to keep the backend simple and maintainable.
    preferred_session: Option<Weak<KmdfSession>>,
}

#[cfg(all(not(feature = "simulated_output"), not(feature = "passthru_ahk")))]
impl KbdOut {
    pub fn new() -> Result<Self, io::Error> {
        Ok(Self {
            preferred_session: None,
        })
    }

    pub(crate) fn set_preferred_session(&mut self, session: &Arc<KmdfSession>) {
        self.preferred_session = Some(Arc::downgrade(session));
    }

    fn choose_session(&mut self) -> Result<Arc<KmdfSession>, io::Error> {
        if let Some(session) = self
            .preferred_session
            .as_ref()
            .and_then(|weak| weak.upgrade())
        {
            return Ok(session);
        }

        KMDF_SESSIONS.pick().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "kanata-kbdflt: no active driver session available for injection",
            )
        })
    }

    pub fn write(&mut self, event: InputEvent) -> Result<(), io::Error> {
        let session = self.choose_session()?;
        session.inject_events(&[event]).map_err(io::Error::other)
    }

    pub fn write_key(&mut self, key: OsCode, value: KeyValue) -> Result<(), io::Error> {
        let event = InputEvent::from_oscode(key, value)?;
        self.write(event)
    }

    /// Note: write_code currently bypasses the KMDF driver and uses SendInput (legacy).
    pub fn write_code(&mut self, code: u32, value: KeyValue) -> Result<(), io::Error> {
        super::write_code(code as u16, value)
    }

    /// Note: write_code_raw currently bypasses the KMDF driver and uses SendInput (legacy).
    pub fn write_code_raw(&mut self, code: u16, value: KeyValue) -> Result<(), io::Error> {
        super::write_code_raw(code, value)
    }

    pub fn press_key(&mut self, key: OsCode) -> Result<(), io::Error> {
        self.write_key(key, KeyValue::Press)
    }

    pub fn release_key(&mut self, key: OsCode) -> Result<(), io::Error> {
        self.write_key(key, KeyValue::Release)
    }

    /// Unicode via VK_PACKET (SendInput — same as other backends)
    pub fn send_unicode(&mut self, c: char) -> Result<(), io::Error> {
        super::send_uc(c, false);
        super::send_uc(c, true);
        Ok(())
    }

    // Mouse via SendInput — driver is keyboard-only
    pub fn click_btn(&mut self, btn: Btn) -> Result<(), io::Error> {
        log::debug!("kmdf: click_btn {btn:?}");
        use winapi::um::winuser::*;
        match btn {
            Btn::Left => self.mouse_btn(MOUSEEVENTF_LEFTDOWN, 0),
            Btn::Right => self.mouse_btn(MOUSEEVENTF_RIGHTDOWN, 0),
            Btn::Mid => self.mouse_btn(MOUSEEVENTF_MIDDLEDOWN, 0),
            Btn::Backward => self.mouse_btn(MOUSEEVENTF_XDOWN, XBUTTON1.into()),
            Btn::Forward => self.mouse_btn(MOUSEEVENTF_XDOWN, XBUTTON2.into()),
        }
    }

    pub fn release_btn(&mut self, btn: Btn) -> Result<(), io::Error> {
        log::debug!("kmdf: release_btn {btn:?}");
        use winapi::um::winuser::*;
        match btn {
            Btn::Left => self.mouse_btn(MOUSEEVENTF_LEFTUP, 0),
            Btn::Right => self.mouse_btn(MOUSEEVENTF_RIGHTUP, 0),
            Btn::Mid => self.mouse_btn(MOUSEEVENTF_MIDDLEUP, 0),
            Btn::Backward => self.mouse_btn(MOUSEEVENTF_XUP, XBUTTON1.into()),
            Btn::Forward => self.mouse_btn(MOUSEEVENTF_XUP, XBUTTON2.into()),
        }
    }

    pub fn scroll(&mut self, direction: MWheelDirection, distance: u16) -> Result<(), io::Error> {
        log::debug!("kmdf: scroll {direction:?} {distance}");
        use winapi::um::winuser::*;
        let (flag, data): (u32, u32) = match direction {
            MWheelDirection::Up => (MOUSEEVENTF_WHEEL, distance.into()),
            MWheelDirection::Down => (MOUSEEVENTF_WHEEL, (-i32::from(distance)) as u32),
            MWheelDirection::Right => (MOUSEEVENTF_HWHEEL, distance.into()),
            MWheelDirection::Left => (MOUSEEVENTF_HWHEEL, (-i32::from(distance)) as u32),
        };
        self.mouse_event(flag, data, 0, 0);
        Ok(())
    }

    pub fn move_mouse(&mut self, mv: CalculatedMouseMove) -> Result<(), io::Error> {
        use winapi::um::winuser::MOUSEEVENTF_MOVE;
        let (x, y) = match mv.direction {
            MoveDirection::Up => (0, -i32::from(mv.distance)),
            MoveDirection::Down => (0, i32::from(mv.distance)),
            MoveDirection::Left => (-i32::from(mv.distance), 0),
            MoveDirection::Right => (i32::from(mv.distance), 0),
        };
        self.mouse_event(MOUSEEVENTF_MOVE, 0, x, y);
        Ok(())
    }

    pub fn move_mouse_many(&mut self, moves: &[CalculatedMouseMove]) -> Result<(), io::Error> {
        for mv in moves {
            self.move_mouse(*mv)?;
        }
        Ok(())
    }

    pub fn set_mouse(&mut self, x: u16, y: u16) -> Result<(), io::Error> {
        use winapi::um::winuser::*;
        self.mouse_event(
            MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE | MOUSEEVENTF_VIRTUALDESK,
            0,
            i32::from(x),
            i32::from(y),
        );
        Ok(())
    }

    // --- private helpers ---

    fn mouse_btn(&mut self, flag: u32, data: u32) -> Result<(), io::Error> {
        self.mouse_event(flag, data, 0, 0);
        Ok(())
    }

    fn mouse_event(&mut self, flags: u32, data: u32, dx: i32, dy: i32) {
        use std::mem;
        use winapi::um::winuser::*;
        let mut input = winapi::um::winuser::INPUT {
            type_: INPUT_MOUSE,
            u: unsafe {
                mem::transmute::<MOUSEINPUT, winapi::um::winuser::INPUT_u>(MOUSEINPUT {
                    dx,
                    dy,
                    mouseData: data,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                })
            },
        };
        let res = unsafe { SendInput(1, &mut input as LPINPUT, mem::size_of::<INPUT>() as _) };
        if res == 0 {
            log::warn!("SendInput for mouse event failed: {}", std::io::Error::last_os_error());
        }
    }
}
