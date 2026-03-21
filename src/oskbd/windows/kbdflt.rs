//! Windows KMDF kernel-filter backend for reading/writing input events.
//!
//! Communicates with `kanata-kbdflt.sys` via two IOCTLs:
//!   - `IOCTL_KANATA_READ_EVENTS`   — blocking read of suppressed key events
//!   - `IOCTL_KANATA_INJECT_EVENTS` — inject remapped key events back through kbdclass
//!
//! Mouse events are handled via `SendInput` (the driver is keyboard-only).
//!
//! The driver rawPdo device is opened as `\\.\KanataKeyboard`.
//!
//! Selected by `--features kmdf_driver`.

use std::collections::VecDeque;
use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use std::time::Duration;

use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, SP_DEVICE_INTERFACE_DATA,
    SP_DEVICE_INTERFACE_DETAIL_DATA_W, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInterfaces,
    SetupDiGetClassDevsW, SetupDiGetDeviceInterfaceDetailW,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::kanata::CalculatedMouseMove;
use crate::oskbd::KeyValue;
use crate::oskbd::osc_to_u16;
use crate::oskbd::u16_to_osc;
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
    pub fn from_oscode(code: OsCode, val: KeyValue) -> Self {
        let sc = osc_to_u16(code).unwrap_or_else(|| {
            log::error!("kmdf: no scancode for {code:?}, sending 0");
            0
        });

        let mut flags: u16 = match val {
            KeyValue::Press | KeyValue::Repeat => KANATA_KEY_MAKE,
            KeyValue::Release => KANATA_KEY_BREAK,
            KeyValue::Tap | KeyValue::WakeUp => panic!("invalid KeyValue for injection"),
        };

        match sc >> 8 {
            0xE0 => flags |= KANATA_KEY_E0,
            0xE1 => flags |= KANATA_KEY_E1,
            _ => {}
        }

        Self {
            make_code: sc & 0x00FF,
            flags,
        }
    }
}

impl TryFrom<InputEvent> for crate::oskbd::KeyEvent {
    type Error = ();

    fn try_from(ev: InputEvent) -> Result<Self, ()> {
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

        let osc = u16_to_osc(full_sc).ok_or(())?;

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

impl From<crate::oskbd::KeyEvent> for InputEvent {
    fn from(ev: crate::oskbd::KeyEvent) -> Self {
        Self::from_oscode(ev.code, ev.value)
    }
}

// ---------------------------------------------------------------------------
// Driver I/O
// ---------------------------------------------------------------------------

/// `\\.\KanataKeyboard\0` as a UTF-16 literal.
static DEVICE_PATH: &[u16] = &[
    b'\\' as u16,
    b'\\' as u16,
    b'.' as u16,
    b'\\' as u16,
    b'K' as u16,
    b'a' as u16,
    b'n' as u16,
    b'a' as u16,
    b't' as u16,
    b'a' as u16,
    b'K' as u16,
    b'e' as u16,
    b'y' as u16,
    b'b' as u16,
    b'o' as u16,
    b'a' as u16,
    b'r' as u16,
    b'd' as u16,
    0u16,
];

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
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        anyhow::bail!("{}", io::Error::last_os_error());
    }

    // SAFETY: handle is valid and we now own it.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as _) })
}

fn try_open_driver_interface() -> anyhow::Result<OwnedHandle> {
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

    let mut index = 0;
    let result = loop {
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
            break Err(anyhow::anyhow!(
                "no present kanata-kbdflt device interface found: {}",
                io::Error::last_os_error()
            ));
        }

        let mut required = 0u32;
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
            let open_result = unsafe { open_driver_path((*detail).DevicePath.as_ptr()) };
            if open_result.is_ok() {
                break open_result;
            }
        }

        index += 1;
    };

    unsafe {
        SetupDiDestroyDeviceInfoList(dev_info);
    }

    result
}

fn try_open_driver() -> anyhow::Result<OwnedHandle> {
    match open_driver_path(DEVICE_PATH.as_ptr()) {
        Ok(handle) => Ok(handle),
        Err(named_err) => {
            try_open_driver_interface().map_err(|iface_err| {
                anyhow::anyhow!(
                    "CreateFileW(\\\\.\\KanataKeyboard) failed: {named_err}; interface open failed: {iface_err}"
                )
            })
        }
    }
}

fn open_driver_with_retry() -> anyhow::Result<OwnedHandle> {
    let mut delay = Duration::from_millis(100);
    loop {
        match try_open_driver() {
            Ok(h) => return Ok(h),
            Err(e) => {
                log::warn!("kanata-kbdflt: open failed ({e}), retry in {delay:?}");
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_secs(5));
            }
        }
    }
}

struct KmdfHandle {
    handle: OwnedHandle,
}

impl KmdfHandle {
    fn open() -> anyhow::Result<Self> {
        Ok(Self {
            handle: open_driver_with_retry()?,
        })
    }

    fn raw(&self) -> isize {
        self.handle.as_raw_handle() as isize
    }

    fn read_events(&self) -> anyhow::Result<Vec<InputEvent>> {
        const CAP: usize = 32;
        let mut buf = [KanataWireEvent::default(); CAP];
        let mut returned: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.raw(),
                IOCTL_KANATA_READ_EVENTS,
                ptr::null(),
                0,
                buf.as_mut_ptr() as *mut _,
                (size_of::<KanataWireEvent>() * CAP) as u32,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            anyhow::bail!("READ_EVENTS: {}", io::Error::last_os_error());
        }

        let count = returned as usize / size_of::<KanataWireEvent>();
        Ok(buf[..count]
            .iter()
            .map(|e| InputEvent {
                make_code: e.make_code,
                flags: e.flags,
            })
            .collect())
    }

    fn inject_events(&self, events: &[InputEvent]) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let wire: Vec<KanataWireEvent> = events
            .iter()
            .map(|e| KanataWireEvent {
                make_code: e.make_code,
                flags: e.flags,
                timestamp: 0,
            })
            .collect();

        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.raw(),
                IOCTL_KANATA_INJECT_EVENTS,
                wire.as_ptr() as *const _,
                (size_of::<KanataWireEvent>() * wire.len()) as u32,
                ptr::null_mut(),
                0,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            anyhow::bail!("INJECT_EVENTS: {}", io::Error::last_os_error());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// KbdIn — used by Kanata's read loop
// ---------------------------------------------------------------------------

pub struct KbdIn {
    drv: KmdfHandle,
    pending: VecDeque<InputEvent>,
}

impl KbdIn {
    pub fn new() -> anyhow::Result<Self> {
        log::info!("kanata-kbdflt: opening \\.\\ KanataKeyboard for input");
        Ok(Self {
            drv: KmdfHandle::open()?,
            pending: VecDeque::new(),
        })
    }

    /// Blocking read; returns one event at a time, reconnecting on error.
    pub fn read(&mut self) -> anyhow::Result<InputEvent> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Ok(event);
            }

            match self.drv.read_events() {
                Ok(mut evts) if !evts.is_empty() => {
                    let first = evts.remove(0);
                    self.pending.extend(evts);
                    return Ok(first);
                }
                Ok(_) => {} // empty — retry immediately
                Err(e) => {
                    log::warn!("kanata-kbdflt: read error ({e}), reconnecting…");
                    self.drv = KmdfHandle::open()?;
                    self.pending.clear();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// KbdOut — used by Kanata to inject the remapped result
// ---------------------------------------------------------------------------

#[cfg(all(not(feature = "simulated_output"), not(feature = "passthru_ahk")))]
pub struct KbdOut {
    drv: KmdfHandle,
}

#[cfg(all(not(feature = "simulated_output"), not(feature = "passthru_ahk")))]
impl KbdOut {
    pub fn new() -> Result<Self, io::Error> {
        log::info!("kanata-kbdflt: opening \\.\\ KanataKeyboard for output");
        KmdfHandle::open()
            .map(|drv| Self { drv })
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    pub fn write(&mut self, event: InputEvent) -> Result<(), io::Error> {
        match self.drv.inject_events(&[event]) {
            Ok(()) => Ok(()),
            Err(first_err) => {
                log::warn!("kanata-kbdflt: inject error ({first_err}), reconnecting…");
                self.drv = KmdfHandle::open()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                self.drv
                    .inject_events(&[event])
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }

    pub fn write_key(&mut self, key: OsCode, value: KeyValue) -> Result<(), io::Error> {
        self.write(InputEvent::from_oscode(key, value))
    }

    pub fn write_code(&mut self, code: u32, value: KeyValue) -> Result<(), io::Error> {
        super::write_code(code as u16, value)
    }

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
        unsafe { SendInput(1, &mut input as LPINPUT, mem::size_of::<INPUT>() as _) };
    }
}
