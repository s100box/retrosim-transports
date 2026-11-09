// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte
//! One serial port, opened by name, with the platform calls behind an FFI
//! declaration rather than behind a crate.
//!
//! DTR and RTS default to deasserted. Some CH340-equipped boards connect
//! these lines to reset or console control; asserting them can silence the
//! console while networking remains responsive. The open path releases both
//! lines, and an RFC 2217 client can explicitly change them.

use std::io;

/// Which adapter a port belongs to, for finding the same adapter again after
/// it re-enumerates under another name.
///
/// All three come from the USB device the port sits on, never from opening
/// it. `serial` is the adapter's own `iSerialNumber`, and follows the adapter
/// to any socket; many cheap adapters (CH340, most CH341 boards) have none.
/// `location` is the physical path to the socket it is plugged into, so it
/// follows the socket, not the adapter. A port that is not on USB, or a
/// platform where neither is read (macOS), has neither.
///
/// `interface` is what tells the ports of ONE adapter apart. An FT2232 or a
/// CP2105 is one USB device with two serial ports, and both report the same
/// serial number and the same location; only the USB interface number (`00`,
/// `01`, as the descriptor's `bInterfaceNumber`) differs. Without it a
/// reconnect could not tell channel A from channel B. A single-port adapter
/// has none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Identity {
    pub serial: Option<String>,
    pub location: Option<String>,
    pub interface: Option<String>,
}

/// The USB device above a tty in sysfs: the first ancestor of `dev` holding
/// an `idVendor` file. Its `serial` file is the serial number (absent when the
/// adapter has none) and its directory name (`1-1.2`: bus 1, root port 1, hub
/// port 2) is the location. The directory just below it is the USB interface
/// (`1-1.2:1.0`), whose `bInterfaceNumber` file holds the interface number.
///
/// Takes the already-resolved device path, so a test can hand it a plain
/// directory tree instead of `/sys`.
#[cfg(any(target_os = "linux", test))]
pub fn usb_identity_in_sysfs(dev: &std::path::Path) -> Identity {
    let read = |p: std::path::PathBuf| {
        std::fs::read_to_string(p)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let mut below: Option<&std::path::Path> = None;
    for dir in dev.ancestors() {
        if dir.join("idVendor").is_file() {
            return Identity {
                serial: read(dir.join("serial")),
                location: dir.file_name().map(|n| n.to_string_lossy().into_owned()),
                interface: below.and_then(|b| read(b.join("bInterfaceNumber"))),
            };
        }
        below = Some(dir);
    }
    Identity::default()
}

/// The interface number in a Windows instance ID of one interface of a
/// composite USB device: `USB\VID_10C4&PID_EA70&MI_01\...` is interface `01`.
#[cfg(any(windows, test))]
pub fn interface_from_instance_id(id: &str) -> Option<String> {
    let up = id.to_ascii_uppercase();
    let at = up.find("&MI_")? + 4;
    let n: String = up[at..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    (!n.is_empty()).then_some(n)
}

/// The serial number in a Windows USB device instance ID, which is the ID's
/// last segment (`USB\VID_0403&PID_6001\FT94XQ2B`). When the device has no
/// serial number, or Windows does not trust it to be unique, Windows writes a
/// generated segment there instead (`5&2a3b4c5d&0&3`), and those always hold
/// an `&`, which a USB serial string reported this way never does.
#[cfg(any(windows, test))]
pub fn serial_from_instance_id(id: &str) -> Option<String> {
    let last = id.rsplit('\\').next()?;
    if last.is_empty() || last.contains('&') {
        None
    } else {
        Some(last.to_string())
    }
}

/// What a read returned, keeping "nothing yet" apart from "the port is gone".
#[derive(Debug)]
pub enum Read {
    /// Bytes arrived.
    Got(usize),
    /// The timeout expired with nothing to read. Normal and frequent.
    Idle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parity {
    None,
    Odd,
    Even,
    Mark,
    Space,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopBits {
    One,
    OnePointFive,
    Two,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    None,
    XonXoff,
    RtsCts,
}

/// How the port frames characters. The bridge's own are 8N1 at `--baud` with
/// no flow control; an RFC 2217 client may change them while it is connected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub baud: u32,
    /// 5..=8.
    pub data_bits: u8,
    pub parity: Parity,
    pub stop_bits: StopBits,
    pub flow: Flow,
}

impl Settings {
    pub fn new(baud: u32) -> Self {
        Settings {
            baud,
            data_bits: 8,
            parity: Parity::None,
            stop_bits: StopBits::One,
            flow: Flow::None,
        }
    }
}

impl std::fmt::Display for Settings {
    /// `115200 8N1`, with the flow control after it when there is any.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parity = match self.parity {
            Parity::None => 'N',
            Parity::Odd => 'O',
            Parity::Even => 'E',
            Parity::Mark => 'M',
            Parity::Space => 'S',
        };
        let stop = match self.stop_bits {
            StopBits::One => "1",
            StopBits::OnePointFive => "1.5",
            StopBits::Two => "2",
        };
        write!(f, "{} {}{parity}{stop}", self.baud, self.data_bits)?;
        match self.flow {
            Flow::None => Ok(()),
            Flow::XonXoff => write!(f, " XON/XOFF"),
            Flow::RtsCts => write!(f, " RTS/CTS"),
        }
    }
}

/// Modem-status bits, in the positions RFC 2217's NOTIFY-MODEMSTATE uses
/// (which are also the positions Windows' `GetCommModemStatus` reports).
pub const MODEM_CTS: u8 = 0x10;
pub const MODEM_DSR: u8 = 0x20;
pub const MODEM_RI: u8 = 0x40;
pub const MODEM_DCD: u8 = 0x80;

#[cfg(unix)]
fn unsupported(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{what} is not supported here"),
    )
}

/// Validate names before converting them to NUL-terminated platform strings.
fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "serial name must be nonempty and contain no NUL",
        ));
    }
    Ok(())
}

fn validate_settings(settings: &Settings) -> io::Result<()> {
    if settings.baud == 0 || !(5..=8).contains(&settings.data_bits) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "serial baud must be nonzero and data bits must be 5..=8",
        ));
    }
    Ok(())
}

/// Windows APIs take a DWORD byte count. Cap each operation rather than
/// wrapping a large slice length to zero or another, smaller request.
#[cfg(any(windows, test))]
fn transfer_len(length: usize) -> u32 {
    length.min(u32::MAX as usize) as u32
}

/// A successful native write must consume bytes or the retry loop cannot advance.
#[cfg(any(unix, test))]
fn written_count(count: usize) -> io::Result<usize> {
    if count == 0 {
        Err(io::ErrorKind::WriteZero.into())
    } else {
        Ok(count)
    }
}

/// Serialize modem-line updates with DCB reconfiguration. A cached snapshot
/// alone is insufficient: SetCommState would overwrite a concurrent line set.
#[cfg(any(windows, test))]
#[derive(Default)]
struct ControlLines(std::sync::Mutex<(bool, bool)>);

#[cfg(any(windows, test))]
impl ControlLines {
    fn apply(&self, operation: impl FnOnce(bool, bool) -> io::Result<()>) -> io::Result<()> {
        let state = self.0.lock().unwrap();
        operation(state.0, state.1)
    }

    fn set(
        &self,
        dtr: bool,
        on: bool,
        operation: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        let mut state = self.0.lock().unwrap();
        operation()?;
        if dtr {
            state.0 = on;
        } else {
            state.1 = on;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------
#[cfg(windows)]
mod imp {
    use super::{io, Flow, Parity, Read, Settings, StopBits};
    use super::{MODEM_CTS, MODEM_DCD, MODEM_DSR, MODEM_RI};
    use std::os::raw::c_void;
    use std::sync::Mutex;

    type Handle = isize;
    const INVALID_HANDLE_VALUE: Handle = -1;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const OPEN_EXISTING: u32 = 3;
    /// Opened OVERLAPPED so a read and a write can be in flight together.
    /// A handle opened without it serializes every call on it, so a write
    /// would wait behind the reader's pending read (up to its 100 ms timeout)
    /// and every reply through the bridge would arrive that much late.
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    const ERROR_IO_PENDING: i32 = 997;
    const PURGE_TXCLEAR: u32 = 0x0004;
    const PURGE_RXCLEAR: u32 = 0x0008;
    const SETRTS: u32 = 3;
    const CLRRTS: u32 = 4;
    const SETDTR: u32 = 5;
    const CLRDTR: u32 = 6;
    const SETBREAK: u32 = 8;
    const CLRBREAK: u32 = 9;

    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: Handle,
    }

    impl Overlapped {
        fn on(event: Handle) -> Self {
            Overlapped {
                internal: 0,
                internal_high: 0,
                offset: 0,
                offset_high: 0,
                event,
            }
        }
    }

    #[repr(C)]
    #[derive(Default)]
    struct Dcb {
        dcb_length: u32,
        baud_rate: u32,
        /// The packed bitfield: bit 0 `fBinary`, bits 4..5 `fDtrControl`,
        /// bits 12..13 `fRtsControl`, and the flow-control flags between them.
        flags: u32,
        w_reserved: u16,
        xon_lim: u16,
        xoff_lim: u16,
        byte_size: u8,
        parity: u8,
        stop_bits: u8,
        xon_char: i8,
        xoff_char: i8,
        error_char: i8,
        eof_char: i8,
        evt_char: i8,
        w_reserved1: u16,
    }

    #[repr(C)]
    #[derive(Default)]
    struct CommTimeouts {
        read_interval: u32,
        read_total_multiplier: u32,
        read_total_constant: u32,
        write_total_multiplier: u32,
        write_total_constant: u32,
    }

    extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            sec: *mut c_void,
            disposition: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn CloseHandle(h: Handle) -> i32;
        fn GetCommState(h: Handle, dcb: *mut Dcb) -> i32;
        fn SetCommState(h: Handle, dcb: *const Dcb) -> i32;
        fn SetCommTimeouts(h: Handle, t: *const CommTimeouts) -> i32;
        fn PurgeComm(h: Handle, flags: u32) -> i32;
        fn ReadFile(h: Handle, buf: *mut u8, n: u32, got: *mut u32, ov: *mut Overlapped) -> i32;
        fn WriteFile(h: Handle, buf: *const u8, n: u32, put: *mut u32, ov: *mut Overlapped) -> i32;
        fn GetOverlappedResult(h: Handle, ov: *mut Overlapped, n: *mut u32, wait: i32) -> i32;
        fn CreateEventW(sec: *mut c_void, manual: i32, initial: i32, name: *const u16) -> Handle;
        fn EscapeCommFunction(h: Handle, func: u32) -> i32;
        fn GetCommModemStatus(h: Handle, status: *mut u32) -> i32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(key: isize, sub: *const u16, opts: u32, sam: u32, out: *mut isize) -> i32;
        fn RegEnumValueW(
            key: isize,
            index: u32,
            name: *mut u16,
            name_len: *mut u32,
            reserved: *mut u32,
            kind: *mut u32,
            data: *mut u8,
            data_len: *mut u32,
        ) -> i32;
        fn RegCloseKey(key: isize) -> i32;
        fn RegQueryValueExW(
            key: isize,
            name: *const u16,
            reserved: *mut u32,
            kind: *mut u32,
            data: *mut u8,
            data_len: *mut u32,
        ) -> i32;
    }

    /// `SP_DEVINFO_DATA`. The GUID is carried as bytes: only its size and
    /// 4-byte alignment matter here, and nothing reads it.
    #[repr(C)]
    struct SpDevinfoData {
        cb_size: u32,
        class_guid: [u32; 4],
        dev_inst: u32,
        reserved: usize,
    }

    // 32 bytes on x64 and 28 on x86, as `sizeof(SP_DEVINFO_DATA)` is; SetupAPI
    // rejects any other `cbSize`, so a wrong layout fails every call, loudly.
    #[cfg(target_pointer_width = "64")]
    const _: () = assert!(std::mem::size_of::<SpDevinfoData>() == 32);
    #[cfg(target_pointer_width = "32")]
    const _: () = assert!(std::mem::size_of::<SpDevinfoData>() == 28);

    const DIGCF_PRESENT: u32 = 0x2;
    const DIGCF_ALLCLASSES: u32 = 0x4;
    const DICS_FLAG_GLOBAL: u32 = 1;
    const DIREG_DEV: u32 = 1;
    const KEY_READ: u32 = 0x2_0019;
    const ERROR_SUCCESS: i32 = 0;
    const CR_SUCCESS: u32 = 0;
    /// `CM_DRP_LOCATION_PATHS` (`SPDRP_LOCATION_PATHS` + 1), a `REG_MULTI_SZ`
    /// such as `PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(3)#USB(2)`.
    const CM_DRP_LOCATION_PATHS: u32 = 0x24;

    #[link(name = "setupapi")]
    extern "system" {
        fn SetupDiGetClassDevsW(
            guid: *const c_void,
            enumerator: *const u16,
            parent: isize,
            flags: u32,
        ) -> isize;
        fn SetupDiEnumDeviceInfo(set: isize, index: u32, data: *mut SpDevinfoData) -> i32;
        fn SetupDiOpenDevRegKey(
            set: isize,
            data: *const SpDevinfoData,
            scope: u32,
            profile: u32,
            key_type: u32,
            sam: u32,
        ) -> isize;
        fn SetupDiDestroyDeviceInfoList(set: isize) -> i32;
    }

    #[link(name = "cfgmgr32")]
    extern "system" {
        fn CM_Get_Parent(parent: *mut u32, dev: u32, flags: u32) -> u32;
        fn CM_Get_Device_IDW(dev: u32, buf: *mut u16, len: u32, flags: u32) -> u32;
        fn CM_Get_DevNode_Registry_PropertyW(
            dev: u32,
            property: u32,
            kind: *mut u32,
            buf: *mut c_void,
            len: *mut u32,
            flags: u32,
        ) -> u32;
    }

    pub struct Port {
        h: Handle,
        read_event: Handle,
        write_event: Handle,
        /// One read and one write at a time: each direction has a single
        /// OVERLAPPED event, and two calls sharing it would complete each
        /// other's waits.
        read_lock: Mutex<()>,
        write_lock: Mutex<()>,
        /// DTR and RTS as last set, so a reconfigure — which rewrites the
        /// line-control fields of the DCB — keeps them.
        lines: super::ControlLines,
    }

    // FFI invariants: Port owns the handles until Drop. Each I/O direction
    // holds its mutex and stack OVERLAPPED through GetOverlappedResult(wait=1),
    // so Windows finishes using the borrowed buffer before the call returns.
    // ControlLines serializes DCB changes with DTR/RTS updates. Registry and
    // SetupAPI calls borrow repr(C) records/UTF-16 buffers only synchronously.
    // Integer handles and mutexes make Port Send + Sync automatically.

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn check(ok: i32) -> io::Result<()> {
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    impl Port {
        pub fn open(name: &str, settings: &Settings) -> io::Result<Self> {
            super::validate_name(name)?;
            super::validate_settings(settings)?;
            // Bare COM names need the device namespace above COM9. Preserve
            // qualified paths, including exact USB serial-device interfaces.
            let path = if name.starts_with('\\') {
                wide(name)
            } else {
                wide(&format!(r"\\.\{name}"))
            };
            let h = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0, // exclusive: the console port opens ONCE
                    std::ptr::null_mut(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    0,
                )
            };
            if h == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            // Own the device before allocating events so any failure closes it.
            let mut p = Port {
                h,
                read_event: 0,
                write_event: 0,
                read_lock: Mutex::new(()),
                write_lock: Mutex::new(()),
                lines: super::ControlLines::default(),
            };
            p.allocate_events(|| {
                // SAFETY: no security/name pointers are supplied. The returned
                // manual-reset event is owned by p until Drop.
                let event = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
                if event == 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(event)
                }
            })?;
            p.configure(settings)?;
            // Return from a read as soon as anything is there, and after 100 ms
            // when nothing is: this exact combination (interval and multiplier
            // both MAXDWORD) is the one Windows documents for that. With a
            // multiplier of 0 a read instead waits out the full 100 ms for a
            // buffer that is not full, and every reply is that much late.
            let t = CommTimeouts {
                read_interval: u32::MAX,
                read_total_multiplier: u32::MAX,
                read_total_constant: 100,
                write_total_multiplier: 0,
                write_total_constant: 3000,
            };
            check(unsafe { SetCommTimeouts(p.h, &t) })?;
            p.purge(true, true)?;
            Ok(p)
        }

        fn allocate_events(
            &mut self,
            mut create: impl FnMut() -> io::Result<Handle>,
        ) -> io::Result<()> {
            // Stop at the first failed allocation. A later successful API call
            // must not overwrite the thread's last-error value before capture.
            self.read_event = create()?;
            self.write_event = create()?;
            Ok(())
        }

        /// Applies `s`, keeping DTR and RTS as they are. A new port has
        /// both DEASSERTED -- see the module note.
        pub fn configure(&self, s: &Settings) -> io::Result<()> {
            super::validate_settings(s)?;
            let mut dcb = Dcb {
                dcb_length: std::mem::size_of::<Dcb>() as u32,
                ..Default::default()
            };
            check(unsafe { GetCommState(self.h, &mut dcb) })?;
            dcb.baud_rate = s.baud;
            dcb.byte_size = s.data_bits;
            dcb.parity = match s.parity {
                Parity::None => 0,
                Parity::Odd => 1,
                Parity::Even => 2,
                Parity::Mark => 3,
                Parity::Space => 4,
            };
            dcb.stop_bits = match s.stop_bits {
                StopBits::One => 0,
                StopBits::OnePointFive => 1,
                StopBits::Two => 2,
            };
            self.lines.apply(|dtr, rts| {
                // The packed flags: bit 0 fBinary, 1 fParity, 2 fOutxCtsFlow,
                // 4..5 fDtrControl, 8 fOutX, 9 fInX, 12..13 fRtsControl. Everything
                // not set here is off. DtrControl/RtsControl 0 is DISABLE (line
                // deasserted), 1 ENABLE (asserted), and RtsControl 2 HANDSHAKE.
                let mut f: u32 = 1;
                if s.parity != Parity::None {
                    f |= 1 << 1;
                }
                if dtr {
                    f |= 1 << 4;
                }
                match s.flow {
                    Flow::None => {
                        if rts {
                            f |= 1 << 12;
                        }
                    }
                    Flow::RtsCts => f |= (1 << 2) | (2 << 12),
                    Flow::XonXoff => {
                        f |= (1 << 8) | (1 << 9);
                        if rts {
                            f |= 1 << 12;
                        }
                        dcb.xon_char = 0x11;
                        dcb.xoff_char = 0x13;
                    }
                }
                dcb.flags = f;
                check(unsafe { SetCommState(self.h, &dcb) })
            })
        }

        pub fn read(&self, buf: &mut [u8]) -> io::Result<Read> {
            let _one = self.read_lock.lock().unwrap();
            let mut ov = Overlapped::on(self.read_event);
            let mut got: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    self.h,
                    buf.as_mut_ptr(),
                    super::transfer_len(buf.len()),
                    std::ptr::null_mut(),
                    &mut ov,
                )
            };
            if ok == 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(ERROR_IO_PENDING) {
                    return Err(e);
                }
            }
            check(unsafe { GetOverlappedResult(self.h, &mut ov, &mut got, 1) })?;
            if got == 0 {
                Ok(Read::Idle)
            } else {
                Ok(Read::Got(got as usize))
            }
        }

        pub fn write_all(&self, mut buf: &[u8]) -> io::Result<()> {
            let _one = self.write_lock.lock().unwrap();
            while !buf.is_empty() {
                let mut ov = Overlapped::on(self.write_event);
                let mut put: u32 = 0;
                let ok = unsafe {
                    WriteFile(
                        self.h,
                        buf.as_ptr(),
                        super::transfer_len(buf.len()),
                        std::ptr::null_mut(),
                        &mut ov,
                    )
                };
                if ok == 0 {
                    let e = io::Error::last_os_error();
                    if e.raw_os_error() != Some(ERROR_IO_PENDING) {
                        return Err(e);
                    }
                }
                check(unsafe { GetOverlappedResult(self.h, &mut ov, &mut put, 1) })?;
                if put == 0 {
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "wrote nothing"));
                }
                buf = &buf[put as usize..];
            }
            Ok(())
        }

        pub fn set_dtr(&self, on: bool) -> io::Result<()> {
            self.lines.set(true, on, || {
                check(unsafe { EscapeCommFunction(self.h, if on { SETDTR } else { CLRDTR }) })
            })
        }

        pub fn set_rts(&self, on: bool) -> io::Result<()> {
            self.lines.set(false, on, || {
                check(unsafe { EscapeCommFunction(self.h, if on { SETRTS } else { CLRRTS }) })
            })
        }

        pub fn set_break(&self, on: bool) -> io::Result<()> {
            check(unsafe { EscapeCommFunction(self.h, if on { SETBREAK } else { CLRBREAK }) })
        }

        /// CTS, DSR, RI and DCD, in the `MODEM_*` bit positions.
        pub fn modem_status(&self) -> io::Result<u8> {
            let mut s: u32 = 0;
            check(unsafe { GetCommModemStatus(self.h, &mut s) })?;
            Ok(s as u8 & (MODEM_CTS | MODEM_DSR | MODEM_RI | MODEM_DCD))
        }

        /// Discards what is queued in the driver. CLEAR only, never ABORT:
        /// an abort would cancel the reader's pending read, which then reads
        /// as a lost port.
        pub fn purge(&self, rx: bool, tx: bool) -> io::Result<()> {
            let mut f = 0;
            if rx {
                f |= PURGE_RXCLEAR;
            }
            if tx {
                f |= PURGE_TXCLEAR;
            }
            check(unsafe { PurgeComm(self.h, f) })
        }
    }

    impl Drop for Port {
        fn drop(&mut self) {
            unsafe {
                if self.h != INVALID_HANDLE_VALUE {
                    CloseHandle(self.h);
                }
                if self.read_event != 0 {
                    CloseHandle(self.read_event);
                }
                if self.write_event != 0 {
                    CloseHandle(self.write_event);
                }
            }
        }
    }

    /// Enumerate registry serial names without opening candidate devices.
    /// Opening a candidate could change modem lines and reset an attached board.
    pub fn present() -> Vec<String> {
        const HKEY_LOCAL_MACHINE: isize = -2147483646; // 0x8000_0002

        let mut out = Vec::new();
        let sub = wide(r"HARDWARE\DEVICEMAP\SERIALCOMM");
        let mut key: isize = 0;
        let rc = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_READ, &mut key) };
        if rc != ERROR_SUCCESS {
            // No key at all means no serial ports, which is a real answer.
            return out;
        }
        let mut idx: u32 = 0;
        loop {
            let mut name = [0u16; 256];
            let mut name_len: u32 = name.len() as u32;
            let mut data = [0u16; 256];
            let mut data_len: u32 = (data.len() * 2) as u32; // BYTES, not chars
            let mut kind: u32 = 0;
            let rc = unsafe {
                RegEnumValueW(
                    key,
                    idx,
                    name.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null_mut(),
                    &mut kind,
                    data.as_mut_ptr().cast(),
                    &mut data_len,
                )
            };
            if rc != ERROR_SUCCESS {
                break;
            }
            // The VALUE is the port name ("COM20"); the name is the device
            // path. Trim at the first NUL -- the length is in bytes and the
            // buffer is not guaranteed to be terminated within it.
            let chars = (data_len as usize) / 2;
            let s: String = String::from_utf16_lossy(&data[..chars.min(data.len())])
                .trim_end_matches('\0')
                .to_string();
            if !s.is_empty() {
                out.push(s);
            }
            idx += 1;
        }
        unsafe { RegCloseKey(key) };
        // SERIALCOMM is keyed by device path, not port name. Re-enumeration
        // can leave several stale device rows naming the same COM port.
        out.sort();
        out.dedup();
        out
    }

    /// Every present port with the identity of the USB adapter under it.
    ///
    /// The port's device node is found by its `PortName` value (the `Device
    /// Parameters` key every serial driver writes), and the identity is read
    /// from the USB device at or above it. Like `present`, this only reads the
    /// device tree and the registry: no port is opened.
    pub fn identities() -> Vec<(String, super::Identity)> {
        let mut found: Vec<(String, u32)> = Vec::new();
        let set = unsafe {
            SetupDiGetClassDevsW(
                std::ptr::null(),
                std::ptr::null(),
                0,
                DIGCF_PRESENT | DIGCF_ALLCLASSES,
            )
        };
        if set != INVALID_HANDLE_VALUE {
            let mut idx = 0;
            loop {
                let mut d = SpDevinfoData {
                    cb_size: std::mem::size_of::<SpDevinfoData>() as u32,
                    class_guid: [0; 4],
                    dev_inst: 0,
                    reserved: 0,
                };
                if unsafe { SetupDiEnumDeviceInfo(set, idx, &mut d) } == 0 {
                    break;
                }
                idx += 1;
                let key = unsafe {
                    SetupDiOpenDevRegKey(set, &d, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ)
                };
                if key == INVALID_HANDLE_VALUE {
                    continue;
                }
                if let Some(name) = reg_string(key, "PortName") {
                    found.push((name, d.dev_inst));
                }
                unsafe { RegCloseKey(key) };
            }
            unsafe { SetupDiDestroyDeviceInfoList(set) };
        }
        present()
            .into_iter()
            .map(|name| {
                let id = found
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case(&name))
                    .map(|&(_, dev)| usb_identity(dev))
                    .unwrap_or_default();
                (name, id)
            })
            .collect()
    }

    /// The identity of the USB device at or above `dev`.
    ///
    /// The port is not always the USB device itself. A CH340's driver sits
    /// on the USB device node (`USB\VID_1A86&PID_7523\...`); a single FTDI's
    /// on a child of it (`FTDIBUS\VID_0403+PID_6001+...`); each port of an
    /// FT2232 on a child of one INTERFACE (`USB\VID_0403&PID_6010&MI_01\...`);
    /// a CP2105's port on the interface node itself. So walk up, noting the
    /// first interface passed, to the first `USB\` node that is not an
    /// interface, and read the serial number and location from that.
    fn usb_identity(mut dev: u32) -> super::Identity {
        let mut interface = None;
        loop {
            if let Some(id) = device_id(dev) {
                let up = id.to_ascii_uppercase();
                if up.starts_with("USB\\") {
                    match super::interface_from_instance_id(&id) {
                        Some(i) => {
                            interface.get_or_insert(i);
                        }
                        None => {
                            return super::Identity {
                                serial: super::serial_from_instance_id(&id),
                                location: location_path(dev),
                                interface,
                            };
                        }
                    }
                }
            }
            let mut parent = 0;
            if unsafe { CM_Get_Parent(&mut parent, dev, 0) } != CR_SUCCESS {
                return super::Identity::default();
            }
            dev = parent;
        }
    }

    fn device_id(dev: u32) -> Option<String> {
        let mut buf = [0u16; 512];
        if unsafe { CM_Get_Device_IDW(dev, buf.as_mut_ptr(), super::transfer_len(buf.len()), 0) }
            != CR_SUCCESS
        {
            return None;
        }
        let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..n]))
    }

    /// The first of the device's location paths.
    fn location_path(dev: u32) -> Option<String> {
        let mut buf = [0u16; 1024];
        let mut len = (buf.len() * 2) as u32; // BYTES
        let mut kind = 0;
        let rc = unsafe {
            CM_Get_DevNode_Registry_PropertyW(
                dev,
                CM_DRP_LOCATION_PATHS,
                &mut kind,
                buf.as_mut_ptr().cast(),
                &mut len,
                0,
            )
        };
        if rc != CR_SUCCESS {
            return None;
        }
        let chars = ((len as usize) / 2).min(buf.len());
        let n = buf[..chars].iter().position(|&c| c == 0).unwrap_or(chars);
        let s = String::from_utf16_lossy(&buf[..n]);
        (!s.is_empty()).then_some(s)
    }

    fn reg_string(key: isize, value: &str) -> Option<String> {
        let name = wide(value);
        let mut data = [0u16; 256];
        let mut len = (data.len() * 2) as u32; // BYTES
        let mut kind = 0;
        let rc = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut kind,
                data.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        let chars = ((len as usize) / 2).min(data.len());
        let n = data[..chars].iter().position(|&c| c == 0).unwrap_or(chars);
        let s = String::from_utf16_lossy(&data[..n]);
        (!s.is_empty()).then_some(s)
    }
    #[cfg(test)]
    mod event_tests {
        use super::*;

        #[test]
        fn failed_first_event_allocation_is_preserved_and_stops_setup() {
            let mut port = Port {
                h: INVALID_HANDLE_VALUE,
                read_event: 0,
                write_event: 0,
                read_lock: Mutex::new(()),
                write_lock: Mutex::new(()),
                lines: super::super::ControlLines::default(),
            };
            let mut calls = 0;
            let error = port
                .allocate_events(|| {
                    calls += 1;
                    Err(io::Error::other("allocation failed"))
                })
                .unwrap_err();
            assert_eq!(calls, 1);
            assert_eq!(error.to_string(), "allocation failed");
            assert_eq!((port.read_event, port.write_event), (0, 0));
        }
    }
}

// ---------------------------------------------------------------------------
// Unix: Linux and the BSD/Darwin family
// ---------------------------------------------------------------------------
//
// Linux and Darwin have different termios layouts, flags and selectors.
// Keep each ABI in its own module, with compile-time layout size checks.
// Windows and Linux have native/pty qualification; macOS has compile-only
// coverage. Other Unix ABIs need their own declarations before being supported.
#[cfg(unix)]
mod imp {
    use super::{io, unsupported, Flow, Parity, Read, Settings, StopBits};
    use super::{MODEM_CTS, MODEM_DCD, MODEM_DSR, MODEM_RI};
    use std::os::raw::{c_int, c_ulong, c_void};
    use std::sync::Mutex;

    // ---- Linux ------------------------------------------------------------
    #[cfg(target_os = "linux")]
    mod abi {
        /// `tcflag_t` and `speed_t` are both `unsigned int` on Linux.
        pub type Flag = u32;

        #[repr(C)]
        #[derive(Default, Clone, Copy)]
        pub struct Termios {
            pub c_iflag: Flag,
            pub c_oflag: Flag,
            pub c_cflag: Flag,
            pub c_lflag: Flag,
            /// Linux only. Darwin's struct has no line discipline here.
            pub c_line: u8,
            pub c_cc: [u8; 32],
            pub c_ispeed: Flag,
            pub c_ospeed: Flag,
        }

        // glibc termios: four flag words, c_line, 32 control bytes and two speeds.
        const _: () = assert!(core::mem::size_of::<Termios>() == 60);

        pub const CLOCAL: Flag = 0o004000;
        pub const CREAD: Flag = 0o000200;
        pub const VTIME: usize = 5;
        pub const VMIN: usize = 6;
        pub const TCIFLUSH: super::c_int = 0;
        pub const TCOFLUSH: super::c_int = 1;
        pub const TCIOFLUSH: super::c_int = 2;
        pub const O_NOCTTY: super::c_int = 0o400;
        pub const O_NONBLOCK: super::c_int = 0o4000;

        pub const CSIZE: Flag = 0o60;
        pub const CS5: Flag = 0;
        pub const CS6: Flag = 0o20;
        pub const CS7: Flag = 0o40;
        pub const CS8: Flag = 0o60;
        pub const CSTOPB: Flag = 0o100;
        pub const PARENB: Flag = 0o400;
        pub const PARODD: Flag = 0o1000;
        /// Mark/space parity: PARODD then picks mark.
        pub const CMSPAR: Option<Flag> = Some(0o10000000000);
        pub const CRTSCTS: Flag = 0o20000000000;
        pub const IXON: Flag = 0o2000;
        pub const IXOFF: Flag = 0o10000;
        pub const IXANY: Flag = 0o4000;

        pub const TIOCMGET: super::c_ulong = 0x5415;
        pub const TIOCMBIS: super::c_ulong = 0x5416;
        pub const TIOCMBIC: super::c_ulong = 0x5417;
        pub const TIOCSBRK: super::c_ulong = 0x5427;
        pub const TIOCCBRK: super::c_ulong = 0x5428;

        /// Linux wants the `Bnnn` **token**, not the rate.
        pub fn baud(n: u32) -> Option<Flag> {
            Some(match n {
                9600 => 0o15,
                19200 => 0o16,
                38400 => 0o17,
                57600 => 0o010001,
                115_200 => 0o010002,
                230_400 => 0o010003,
                460_800 => 0o010004,
                921_600 => 0o010007,
                _ => return None,
            })
        }
    }

    // ---- Darwin ----------------------------------------------
    #[cfg(target_os = "macos")]
    mod abi {
        /// `tcflag_t` and `speed_t` are `unsigned long` here, not `unsigned
        /// int`. On 64-bit that doubles every field's width and moves `c_cc`.
        pub type Flag = u64;

        #[repr(C)]
        #[derive(Default, Clone, Copy)]
        pub struct Termios {
            pub c_iflag: Flag,
            pub c_oflag: Flag,
            pub c_cflag: Flag,
            pub c_lflag: Flag,
            /// `NCCS` is 20 here, against Linux's 32, and there is no `c_line`.
            pub c_cc: [u8; 20],
            pub c_ispeed: Flag,
            pub c_ospeed: Flag,
        }

        // Darwin termios uses 64-bit flag/speed words and 20 control bytes.
        const _: () = assert!(core::mem::size_of::<Termios>() == 72);

        pub const CLOCAL: Flag = 0x8000;
        pub const CREAD: Flag = 0x800;
        pub const VMIN: usize = 16;
        pub const VTIME: usize = 17;
        /// 1/2/3 here, 0/1/2 on Linux — the queue selectors are numbered
        /// differently.
        pub const TCIFLUSH: super::c_int = 1;
        pub const TCOFLUSH: super::c_int = 2;
        pub const TCIOFLUSH: super::c_int = 3;
        pub const O_NOCTTY: super::c_int = 0x20000;
        pub const O_NONBLOCK: super::c_int = 0x0004;

        pub const CSIZE: Flag = 0x300;
        pub const CS5: Flag = 0;
        pub const CS6: Flag = 0x100;
        pub const CS7: Flag = 0x200;
        pub const CS8: Flag = 0x300;
        pub const CSTOPB: Flag = 0x400;
        pub const PARENB: Flag = 0x1000;
        pub const PARODD: Flag = 0x2000;
        /// Darwin has no mark/space parity.
        pub const CMSPAR: Option<Flag> = None;
        /// `CCTS_OFLOW | CRTS_IFLOW`.
        pub const CRTSCTS: Flag = 0x30000;
        pub const IXON: Flag = 0x200;
        pub const IXOFF: Flag = 0x400;
        pub const IXANY: Flag = 0x800;

        // `_IOR('t', 106, int)`, `_IOW('t', 108, int)`, `_IOW('t', 107, int)`,
        // `_IO('t', 123)`, `_IO('t', 122)`.
        pub const TIOCMGET: super::c_ulong = 0x4004_746a;
        pub const TIOCMBIS: super::c_ulong = 0x8004_746c;
        pub const TIOCMBIC: super::c_ulong = 0x8004_746b;
        pub const TIOCSBRK: super::c_ulong = 0x2000_747b;
        pub const TIOCCBRK: super::c_ulong = 0x2000_747a;

        /// Darwin encodes the literal rate; the driver may still reject it.
        pub fn baud(n: u32) -> Option<Flag> {
            Some(Flag::from(n))
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    compile_error!("serbridge's native serial backend supports Linux and macOS Unix ABIs only");

    use abi::Termios;

    const O_RDWR: c_int = 0o2;
    const TCSANOW: c_int = 0;
    const F_GETFL: c_int = 3;
    const F_SETFL: c_int = 4;
    // The same values on Linux and Darwin.
    const TIOCM_DTR: c_int = 0x002;
    const TIOCM_RTS: c_int = 0x004;
    const TIOCM_CTS: c_int = 0x020;
    const TIOCM_CAR: c_int = 0x040;
    const TIOCM_RNG: c_int = 0x080;
    const TIOCM_DSR: c_int = 0x100;

    extern "C" {
        fn open(path: *const u8, flags: c_int, ...) -> c_int;
        fn close(fd: c_int) -> c_int;
        fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
        fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
        fn cfmakeraw(t: *mut Termios);
        fn cfsetispeed(t: *mut Termios, speed: abi::Flag) -> c_int;
        fn cfsetospeed(t: *mut Termios, speed: abi::Flag) -> c_int;
        fn tcgetattr(fd: c_int, t: *mut Termios) -> c_int;
        fn tcsetattr(fd: c_int, opt: c_int, t: *const Termios) -> c_int;
        fn tcflush(fd: c_int, q: c_int) -> c_int;
        fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
        fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    }

    pub struct Port {
        fd: c_int,
        /// One writer at a time, so two callers' bytes do not interleave.
        write_lock: Mutex<()>,
    }

    fn check(rc: c_int) -> io::Result<()> {
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    impl Port {
        pub fn open(name: &str, settings: &Settings) -> io::Result<Self> {
            super::validate_name(name)?;
            super::validate_settings(settings)?;
            let mut path: Vec<u8> = name.as_bytes().to_vec();
            path.push(0);
            // O_NONBLOCK on the OPEN: without it a port whose carrier is low
            // blocks in `open` itself, before there is any way to set CLOCAL.
            let fd = unsafe { open(path.as_ptr(), O_RDWR | abi::O_NOCTTY | abi::O_NONBLOCK) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let p = Port {
                fd,
                write_lock: Mutex::new(()),
            };
            p.configure(settings)?;
            // Then BLOCKING, now CLOCAL is set: a read waits up to VTIME
            // (100 ms) for the first byte instead of returning EAGAIN at once,
            // which would spin the reader.
            let fl = unsafe { fcntl(fd, F_GETFL) };
            check(fl)?;
            check(unsafe { fcntl(fd, F_SETFL, fl & !abi::O_NONBLOCK) })?;
            // Opening a tty ASSERTS DTR and RTS, which on a CH340 board holds
            // the target in reset (see the module note). Release both. Best
            // effort: a pty has no modem lines and refuses the request.
            let _ = p.set_dtr(false);
            let _ = p.set_rts(false);
            p.purge(true, true)?;
            Ok(p)
        }

        pub fn configure(&self, s: &Settings) -> io::Result<()> {
            super::validate_settings(s)?;
            let speed = abi::baud(s.baud).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported baud {}", s.baud),
                )
            })?;
            let mut t = Termios::default();
            check(unsafe { tcgetattr(self.fd, &mut t) })?;
            unsafe { cfmakeraw(&mut t) };
            if unsafe { cfsetispeed(&mut t, speed) } != 0
                || unsafe { cfsetospeed(&mut t, speed) } != 0
            {
                return Err(io::Error::last_os_error());
            }
            // CLOCAL so a modem-control line dropping does not deliver a
            // hangup, which is the same reason the Windows side leaves DTR and
            // RTS alone; CREAD so the receiver is actually enabled.
            t.c_cflag |= abi::CLOCAL | abi::CREAD;
            t.c_cflag &= !(abi::CSIZE | abi::CSTOPB | abi::PARENB | abi::PARODD | abi::CRTSCTS);
            if let Some(m) = abi::CMSPAR {
                t.c_cflag &= !m;
            }
            t.c_cflag |= match s.data_bits {
                5 => abi::CS5,
                6 => abi::CS6,
                7 => abi::CS7,
                8 => abi::CS8,
                _ => return Err(unsupported("that data size")),
            };
            match s.stop_bits {
                StopBits::One => {}
                StopBits::Two => t.c_cflag |= abi::CSTOPB,
                StopBits::OnePointFive => return Err(unsupported("1.5 stop bits")),
            }
            match s.parity {
                Parity::None => {}
                Parity::Even => t.c_cflag |= abi::PARENB,
                Parity::Odd => t.c_cflag |= abi::PARENB | abi::PARODD,
                Parity::Mark | Parity::Space => {
                    let m = abi::CMSPAR.ok_or_else(|| unsupported("mark/space parity"))?;
                    t.c_cflag |= abi::PARENB | m;
                    if s.parity == Parity::Mark {
                        t.c_cflag |= abi::PARODD;
                    }
                }
            }
            t.c_iflag &= !(abi::IXON | abi::IXOFF | abi::IXANY);
            match s.flow {
                Flow::None => {}
                Flow::RtsCts => t.c_cflag |= abi::CRTSCTS,
                Flow::XonXoff => t.c_iflag |= abi::IXON | abi::IXOFF,
            }
            // A read returns as soon as anything is there, and after 100 ms
            // when nothing is: VTIME is in tenths.
            t.c_cc[abi::VMIN] = 0;
            t.c_cc[abi::VTIME] = 1;
            check(unsafe { tcsetattr(self.fd, TCSANOW, &t) })
        }

        pub fn read(&self, buf: &mut [u8]) -> io::Result<Read> {
            let n = unsafe { read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                // EAGAIN on a non-blocking fd is "nothing yet", not a fault.
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted {
                    return Ok(Read::Idle);
                }
                return Err(e);
            }
            if n == 0 {
                // Zero is NOT end-of-file on a tty configured VMIN=0: it is
                // the VTIME timeout expiring with nothing to read.
                Ok(Read::Idle)
            } else {
                Ok(Read::Got(n as usize))
            }
        }

        pub fn write_all(&self, mut buf: &[u8]) -> io::Result<()> {
            let _one = self.write_lock.lock().unwrap();
            while !buf.is_empty() {
                let n = unsafe { write(self.fd, buf.as_ptr().cast(), buf.len()) };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted
                    {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    }
                    return Err(e);
                }
                let written = super::written_count(n as usize)?;
                buf = &buf[written..];
            }
            Ok(())
        }

        fn modem_bits(&self, bits: c_int, on: bool) -> io::Result<()> {
            let req = if on { abi::TIOCMBIS } else { abi::TIOCMBIC };
            check(unsafe { ioctl(self.fd, req, &bits as *const c_int) })
        }

        pub fn set_dtr(&self, on: bool) -> io::Result<()> {
            self.modem_bits(TIOCM_DTR, on)
        }

        pub fn set_rts(&self, on: bool) -> io::Result<()> {
            self.modem_bits(TIOCM_RTS, on)
        }

        pub fn set_break(&self, on: bool) -> io::Result<()> {
            let req = if on { abi::TIOCSBRK } else { abi::TIOCCBRK };
            check(unsafe { ioctl(self.fd, req) })
        }

        /// CTS, DSR, RI and DCD, in the `MODEM_*` bit positions.
        pub fn modem_status(&self) -> io::Result<u8> {
            let mut m: c_int = 0;
            check(unsafe { ioctl(self.fd, abi::TIOCMGET, &mut m as *mut c_int) })?;
            let mut s = 0;
            for (bit, to) in [
                (TIOCM_CTS, MODEM_CTS),
                (TIOCM_DSR, MODEM_DSR),
                (TIOCM_RNG, MODEM_RI),
                (TIOCM_CAR, MODEM_DCD),
            ] {
                if m & bit != 0 {
                    s |= to;
                }
            }
            Ok(s)
        }

        pub fn purge(&self, rx: bool, tx: bool) -> io::Result<()> {
            let q = match (rx, tx) {
                (true, true) => abi::TCIOFLUSH,
                (true, false) => abi::TCIFLUSH,
                (false, true) => abi::TCOFLUSH,
                (false, false) => return Ok(()),
            };
            check(unsafe { tcflush(self.fd, q) })
        }
    }

    impl Drop for Port {
        fn drop(&mut self) {
            unsafe { close(self.fd) };
        }
    }

    /// The tty devices that exist now, for finding a port that came back under
    /// a different name.
    ///
    /// Reading a directory, like the Windows side reads the registry: it
    /// touches no hardware. Opening candidate ports to see which succeed would
    /// assert DTR on every adapter on the bench, and on these boards DTR is
    /// wired to reset.
    pub fn present() -> Vec<String> {
        // Linux names USB adapters ttyUSB*/ttyACM*; Darwin exposes each port
        // twice, as /dev/tty.* (blocks for carrier) and /dev/cu.* (does not),
        // and the callout device is the one a bridge wants.
        const PREFIXES: &[&str] = &[
            "ttyUSB",
            "ttyACM",
            "ttyS",
            "cu.usbserial",
            "cu.usbmodem",
            "cu.SLAB",
            "cu.wchusb",
        ];
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir("/dev") {
            for e in rd.flatten() {
                let n = e.file_name();
                let n = n.to_string_lossy();
                if PREFIXES.iter().any(|p| n.starts_with(p)) {
                    out.push(format!("/dev/{n}"));
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// Every present port with the identity of the USB adapter under it, read
    /// from sysfs: `/sys/class/tty/<name>/device` resolves into the USB tree.
    #[cfg(target_os = "linux")]
    pub fn identities() -> Vec<(String, super::Identity)> {
        present()
            .into_iter()
            .map(|name| {
                let base = name.rsplit('/').next().unwrap_or(&name).to_string();
                let link = std::path::Path::new("/sys/class/tty")
                    .join(&base)
                    .join("device");
                let id = std::fs::canonicalize(link)
                    .map(|dev| super::usb_identity_in_sysfs(&dev))
                    .unwrap_or_default();
                (name, id)
            })
            .collect()
    }

    /// USB identity is not read on macOS: every port reports no identity, so
    /// a reconnect there waits for the same name to come back.
    #[cfg(not(target_os = "linux"))]
    pub fn identities() -> Vec<(String, super::Identity)> {
        present()
            .into_iter()
            .map(|name| (name, super::Identity::default()))
            .collect()
    }
}

pub use imp::{identities, Port};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modem_line_snapshots_and_updates_share_a_lock_and_failed_updates_do_not_commit() {
        let lines = ControlLines::default();
        lines
            .set(true, true, || {
                assert!(lines.0.try_lock().is_err());
                Ok(())
            })
            .unwrap();
        assert!(lines
            .set(false, true, || Err(io::ErrorKind::PermissionDenied.into()))
            .is_err());
        lines
            .apply(|dtr, rts| {
                assert!(lines.0.try_lock().is_err());
                assert!(dtr);
                assert!(!rts);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn invalid_names_and_settings_fail_before_hardware_access() {
        for name in ["", "COM16\0suffix"] {
            assert_eq!(
                Port::open(name, &Settings::new(9600)).err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        for (baud, bits) in [(0, 8), (9600, 4), (9600, 9)] {
            let mut settings = Settings::new(baud);
            settings.data_bits = bits;
            assert_eq!(
                Port::open("nonexistent-test-port", &settings)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(
            written_count(0).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
        assert_eq!(written_count(7).unwrap(), 7);
        assert_eq!(transfer_len(7), 7);
        assert_eq!(transfer_len(usize::MAX), u32::MAX);
    }

    #[test]
    fn a_windows_serial_is_the_last_segment() {
        assert_eq!(
            serial_from_instance_id(r"USB\VID_0403&PID_6001\FT94XQ2B").as_deref(),
            Some("FT94XQ2B")
        );
    }

    #[test]
    fn a_generated_windows_segment_is_no_serial() {
        // A CH340: no iSerialNumber, so Windows builds the segment itself.
        assert_eq!(
            serial_from_instance_id(r"USB\VID_1A86&PID_7523\5&1D7F3A2&0&3"),
            None
        );
    }

    fn tree(parts: &[&str]) -> std::path::PathBuf {
        let mut root = std::env::temp_dir();
        root.push(format!(
            "serbridge-sysfs-{}-{}",
            std::process::id(),
            parts.join("-").replace(['/', ':'], "_")
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut p = root.clone();
        for part in parts {
            p.push(part);
        }
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn a_windows_interface_is_the_mi_number() {
        assert_eq!(
            interface_from_instance_id(r"USB\VID_10C4&PID_EA70&MI_01\8&2408B499&0&0001").as_deref(),
            Some("01")
        );
        assert_eq!(
            interface_from_instance_id(r"USB\VID_10C4&PID_EA70\01660305"),
            None
        );
    }

    #[test]
    fn sysfs_reads_the_usb_device_above_the_tty() {
        // The interface directory is "1-1.2:1.0" in a real sysfs; a colon is not
        // a legal file name on Windows, and the walk never reads that name.
        let tty = tree(&["usb1", "1-1", "1-1.2", "1-1.2_1.0", "ttyUSB0"]);
        let dev = tty.parent().unwrap().parent().unwrap();
        std::fs::write(dev.join("idVendor"), "0403\n").unwrap();
        std::fs::write(dev.join("serial"), "FT94XQ2B\n").unwrap();
        std::fs::write(tty.parent().unwrap().join("bInterfaceNumber"), "01\n").unwrap();
        // A hub above it also has an idVendor; the NEAREST one is the adapter.
        std::fs::write(dev.parent().unwrap().join("idVendor"), "05e3\n").unwrap();
        let id = usb_identity_in_sysfs(&tty);
        assert_eq!(id.serial.as_deref(), Some("FT94XQ2B"));
        assert_eq!(id.location.as_deref(), Some("1-1.2"));
        assert_eq!(id.interface.as_deref(), Some("01"));
    }

    #[test]
    fn sysfs_without_a_serial_file_has_only_a_location() {
        let tty = tree(&["usb2", "2-3", "2-3_1.0", "ttyUSB1"]);
        let dev = tty.parent().unwrap().parent().unwrap();
        std::fs::write(dev.join("idVendor"), "1a86\n").unwrap();
        let id = usb_identity_in_sysfs(&tty);
        assert_eq!(id.serial, None);
        assert_eq!(id.location.as_deref(), Some("2-3"));
    }

    #[test]
    fn a_tty_off_usb_has_no_identity() {
        let tty = tree(&["platform", "serial8250", "tty", "ttyS0"]);
        assert_eq!(usb_identity_in_sysfs(&tty), Identity::default());
    }
}
