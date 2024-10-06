use core::ffi::c_void;
use core::{
    cell::UnsafeCell,
    ptr::null_mut,
    sync::atomic::{AtomicBool, Ordering},
};

use super::ldrapi::{ldr_function, ldr_module};

pub type WriteFile = unsafe extern "system" fn(
    hFile: *mut c_void,
    lpBuffer: *const u8,
    nNumberOfBytesToWrite: u32,
    lpNumberOfBytesWritten: *mut u32,
    lpOverlapped: *mut c_void,
) -> i32;

#[repr(C)]
pub struct K32 {
    pub write_file: WriteFile,
}

impl K32 {
    pub fn new() -> Self {
        K32 {
            write_file: unsafe { core::mem::transmute(null_mut::<c_void>()) },
        }
    }
}

static INIT_K32: AtomicBool = AtomicBool::new(false);

pub static mut K32_G: UnsafeCell<Option<K32>> = UnsafeCell::new(None);

pub unsafe fn k32() -> &'static K32 {
    ensure_initialized();
    return K32_G.get().as_ref().unwrap().as_ref().unwrap();
}

/// Function to ensure that initialization is performed if it hasn't been already.
fn ensure_initialized() {
    unsafe {
        if !INIT_K32.load(Ordering::Acquire) {
            init_k32();
        }
    }
}

unsafe fn init_k32() {
    if !INIT_K32.load(Ordering::Acquire) {
        let mut k32 = K32::new();

        // Resolve the base address of `kernel32.dll` using its hash (0x6ddb9555).
        let kernel32_base = ldr_module(0x6ddb9555);

        // Resolve the address of `WriteFile` function from `kernel32.dll` using its hash (0xf1d207d0).
        let k_write_file_addr = ldr_function(kernel32_base, 0xf1d207d0);

        // Cast the resolved address to a callable function of type `WriteFile`.
        k32.write_file = core::mem::transmute(k_write_file_addr);

        *K32_G.get() = Some(k32);

        INIT_K32.store(true, Ordering::Release);
    }
}
/// Global mutable instance of the agent.

/// Implements a low-level `_write` function that writes data to a file descriptor (typically `stdout` or `stderr`).
/// This function resolves the `WriteFile` function from `kernel32.dll` and uses it to perform the actual write.
#[no_mangle]
extern "C" fn _write(_fd: i32, buf: *const u8, count: usize) -> isize {
    unsafe {
        let mut written: u32 = 0; // Variable to store the number of bytes written.
        let handle = -11i32 as u32; // File handle for `stdout` or `stderr` (often -11 represents `stdout` on Windows).

        // Call `WriteFile` with the handle, buffer, and count of bytes to write.
        let ntstatus = (k32().write_file)(
            handle as *mut c_void, // File handle
            buf,                   // Buffer containing the data to write
            count as u32,          // Number of bytes to write
            &mut written, // Pointer to the variable that will receive the number of bytes written
            core::ptr::null_mut(), // No overlapped structure
        );

        // Return the number of bytes written or an error code (if `ntstatus` is negative).
        if ntstatus < 0 {
            ntstatus as isize
        } else {
            written as isize
        }
    }
}
