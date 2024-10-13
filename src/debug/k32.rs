use core::{ffi::c_void, ptr::null_mut};

use crate::{
    common::ldrapi::{ldr_function, ldr_module},
    get_instance,
};

pub type WriteFile = unsafe extern "system" fn(
    hFile: *mut c_void,
    lpBuffer: *const c_void,
    nNumberOfBytesToWrite: u32,
    lpNumberOfBytesWritten: *mut u32,
    lpOverlapped: *mut c_void,
) -> i32;

pub struct Kernel32 {
    pub module_hash: u32,
    pub module_base: *mut u8,
    pub write_file: WriteFile,
}

impl Kernel32 {
    pub fn new() -> Self {
        Kernel32 {
            module_hash: 0x6ddb9555,
            module_base: null_mut(),
            write_file: unsafe { core::mem::transmute(null_mut::<c_void>()) },
        }
    }
}

unsafe impl Sync for Kernel32 {}
unsafe impl Send for Kernel32 {}

pub fn init_kernel32_funcs() {
    unsafe {
        let instance = get_instance().unwrap();

        //Kernel32.dll
        instance.k32.module_base = ldr_module(instance.k32.module_hash);

        //WriteFile
        let k_write_file_addr = ldr_function(instance.k32.module_base, 0xf1d207d0);
        instance.k32.write_file = core::mem::transmute(k_write_file_addr);
    }
}
