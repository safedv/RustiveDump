use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};

use super::syscall_gate::get_ssn;

use crate::{
    common::ldrapi::{ldr_function, ldr_module},
    ntapi::syscall::NtDll,
};

#[repr(C)]
pub struct Instance {
    pub ntdll: NtDll, // NtDll API functions
}

impl Instance {
    pub fn new() -> Self {
        Instance {
            ntdll: NtDll::new(),
        }
    }
}

static INIT_INSTANCE: AtomicBool = AtomicBool::new(false);

pub static mut INSTANCE: UnsafeCell<Option<Instance>> = UnsafeCell::new(None);

/// Retrieves a reference to the global instance.
pub unsafe fn instance() -> &'static Instance {
    ensure_initialized();
    return INSTANCE.get().as_ref().unwrap().as_ref().unwrap();
}

/// Function to ensure that initialization is performed if it hasn't been already.
fn ensure_initialized() {
    unsafe {
        if !INIT_INSTANCE.load(Ordering::Acquire) {
            init_native();
        }
    }
}

unsafe fn init_native() {
    if !INIT_INSTANCE.load(Ordering::Acquire) {
        let mut instance = Instance::new();

        const NTDLL_HASH: u32 = 0x1edab0ed;

        instance.ntdll.module_base = ldr_module(NTDLL_HASH);

        // Resolve LdrLoadDll
        let ldr_load_dll_addr = ldr_function(instance.ntdll.module_base, 0x9e456a43);
        instance.ntdll.ldr_load_dll = core::mem::transmute(ldr_load_dll_addr);

        // NtAllocateVirtualMemory
        instance.ntdll.nt_allocate_virtual_memory.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_allocate_virtual_memory.syscall.hash,
        );
        instance.ntdll.nt_allocate_virtual_memory.syscall.number =
            get_ssn(instance.ntdll.nt_allocate_virtual_memory.syscall.address);

        // NtFreeVirtualMemory
        instance.ntdll.nt_free_virtual_memory.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_free_virtual_memory.syscall.hash,
        );
        instance.ntdll.nt_free_virtual_memory.syscall.number =
            get_ssn(instance.ntdll.nt_free_virtual_memory.syscall.address);

        // NtReadVirtualMemory
        instance.ntdll.nt_read_virtual_memory.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_read_virtual_memory.syscall.hash,
        );
        instance.ntdll.nt_read_virtual_memory.syscall.number =
            get_ssn(instance.ntdll.nt_read_virtual_memory.syscall.address);

        // NtQueryVirtualMemory
        instance.ntdll.nt_query_virtual_memory.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_query_virtual_memory.syscall.hash,
        );
        instance.ntdll.nt_query_virtual_memory.syscall.number =
            get_ssn(instance.ntdll.nt_query_virtual_memory.syscall.address);

        // NtOpenProcess
        instance.ntdll.nt_open_process.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_open_process.syscall.hash,
        );
        instance.ntdll.nt_open_process.syscall.number =
            get_ssn(instance.ntdll.nt_open_process.syscall.address);

        // NtQuerySystemInformation
        instance.ntdll.nt_query_system_information.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_query_system_information.syscall.hash,
        );
        instance.ntdll.nt_query_system_information.syscall.number =
            get_ssn(instance.ntdll.nt_query_system_information.syscall.address);

        // NtQueryInformationProcess
        instance.ntdll.nt_query_information_process.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_query_information_process.syscall.hash,
        );
        instance.ntdll.nt_query_information_process.syscall.number =
            get_ssn(instance.ntdll.nt_query_information_process.syscall.address);

        // NtCreateFile
        instance.ntdll.nt_create_file.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_create_file.syscall.hash,
        );
        instance.ntdll.nt_create_file.syscall.number =
            get_ssn(instance.ntdll.nt_create_file.syscall.address);

        // NtWriteFile
        instance.ntdll.nt_write_file.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_write_file.syscall.hash,
        );
        instance.ntdll.nt_write_file.syscall.number =
            get_ssn(instance.ntdll.nt_write_file.syscall.address);

        // NtClose
        instance.ntdll.nt_close.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_close.syscall.hash,
        );
        instance.ntdll.nt_close.syscall.number = get_ssn(instance.ntdll.nt_close.syscall.address);

        // NtOpenProcessToken
        instance.ntdll.nt_open_process_token.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_open_process_token.syscall.hash,
        );
        instance.ntdll.nt_open_process_token.syscall.number =
            get_ssn(instance.ntdll.nt_open_process_token.syscall.address);

        // NtAdjustPrivilegesToken
        instance.ntdll.nt_adjust_privileges_token.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_adjust_privileges_token.syscall.hash,
        );
        instance.ntdll.nt_adjust_privileges_token.syscall.number =
            get_ssn(instance.ntdll.nt_adjust_privileges_token.syscall.address);

        *INSTANCE.get() = Some(instance);

        // Set the initialization flag to true.
        INIT_INSTANCE.store(true, Ordering::Release);
    }
}
