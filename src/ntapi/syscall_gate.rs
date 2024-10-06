use core::arch::global_asm;

global_asm!(
    r#"
.globl do_syscall

.section .text

do_syscall:
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
    pub fn do_syscall(ssn: u16, addr: usize, n_args: u32, ...) -> i32;
}

#[cfg(target_arch = "x86_64")]
#[macro_export]
macro_rules! run_syscall {
    ($ssn:expr, $addr:expr, $($y:expr), +) => {
        {
            let mut cnt: u32 = 0;

            // Count the number of arguments passed
            $(
                let _ = $y;
                cnt += 1;
            )+

            // Perform the syscall with the given number, address (offset by 0x12),
            // argument count, and the arguments
            unsafe { $crate::ntapi::syscall_gate::do_syscall($ssn, $addr + 0x12, cnt, $($y), +) }
        }
    }
}

const UP: isize = -32; // Constant for upward memory search
const DOWN: usize = 32; // Constant for downward memory search

pub unsafe fn get_ssn(address: *mut u8) -> u16 {
    // Check if the address is null
    if address.is_null() {
        return 0;
    }

    // Hell's Gate: Check if the bytes match a typical syscall instruction sequence
    // mov r10, rcx; mov rcx, <syscall>
    if address.read() == 0x4c
        && address.add(1).read() == 0x8b
        && address.add(2).read() == 0xd1
        && address.add(3).read() == 0xb8
        && address.add(6).read() == 0x00
        && address.add(7).read() == 0x00
    {
        // Extract the syscall number from the instruction
        let high = address.add(5).read() as u16;
        let low = address.add(4).read() as u16;
        return ((high << 8) | low) as u16;
    }

    // Halo's Gate: Check if the syscall is hooked and attempt to locate a clean syscall
    if address.read() == 0xe9 {
        for idx in 1..500 {
            // Check downwards for a clean syscall instruction
            if address.add(idx * DOWN).read() == 0x4c
                && address.add(1 + idx * DOWN).read() == 0x8b
                && address.add(2 + idx * DOWN).read() == 0xd1
                && address.add(3 + idx * DOWN).read() == 0xb8
                && address.add(6 + idx * DOWN).read() == 0x00
                && address.add(7 + idx * DOWN).read() == 0x00
            {
                let high = address.add(5 + idx * DOWN).read() as u16;
                let low = address.add(4 + idx * DOWN).read() as u16;
                return (high << 8) | (low.wrapping_sub(idx as u16));
            }

            // Check upwards for a clean syscall instruction
            if address.offset(idx as isize * UP).read() == 0x4c
                && address.offset(1 + idx as isize * UP).read() == 0x8b
                && address.offset(2 + idx as isize * UP).read() == 0xd1
                && address.offset(3 + idx as isize * UP).read() == 0xb8
                && address.offset(6 + idx as isize * UP).read() == 0x00
                && address.offset(7 + idx as isize * UP).read() == 0x00
            {
                let high = address.offset(5 + idx as isize * UP).read() as u16;
                let low = address.offset(4 + idx as isize * UP).read() as u16;
                return (high << 8) | (low.wrapping_add(idx as u16));
            }
        }
    }

    // Tartarus' Gate: Another method to bypass hooked syscalls
    if address.add(3).read() == 0xe9 {
        for idx in 1..500 {
            // Check downwards for a clean syscall instruction
            if address.add(idx * DOWN).read() == 0x4c
                && address.add(1 + idx * DOWN).read() == 0x8b
                && address.add(2 + idx * DOWN).read() == 0xd1
                && address.add(3 + idx * DOWN).read() == 0xb8
                && address.add(6 + idx * DOWN).read() == 0x00
                && address.add(7 + idx * DOWN).read() == 0x00
            {
                let high = address.add(5 + idx * DOWN).read() as u16;
                let low = address.add(4 + idx * DOWN).read() as u16;
                return (high << 8) | (low.wrapping_sub(idx as u16));
            }

            // Check upwards for a clean syscall instruction
            if address.offset(idx as isize * UP).read() == 0x4c
                && address.offset(1 + idx as isize * UP).read() == 0x8b
                && address.offset(2 + idx as isize * UP).read() == 0xd1
                && address.offset(3 + idx as isize * UP).read() == 0xb8
                && address.offset(6 + idx as isize * UP).read() == 0x00
                && address.offset(7 + idx as isize * UP).read() == 0x00
            {
                let high = address.offset(5 + idx as isize * UP).read() as u16;
                let low = address.offset(4 + idx as isize * UP).read() as u16;
                return (high << 8) | (low.wrapping_add(idx as u16));
            }
        }
    }

    return 0;
}
