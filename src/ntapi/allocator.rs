use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::Ordering;
use core::sync::atomic::{AtomicBool, AtomicIsize};

use crate::common::ldrapi::{ldr_function, ldr_module};
use crate::run_syscall;

use super::syscall::NtSyscall;
use super::syscall_gate::get_ssn;

// Atomic flag contains the last status of an NT syscall.
pub static NT_ALLOCATOR_STATUS: AtomicIsize = AtomicIsize::new(0);

// Atomic flag to ensure initialization happens only once.
static INIT: AtomicBool = AtomicBool::new(false);

// Static variables to hold the configuration and syscall information, wrapped in UnsafeCell for interior mutability.
static mut NT_ALLOCATE_VIRTUAL_MEMORY_SYSCALL: UnsafeCell<Option<NtSyscall>> =
    UnsafeCell::new(None);

static mut NT_FREE_VIRTUAL_MEMORY_SYSCALL: UnsafeCell<Option<NtSyscall>> = UnsafeCell::new(None);

/// Unsafe function to perform the initialization of the static variables.
/// This includes locating and storing the addresses and syscall numbers for `NtAllocateVirtualMemory` and `NtFreeVirtualMemory`.
pub unsafe fn initialize() {
    // Check if initialization has already occurred.
    if !INIT.load(Ordering::Acquire) {
        // Get the address of ntdll module in memory.
        let ntdll_address = ldr_module(0x1edab0ed);

        // Initialize the syscall for NtAllocateVirtualMemory.
        let alloc_syscall_address = ldr_function(ntdll_address, 0xf783b8ec);
        let alloc_syscall = NtSyscall {
            address: alloc_syscall_address,
            number: get_ssn(alloc_syscall_address),
            hash: 0xf783b8ec,
        };

        *NT_ALLOCATE_VIRTUAL_MEMORY_SYSCALL.get() = Some(alloc_syscall);

        // Initialize the syscall for NtFreeVirtualMemory.
        let free_syscall_address = ldr_function(ntdll_address, 0x2802c609);
        let free_syscall = NtSyscall {
            address: free_syscall_address,
            number: get_ssn(free_syscall_address),
            hash: 0x2802c609,
        };

        *NT_FREE_VIRTUAL_MEMORY_SYSCALL.get() = Some(free_syscall);

        // Set the initialization flag to true.
        INIT.store(true, Ordering::Release);
    }
}

/// Function to ensure that initialization is performed if it hasn't been already.
fn ensure_initialized() {
    unsafe {
        if !INIT.load(Ordering::Acquire) {
            initialize();
        }
    }
}

/// Function to get a reference to the NtAllocateVirtualMemory syscall, ensuring initialization first.
fn get_nt_allocate_virtual_memory_syscall() -> &'static NtSyscall {
    ensure_initialized();
    unsafe {
        NT_ALLOCATE_VIRTUAL_MEMORY_SYSCALL
            .get()
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
    }
}

/// Function to get a reference to the NtFreeVirtualMemory syscall, ensuring initialization first.
fn get_nt_free_virtual_memory_syscall() -> &'static NtSyscall {
    ensure_initialized();
    unsafe {
        NT_FREE_VIRTUAL_MEMORY_SYSCALL
            .get()
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
    }
}

/// Custom allocator using NT system calls.
pub struct NtVirtualAlloc;

unsafe impl GlobalAlloc for NtVirtualAlloc {
    /// Allocates memory as described by the given `layout` using NT system calls.
    ///
    /// This function uses the `NtAllocateVirtualMemory` system call to allocate memory.
    /// The memory is allocated with `PAGE_READWRITE` protection, which allows both
    /// reading and writing. This is appropriate for most use cases like vectors and strings.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Pointer to the allocated memory.
        let mut p_address: *mut c_void = null_mut();
        // Size of the memory to allocate.
        let region_size = layout.size();
        // Handle to the current process (-1).
        let h_process: *mut u8 = -1isize as _;

        let alloc_syscall = get_nt_allocate_virtual_memory_syscall();

        let ntstatus = run_syscall!(
            (*alloc_syscall).number,
            (*alloc_syscall).address as usize,
            h_process,
            &mut p_address,
            0,
            &mut (region_size as usize) as *mut usize,
            0x3000, // MEM_COMMIT | MEM_RESERVE
            0x04    // PAGE_READWRITE
        );

        NT_ALLOCATOR_STATUS.store(ntstatus as isize, Ordering::SeqCst);

        // If the allocation fails, return null; otherwise, return the allocated address.
        p_address as *mut u8
    }

    /// Deallocates the block of memory at the given `ptr` pointer with the given `layout` using NT system calls.
    ///
    /// This function uses the `NtFreeVirtualMemory` system call to deallocate memory.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Size of the memory to deallocate.
        let mut region_size = layout.size();
        // Handle to the current process (-1).
        let h_process: *mut u8 = -1isize as _;

        let free_syscall = get_nt_free_virtual_memory_syscall();

        let ntstatus = run_syscall!(
            (*free_syscall).number,
            (*free_syscall).address as usize,
            h_process,
            &mut (ptr as *mut c_void),
            &mut region_size,
            0x8000 // MEM_RELEASE
        );

        NT_ALLOCATOR_STATUS.store(ntstatus as isize, Ordering::SeqCst);
    }
}
