use core::{
    alloc::{GlobalAlloc, Layout},
    ffi::c_void,
    ptr::null_mut,
};

use crate::{instance::get_instance, run_syscall};

pub struct NtVirtualAlloc;

unsafe impl GlobalAlloc for NtVirtualAlloc {
    /// Allocates memory as described by the given `layout` using NT system calls.
    ///
    /// This function uses the `NtAllocateVirtualMemory` system call to allocate memory.
    /// The memory is allocated with `PAGE_READWRITE` protection, which allows both
    /// reading and writing.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Pointer to the allocated memory.
        let mut p_address: *mut c_void = null_mut();
        // Size of the memory to allocate.
        let region_size = layout.size();
        // Handle to the current process (-1).
        let h_process: *mut u8 = -1isize as _;

        if let Some(instance) = get_instance() {
            run_syscall!(
                instance.ntdll.nt_allocate_virtual_memory.syscall.number,
                instance.ntdll.nt_allocate_virtual_memory.syscall.address as usize,
                h_process,
                &mut p_address,
                0,
                &mut (region_size as usize) as *mut usize,
                0x3000, // MEM_COMMIT | MEM_RESERVE
                0x04    // PAGE_READWRITE
            );
        }

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

        if let Some(instance) = get_instance() {
            run_syscall!(
                instance.ntdll.nt_free_virtual_memory.syscall.number,
                instance.ntdll.nt_free_virtual_memory.syscall.address as usize,
                h_process,
                &mut (ptr as *mut c_void),
                &mut region_size,
                0x8000 // MEM_RELEASE
            );
        }
    }
}
