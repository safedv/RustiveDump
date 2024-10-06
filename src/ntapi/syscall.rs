use core::{
    ffi::{c_ulong, c_void},
    ptr::null_mut,
};

use crate::{
    ntapi::def::{AccessMask, IoStatusBlock, LargeInteger, ObjectAttributes, UnicodeString},
    run_syscall,
};

use super::def::TokenPrivileges;

pub struct NtSyscall {
    /// The number of the syscall
    pub number: u16,
    /// The address of the syscall
    pub address: *mut u8,
    /// The hash of the syscall
    pub hash: usize,
}

unsafe impl Sync for NtSyscall {}

impl NtSyscall {
    pub const fn new(hash: usize) -> Self {
        NtSyscall {
            number: 0,
            address: null_mut(),
            hash: hash,
        }
    }
}

pub struct NtAllocateVirtualMemory {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtAllocateVirtualMemory {}

impl NtAllocateVirtualMemory {
    pub const fn new() -> Self {
        NtAllocateVirtualMemory {
            syscall: NtSyscall::new(0xf783b8ec),
        }
    }
}

pub struct NtFreeVirtualMemory {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtFreeVirtualMemory {}

impl NtFreeVirtualMemory {
    pub const fn new() -> Self {
        NtFreeVirtualMemory {
            syscall: NtSyscall::new(0x2802c609),
        }
    }
}

pub struct NtReadVirtualMemory {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtReadVirtualMemory {}

impl NtReadVirtualMemory {
    pub const fn new() -> Self {
        NtReadVirtualMemory {
            syscall: NtSyscall::new(0xa3288103),
        }
    }

    /// Wrapper for the NtReadVirtualMemory syscall.
    ///
    /// This function reads memory in the virtual address space of a specified process.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `process_handle` A handle to the process whose memory is to be read.
    /// * `[in]` - `base_address` A pointer to the base address in the specified process from which to read.
    /// * `[out]` - `buffer` A pointer to a buffer that receives the contents from the address space of the specified process.
    /// * `[in]` - `buffer_size` The number of bytes to be read into the buffer.
    /// * `[out, opt]` - `number_of_bytes_read` A pointer to a variable that receives the number of bytes transferred into the buffer.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub fn run(
        &self,
        process_handle: *mut c_void,
        base_address: *const c_void,
        buffer: *mut c_void,
        buffer_size: usize,
        number_of_bytes_read: *mut usize,
    ) -> i32 {
        run_syscall!(
            self.syscall.number,
            self.syscall.address as usize,
            process_handle,
            base_address,
            buffer,
            buffer_size,
            number_of_bytes_read
        )
    }
}

pub struct NtQueryVirtualMemory {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtQueryVirtualMemory {}

impl NtQueryVirtualMemory {
    pub const fn new() -> Self {
        NtQueryVirtualMemory {
            syscall: NtSyscall::new(0x10c0e85d),
        }
    }

    /// Wrapper for the NtQueryVirtualMemory syscall.
    ///
    /// This function queries information about the virtual memory of a specified process.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `process_handle` A handle to the process whose virtual memory is to be queried.
    /// * `[in]` - `base_address` A pointer to the base address in the process's virtual memory space.
    /// * `[in]` - `memory_information_class` Specifies the type of information to be queried (e.g., MemoryBasicInformation).
    /// * `[out]` - `memory_information` A pointer to a buffer that receives the information about the memory.
    /// * `[in]` - `memory_information_length` The size, in bytes, of the buffer pointed to by `memory_information`.
    /// * `[out, opt]` - `return_length` A pointer to a variable that receives the number of bytes returned.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub fn run(
        &self,
        process_handle: *mut c_void,
        base_address: *const c_void,
        memory_information_class: u32,
        memory_information: *mut c_void,
        memory_information_length: usize,
        return_length: *mut usize,
    ) -> i32 {
        run_syscall!(
            self.syscall.number,
            self.syscall.address as usize,
            process_handle,
            base_address,
            memory_information_class as usize,
            memory_information,
            memory_information_length,
            return_length
        )
    }
}

pub struct NtOpenProcess {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtOpenProcess {}

impl NtOpenProcess {
    pub const fn new() -> Self {
        NtOpenProcess {
            syscall: NtSyscall::new(0x4b82f718),
        }
    }

    /// Wrapper for the NtOpenProcess syscall.
    ///
    /// # Arguments
    ///
    /// * `[out]` - `process_handle` A mutable pointer to a handle that will receive the process handle.
    /// * `[in]` - `desired_access` The desired access for the process.
    /// * `[in]` - `object_attributes` A pointer to the object attributes structure.
    /// * `[in, opt]` - `client_id` A pointer to the client ID structure.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub fn run(
        &self,
        process_handle: &mut *mut c_void,
        desired_access: AccessMask,
        object_attributes: &mut ObjectAttributes,
        client_id: *mut c_void,
    ) -> i32 {
        run_syscall!(
            self.syscall.number,
            self.syscall.address as usize,
            process_handle,
            desired_access,
            object_attributes as *mut _ as *mut c_void,
            client_id
        )
    }
}

pub struct NtQuerySystemInformation {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtQuerySystemInformation {}

impl NtQuerySystemInformation {
    pub const fn new() -> Self {
        NtQuerySystemInformation {
            syscall: NtSyscall::new(0x7bc23928),
        }
    }

    /// Wrapper for the NtQuerySystemInformation syscall.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `system_information_class` The system information class to be queried.
    /// * `[out]` - `system_information` A pointer to a buffer that receives the requested information.
    /// * `[in]` - `system_information_length` The size, in bytes, of the buffer pointed to by the `system_information` parameter.
    /// * `[out, opt]` - `return_length` A pointer to a variable that receives the size, in bytes, of the data returned.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub fn run(
        &self,
        system_information_class: u32,
        system_information: *mut c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> i32 {
        run_syscall!(
            self.syscall.number,
            self.syscall.address as usize,
            system_information_class,
            system_information,
            system_information_length,
            return_length
        )
    }
}

pub struct NtQueryInformationProcess {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtQueryInformationProcess {}

impl NtQueryInformationProcess {
    pub const fn new() -> Self {
        NtQueryInformationProcess {
            syscall: NtSyscall::new(0x8cdc5dc2),
        }
    }

    /// Wrapper for the NtQueryInformationProcess syscall.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `process_handle` A handle to the process.
    /// * `[in]` - `process_information_class` The class of information to be queried.
    /// * `[out]` - `process_information` A pointer to a buffer that receives the requested information.
    /// * `[in]` - `process_information_length` The size, in bytes, of the buffer pointed to by the `process_information` parameter.
    /// * `[out, opt]` - `return_length` A pointer to a variable that receives the size, in bytes, of the data returned.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub fn run(
        &self,
        process_handle: *mut c_void,
        process_information_class: u32,
        process_information: *mut c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32 {
        run_syscall!(
            self.syscall.number,
            self.syscall.address as usize,
            process_handle,
            process_information_class,
            process_information,
            process_information_length,
            return_length
        )
    }
}

pub struct NtWriteFile {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtWriteFile {}

impl NtWriteFile {
    pub const fn new() -> Self {
        NtWriteFile {
            syscall: NtSyscall::new(0xe0d61db2),
        }
    }

    /// Wrapper for the NtWriteFile syscall.
    ///
    /// This function writes data to a file or I/O device. It wraps the NtWriteFile syscall.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `file_handle` A handle to the file or I/O device to be written to.
    /// * `[in, opt]` - `event` An optional handle to an event object that will be signaled when the operation completes.
    /// * `[in, opt]` - `apc_routine` An optional pointer to an APC routine to be called when the operation completes.
    /// * `[in, opt]` - `apc_context` An optional pointer to a context for the APC routine.
    /// * `[out]` - `io_status_block` A pointer to an IO_STATUS_BLOCK structure that receives the final completion status and information about the operation.
    /// * `[in]` - `buffer` A pointer to a buffer that contains the data to be written to the file or device.
    /// * `[in]` - `length` The length, in bytes, of the buffer pointed to by the `buffer` parameter.
    /// * `[in, opt]` - `byte_offset` A pointer to the byte offset in the file where the operation should begin. If this parameter is `None`, the system writes data to the current file position.
    /// * `[in, opt]` - `key` A pointer to a caller-supplied variable to receive the I/O completion key. This parameter is ignored if `event` is not `None`.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    #[allow(dead_code)]
    pub fn run(
        &self,
        file_handle: *mut c_void,
        event: *mut c_void,
        apc_routine: *mut c_void,
        apc_context: *mut c_void,
        io_status_block: &mut IoStatusBlock,
        buffer: *mut c_void,
        length: c_ulong,
        byte_offset: *mut u64,
        key: *mut c_ulong,
    ) -> i32 {
        run_syscall!(
            self.syscall.number,
            self.syscall.address as usize,
            file_handle,
            event,
            apc_routine,
            apc_context,
            io_status_block,
            buffer,
            length,
            byte_offset,
            key
        )
    }
}

pub struct NtCreateFile {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtCreateFile {}

impl NtCreateFile {
    pub const fn new() -> Self {
        NtCreateFile {
            syscall: NtSyscall::new(0x66163fbb),
        }
    }

    /// Wrapper for the NtCreateFile syscall.
    ///
    /// This function creates or opens a file or I/O device. It wraps the NtCreateFile syscall.
    ///
    /// # Arguments
    ///
    /// * `[out]` - `file_handle` A mutable pointer to a handle that will receive the file handle.
    /// * `[in]` - `desired_access` The access to the file or device, which can be read, write, or both.
    /// * `[in]` - `obj_attributes` A pointer to an OBJECT_ATTRIBUTES structure that specifies the object name and other attributes.
    /// * `[out]` - `io_status_block` A pointer to an IO_STATUS_BLOCK structure that receives the final completion status and information about the operation.
    /// * `[in, opt]` - `allocation_size` A pointer to a LARGE_INTEGER that specifies the initial allocation size in bytes. If this parameter is `None`, the file is allocated with a default size.
    /// * `[in]` - `file_attributes` The file attributes for the file or device if it is created.
    /// * `[in]` - `share_access` The requested sharing mode of the file or device.
    /// * `[in]` - `create_disposition` The action to take depending on whether the file or device already exists.
    /// * `[in]` - `create_options` Options to be applied when creating or opening the file or device.
    /// * `[in, opt]` - `ea_buffer` A pointer to a buffer that contains the extended attributes (EAs) for the file or device. This parameter is optional.
    /// * `[in]` - `ea_length` The length, in bytes, of the EaBuffer parameter.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    #[allow(dead_code)]
    pub fn run(
        &self,
        file_handle: &mut *mut c_void,
        desired_access: u32,
        obj_attributes: &mut ObjectAttributes,
        io_status_block: &mut IoStatusBlock,
        allocation_size: *mut LargeInteger,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *mut c_void,
        ea_length: u32,
    ) -> i32 {
        run_syscall!(
            self.syscall.number,
            self.syscall.address as usize,
            file_handle,
            desired_access,
            obj_attributes,
            io_status_block,
            allocation_size,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            ea_buffer,
            ea_length
        )
    }
}

pub struct NtClose {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtClose {}

impl NtClose {
    pub const fn new() -> Self {
        NtClose {
            syscall: NtSyscall::new(0x40d6e69d),
        }
    }

    /// Wrapper function for NtClose to avoid repetitive run_syscall calls.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `handle` A handle to an object. This is a required parameter that must be valid.
    ///   It represents the handle that will be closed by the function.
    ///
    /// # Returns
    ///
    /// * `true` if the operation was successful, `false` otherwise.
    ///   The function returns an NTSTATUS code; however, in this wrapper, the result is simplified to a boolean.
    #[allow(dead_code)]
    pub fn run(&self, handle: *mut c_void) -> i32 {
        run_syscall!(self.syscall.number, self.syscall.address as usize, handle)
    }
}

pub struct NtOpenProcessToken {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtOpenProcessToken {}

impl NtOpenProcessToken {
    pub const fn new() -> Self {
        NtOpenProcessToken {
            syscall: NtSyscall::new(0x350dca99),
        }
    }

    /// Wrapper for the NtOpenProcessToken syscall.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `process_handle` The handle of the process whose token is to be opened.
    /// * `[in]` - `desired_access` The desired access for the token.
    /// * `[out]` - `token_handle` A mutable pointer to a handle that will receive the token handle.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub fn run(
        &self,
        process_handle: *mut c_void,
        desired_access: AccessMask,
        token_handle: &mut *mut c_void,
    ) -> i32 {
        run_syscall!(
            self.syscall.number,
            self.syscall.address as usize,
            process_handle,
            desired_access,
            token_handle
        )
    }
}

pub struct NtAdjustPrivilegesToken {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtAdjustPrivilegesToken {}

impl NtAdjustPrivilegesToken {
    pub const fn new() -> Self {
        NtAdjustPrivilegesToken {
            syscall: NtSyscall::new(0x2dbc736d),
        }
    }
    /// Wrapper for the NtAdjustPrivilegesToken syscall.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `token_handle` The handle of the token to be adjusted.
    /// * `[in]` - `disable_all_privileges` Boolean to disable all privileges.
    /// * `[in, opt]` - `new_state` A pointer to a TOKEN_PRIVILEGES structure.
    /// * `[in]` - `buffer_length` The length of the buffer for previous privileges.
    /// * `[out, opt]` - `previous_state` A pointer to a buffer that receives the previous state.
    /// * `[out, opt]` - `return_length` A pointer to a variable that receives the length of the previous state.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub fn run(
        &self,
        token_handle: *mut c_void,
        disable_all_privileges: bool,
        new_state: *mut TokenPrivileges,
        buffer_length: u32,
        previous_state: *mut TokenPrivileges,
        return_length: *mut u32,
    ) -> i32 {
        run_syscall!(
            self.syscall.number,
            self.syscall.address as usize,
            token_handle,
            disable_all_privileges as i32,
            new_state,
            buffer_length,
            previous_state,
            return_length
        )
    }
}

/// Type definition for the LdrLoadDll function.
///
/// Loads a DLL into the address space of the calling process.
///
/// # Parameters
/// - `[in, opt]` - `DllPath`: A pointer to a `UNICODE_STRING` that specifies the fully qualified path of the DLL to load. This can be `NULL`, in which case the system searches for the DLL.
/// - `[in, opt]` - `DllCharacteristics`: A pointer to a variable that specifies the DLL characteristics (optional, can be `NULL`).
/// - `[in]` - `DllName`: A `UNICODE_STRING` that specifies the name of the DLL to load.
/// - `[out]` - `DllHandle`: A pointer to a variable that receives the handle to the loaded DLL.
///
/// # Returns
/// - `i32` - The NTSTATUS code of the operation.
type LdrLoadDll = unsafe extern "system" fn(
    DllPath: *mut u16,
    DllCharacteristics: *mut u32,
    DllName: UnicodeString,
    DllHandle: *mut c_void,
) -> i32;

pub struct NtDll {
    pub module_base: *mut u8,
    pub ldr_load_dll: LdrLoadDll,
    pub nt_allocate_virtual_memory: NtAllocateVirtualMemory,
    pub nt_free_virtual_memory: NtFreeVirtualMemory,
    pub nt_read_virtual_memory: NtReadVirtualMemory,
    pub nt_query_virtual_memory: NtQueryVirtualMemory,
    pub nt_open_process: NtOpenProcess,
    pub nt_query_system_information: NtQuerySystemInformation,
    pub nt_query_information_process: NtQueryInformationProcess,
    pub nt_create_file: NtCreateFile,
    pub nt_write_file: NtWriteFile,
    pub nt_close: NtClose,
    pub nt_open_process_token: NtOpenProcessToken,
    pub nt_adjust_privileges_token: NtAdjustPrivilegesToken,
}

impl NtDll {
    pub fn new() -> Self {
        NtDll {
            module_base: null_mut(),
            ldr_load_dll: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            nt_allocate_virtual_memory: NtAllocateVirtualMemory::new(),
            nt_free_virtual_memory: NtFreeVirtualMemory::new(),
            nt_read_virtual_memory: NtReadVirtualMemory::new(),
            nt_query_virtual_memory: NtQueryVirtualMemory::new(),
            nt_open_process: NtOpenProcess::new(),
            nt_query_system_information: NtQuerySystemInformation::new(),
            nt_query_information_process: NtQueryInformationProcess::new(),
            nt_create_file: NtCreateFile::new(),
            nt_write_file: NtWriteFile::new(),
            nt_close: NtClose::new(),
            nt_open_process_token: NtOpenProcessToken::new(),
            nt_adjust_privileges_token: NtAdjustPrivilegesToken::new(),
        }
    }
}
