## **RustiveDump**

**RustiveDump** is a Rust-based tool designed to dump the memory of the **lsass.exe** process using **only NT system calls**.

It creates a minimal minidump file from scratch, containing essential components like **SystemInfo**, **ModuleList**, and **Memory64List**, with support for **XOR encryption** and **remote transmission**.

This project is a personal learning experience, focusing on leveraging native Windows APIs for memory dumping and building a minimalistic minidump file entirely from the ground up.

## **Key Features**

1. **NT System Calls for Everything**  
   RustiveDump bypasses standard APIs and leverages NT system calls for all its operations.

2. **No-Std and CRT-Independent**:  
   RustiveDump is built using Rust's `no_std` feature, which removes reliance on Rust's standard library, and it's also **CRT library independent**. This resulting in a lean release build of only **18KB**.

3. **Indirect NT Syscalls**:  
   The tool uses indirect syscalls, retrieving system service numbers (SSN) with techniques like **Hell’s Gate**, **Halo's Gate**, and **Tartarus' Gate**.

4. **Lean Memory Dump**:  
   RustiveDump generates a focused memory dump, containing only essential data (i.e., **SystemInfo**, **ModuleList**, and **Memory64List**), ensuring no bloated files—just enough to feed your memory analysis tools like **Mimikatz** or **Pypykatz**.

5. **XOR Encryption**:  
   RustiveDump can encrypt the dump file using XOR before saving or transmitting it, adding an extra layer of security to the dumped memory.

6. **Remote File Transmission**:  
   The dump file can be sent directly to a remote server using **winsock** APIs calls

7. **Verbose Mode**:  
   The verbose mode provides detailed logs of each step, which can be enabled during the build process.

## **How it works**

1. **Enable SeDebugPrivilege**:  
   RustiveDump uses `NtOpenProcessToken` and `NtAdjustPrivilegesToken` to enable **SeDebugPrivilege**, allowing access to protected processes like **lsass.exe**.

2. **LSASS Process Access**:  
   The tool locates the **lsass.exe** process by querying `NtQuerySystemInformation` to get a snapshot of active processes, and then opens a process handle using `NtOpenProcess` with the `PROCESS_QUERY_INFORMATION` and `PROCESS_VM_READ` access rights.

3. **Memory Regions Handling**:  
   RustiveDump scans through the memory regions of the process using `NtQueryVirtualMemory` and dumps committed and accessible memory using `NtReadVirtualMemory`.

4. **Module Information**:  
   RustiveDump retrieves a list of modules loaded by **lsass.exe** using `NtQueryInformationProcess` to extract the **ModuleList** from the remote PEB (Process Environment Block).

5. **Memory Dump Creation**:  
   The dump is saved locally using `NtCreateFile` and `NtWriteFile`, or sent to a remote server. If desired, the dump can also be encrypted with XOR before being saved or transmitted.

## **Build**

RustiveDump offers several configurable build options through **cargo make** to customize the behavior of the tool. You can enable features like **XOR encryption**, **remote file transmission** and **verbose logging**.

**Available Features:**

- **xor**: Encrypts the dump file using XOR encryption.
- **verbose**: Enables detailed logs for each step of the process.
- **remote**: Sends the dump file to a remote server via Winsock.
- **lsasrv**: Filters the memory dump to include only the `lsasrv.dll` module from **lsass.exe**.

### **Build Options**

To build RustiveDump with different combinations of features, use the following commands:

- **Basic build** (save dump locally without additional features):

  ```bash
  cargo make
  ```

- **Build with specific features**
  ```bash
  cargo make --env FEATURES=xor,remote,lsasrv,verbose
  ```
  
## **Memory Dump File Structure**

RustiveDump generates a minimalistic minidump file, including only the essential components for tools like **Mimikatz** and **Pypykatz**. The file consists of three core streams:

1. **SystemInfo Stream**: OS version and architecture details.
2. **ModuleList Stream**: Lists modules loaded in **lsass.exe**.
3. **Memory64List Stream**: Memory regions from **lsass.exe**.

For more details on the Minidump file structure, see: [Minidump (MDMP) format documentation](<https://github.com/libyal/libmdmp/blob/main/documentation/Minidump%20(MDMP)%20format.asciidoc>).

## Disclaimer

This project is intended **for educational and research purposes only**. RustiveDump is a minimalist memory dumper built for learning purposes. Use it responsibly, and remember, if you misuse it, that’s on you—not me!

Always follow ethical guidelines and legal frameworks when doing security research (and, you know, just in general).

## **Credits**

- Inspired by [NativeDump](https://github.com/ricardojoserf/NativeDump). Thanks to the author for sharing their work.

## **Contributions**

Contributions are welcome! If you want to help improve RustiveDump or report bugs, feel free to open an issue or a pull request in the repository.

---
