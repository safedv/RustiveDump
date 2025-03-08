# CHANGELOG

## **[0.1.2]** - 2025-03-08

### Features:

- **MSVC Support (PIC)**: RustiveDump can now be compiled using the MSVC toolchain as **Position Independent Code (PIC)**, allowing for more flexibility in cross-compilation scenarios.
- **Smaller Shellcode Size**: With the optimizations for MSVC, the shellcode size has been reduced to **14KB** when enabling features like **xor** and **remote**.
- **Updated to Rust 2024 Edition**: RustiveDump now supports the **Rust 2024 edition**.

---

## **[0.1.1]** - 2024-10-14

### Features:

- **Position Independent Code (PIC)**: RustiveDump can now be compiled as **Position Independent Code (PIC)**, making it possible to use the tool as **shellcode**. This flexibility allows RustiveDump to be embedded in other projects or used in memory-only payloads.
- **Refactored Code**: Significant code refactoring to improve the structure and efficiency of the tool.
- **Shellcode Size**: The shellcode, with the `xor` and `remote` features enabled, is **15KB** in size.

---

## **[0.1.0]** - 2024-10-06

### Initial Release:

- **Memory Dumping via NT System Calls**: RustiveDump uses only **NT system calls** to access the memory of **lsass.exe**.
- **Minimal Minidump Creation**: The tool creates a minimalistic minidump file containing only essential information, such as:
  - **SystemInfo Stream**: Provides OS version and architecture details.
  - **ModuleList Stream**: Lists the modules loaded in **lsass.exe**.
  - **Memory64List Stream**: Contains the memory regions from **lsass.exe**.
- **XOR Encryption**: Option to encrypt the minidump file using XOR before saving or transmitting it.
- **Remote File Transmission**: The tool can send the dump file directly to a remote server using **Winsock** API calls, allowing remote exfiltration.
- **Debug Logging**: Optional debug mode to provide detailed logs of each step taken during the memory dump creation.
- **No-Std and CRT-Independent**: RustiveDump is built with the `no_std` feature in Rust, removing the dependency on the standard library. It is also independent of the **C Runtime (CRT)**.

---
