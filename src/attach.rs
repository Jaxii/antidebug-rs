use winapi::shared::minwindef::{DWORD, FARPROC, HMODULE};
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::{PAGE_EXECUTE_READWRITE, HANDLE};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use std::ptr::null_mut;

pub fn anti_attach() {
    let h_ntdll: HMODULE = unsafe { GetModuleHandleA(obfstr::obfstr!("ntdll.dll\0").as_bytes().as_ptr() as *const i8) };
    if h_ntdll.is_null() {
        return;
    }

    let p_dbg_break_point: FARPROC = unsafe { GetProcAddress(h_ntdll, obfstr::obfstr!("DbgBreakPoint\0").as_bytes().as_ptr() as *const i8) };
    if p_dbg_break_point.is_null() {
        return;
    }

    let mut dw_old_protect: DWORD = 0;
    let result = unsafe { VirtualProtect(p_dbg_break_point as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut dw_old_protect) };
    if result == 0 {
        return;
    }

    unsafe { *(p_dbg_break_point as *mut u8) = 0xC3; }
}