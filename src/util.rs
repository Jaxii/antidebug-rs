use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::shared::ntdef::NULL;
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Module32First, Module32Next, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, MODULEENTRY32};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::psapi::{GetModuleInformation, MODULEINFO};
use winapi::um::processthreadsapi::GetCurrentProcessId;
use winapi::um::handleapi::CloseHandle;
use std::mem;
use std::ptr::null_mut;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use winapi::um::processthreadsapi::GetCurrentProcess;

struct ModuleEntry {
    name: String,
    id: u32,
    size: usize,
    
}

pub fn get_currentprocess_modules() -> usize {

    //get current process id
    let process_id = unsafe {
        GetCurrentProcessId();
    };

    let snapshot_handle = unsafe { CreateToolhelp32Snapshot };

    //ModuleEntry32, CloseHandle, GetModuleInformation
    return 0;
}

pub fn test_get_currentprocess_modules() {

    let process_id = unsafe { GetCurrentProcessId() };

    let snapshot_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id) };

    if snapshot_handle == INVALID_HANDLE_VALUE {
      
    }

    let mut module_entry: MODULEENTRY32 = unsafe { mem::zeroed() };
    module_entry.dwSize = mem::size_of::<MODULEENTRY32>() as DWORD;

    if unsafe { Module32First(snapshot_handle, &mut module_entry) } == FALSE {
        unsafe { CloseHandle(snapshot_handle) };
       
    }

        let u16_vec: &Vec<u16> = &module_entry.szModule.iter().map(|&x| x as u16).collect();
        let u16_slice: &[u16] = &u16_vec;

        let module_name = OsString::from_wide(u16_slice);
        let module_handle = module_entry.hModule;

        let mut module_info: MODULEINFO = unsafe { mem::zeroed() };
        if unsafe { GetModuleInformation(GetCurrentProcess(), module_handle, &mut module_info, mem::size_of::<MODULEINFO>() as DWORD) } == FALSE {
            println!("Failed to get module information for {:?}", module_name);
        } else {
            println!("Module Name: {:?}\nModule Size: {:?}\n", module_name, module_info.SizeOfImage);
        }

        if unsafe { Module32Next(snapshot_handle, &mut module_entry) } == FALSE {
      
                
    }

    //unsafe { CloseHandle(snapshot_handle) };

}