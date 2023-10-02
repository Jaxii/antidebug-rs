use anyhow::Error;
use std::ptr::{null, null_mut};
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::PAGE_READWRITE;

//https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiDump/ErasePEHeaderFromMemory.cpp
fn erase_pe_header_from_memory() {
    // Get base address of module
    let p_base_addr = unsafe { GetModuleHandleW(null()) as *mut u8 };

    if !p_base_addr.is_null() {
        // Change memory protection
        let mut old_protect = 0;
        let page_size: usize = 4096; // Assumes x86 page size. todo: GetModuleInformation
        let success = unsafe {
            VirtualProtect(
                p_base_addr as *mut _,
                page_size,
                PAGE_READWRITE,
                &mut old_protect,
            )
        } != 0;

        if success {
            // Erase the header
            unsafe {
                std::ptr::write_bytes(p_base_addr, 0, page_size);
            }
        }
    }
}

pub fn run_anti_dump() {
    erase_pe_header_from_memory()
}
