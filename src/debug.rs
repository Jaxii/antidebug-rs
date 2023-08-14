
use winapi::shared::basetsd::ULONG_PTR;
use winapi::shared::minwindef::{DWORD, PBYTE, HMODULE};
use winapi::shared::ntdef::{NTSTATUS, PVOID, HANDLE, PULONG, BOOLEAN};
use winapi::um::heapapi::{GetProcessHeap, HeapWalk};
use winapi::um::minwinbase::PROCESS_HEAP_ENTRY;

use std::thread;
use winapi::um::debugapi::IsDebuggerPresent;
use winapi::um::winuser::{GetShellWindow, GetWindowThreadProcessId};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::debugapi::CheckRemoteDebuggerPresent;
use winapi::shared::ntdef::ULONG;
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect};
use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_GUARD};
use winapi::ctypes::c_ulong;
use winapi::shared::ntstatus::STATUS_SUCCESS;
use std::mem::size_of;
use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress};
use std::ffi::CString;

use std::ptr::null_mut;
use winapi::shared::minwindef::FALSE;

use winapi::um::debugapi::ContinueDebugEvent;
use winapi::um::debugapi::DebugActiveProcess;
use winapi::um::debugapi::WaitForDebugEvent;


use winapi::um::winnt::DBG_CONTINUE;
use winapi::um::processthreadsapi::{GetCurrentThread, GetThreadContext};
use winapi::um::winnt::CONTEXT;

use winapi::um::winnt::CONTEXT_DEBUG_REGISTERS;

use std::process;

use std::arch::asm;

#[repr(C)]
struct PROCESS_BASIC_INFORMATION {
    Reserved1: PVOID,
    PebBaseAddress: PVOID,
    Reserved2: [PVOID; 2],
    UniqueProcessId: ULONG_PTR,
    InheritedFromUniqueProcessId: PVOID,
}

extern "system" {
    fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: DWORD,
        ProcessInformation: PVOID,
        ProcessInformationLength: ULONG,
        ReturnLength: ULONG,
    ) -> NTSTATUS;
}

pub fn check_heap() -> Result<bool, &'static str> {
    let mut heap_entry: PROCESS_HEAP_ENTRY = unsafe { std::mem::zeroed() };
    let heap = unsafe { GetProcessHeap() };

    loop {
        if unsafe { HeapWalk(heap, &mut heap_entry) } == 0 {
            return Err("HeapWalk failed");
        }

        if heap_entry.wFlags & winapi::um::minwinbase::PROCESS_HEAP_ENTRY_BUSY != 0 {
            break;
        }
    }

    let p_overlapped: *const DWORD = unsafe {
        (heap_entry.lpData as *const u8).add(heap_entry.cbData as usize) as *const DWORD
    };

    if unsafe { *p_overlapped } == 0xABABABAB {
        return Ok(true);
    }

    Ok(false)
}

// const STATUS_SUCCESS: NTSTATUS = 0x0;

// pub fn is_debugged() -> bool {
//     let h_explorer_wnd = unsafe { GetShellWindow() };
//     if h_explorer_wnd.is_null() {
//         return false;
//     }

//     let mut dw_explorer_process_id: DWORD = 0;
//     unsafe { GetWindowThreadProcessId(h_explorer_wnd, &mut dw_explorer_process_id) };

//     let mut process_info: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
//     let status = unsafe {
//         NtQueryInformationProcess(
//             GetCurrentProcess(),
//             0, // ProcessBasicInformation
//             &mut process_info as *mut _ as PVOID,
//             std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
//             0,
//         )
//     };
//     if status != STATUS_SUCCESS {
//         return false;
//     }

//     (process_info.InheritedFromUniqueProcessId as DWORD) != dw_explorer_process_id
// }

pub fn check_debugger_present() -> bool {
    unsafe { IsDebuggerPresent() != 0 }
}

pub fn check_remote_debugger_present() -> bool {
    let mut b_debugger_present: i32 = 0;
    let mut b_debugger_present: i32 = 0; // Using i32 instead of BOOL since BOOL is typedef to i32 in winapi.
    unsafe {
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut b_debugger_present) != 0
            && b_debugger_present != 0
    }
}

pub fn create_debugger_hidden_thread() {
    let handler = thread::spawn(|| {
        // thread code
        const ThreadHideFromDebugger: u32 = 0x11; //todo: verify this value

        let status = unsafe {
            NtSetInformationThread(
                NtCurrentThread,
                ThreadHideFromDebugger,
                std::ptr::null_mut(),
                0,
            )
        };

    });
    
    handler.join().unwrap();

}

pub fn check_drx_breakpoint() -> bool {
    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if unsafe { GetThreadContext(GetCurrentThread(), &mut ctx) } == FALSE {
        return false;
    }

    ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0
}

pub fn check_kuser_shared_data_structure() -> bool {
    let address: *const u8 = 0x7ffe02d4 as *const u8;
    let b: u8 = unsafe { *address };
    (b & 0x01 != 0) || (b & 0x02 != 0)
}


pub fn check_kernel_debugger() -> bool {
    let mut system_info = SystemKernelDebuggerInformation {
        DebuggerEnabled: 0,
        DebuggerNotPresent: 0,
    };
    let status: NTSTATUS = unsafe {
        NtQuerySystemInformation(
            SYSTEM_KERNEL_DEBUGGER_INFORMATION,
            &mut system_info as *mut _ as PVOID,
            size_of::<SystemKernelDebuggerInformation>() as ULONG,
            null_mut(),
        )
    };

    status == STATUS_SUCCESS && system_info.DebuggerEnabled != 0 && system_info.DebuggerNotPresent == 0
}

pub fn query_kernel_debug_object() -> bool {
    let h_ntdll: HMODULE = unsafe { LoadLibraryA(CString::new(obfstr::obfstr!("ntdll.dll")).unwrap().as_ptr()) };

    if !h_ntdll.is_null() {
        let pfn_nt_query_information_process: TNtQueryInformationProcess = unsafe {
            std::mem::transmute(GetProcAddress(
                h_ntdll,
                CString::new(obfstr::obfstr!("NtQueryInformationProcess")).unwrap().as_ptr(),
            ))
        };

            let mut dw_process_debug_port: DWORD = 0;
            let mut dw_returned: ULONG = 0;
            let status: NTSTATUS = unsafe {
                pfn_nt_query_information_process(
                    GetCurrentProcess(),
                    ProcessDebugPort,
                    &mut dw_process_debug_port as *mut _ as PVOID,
                    std::mem::size_of::<DWORD>() as ULONG,
                    &mut dw_returned,
                )
            };

            return status == STATUS_SUCCESS && dw_process_debug_port == !0
    } else {
        return false
    }
}


extern "C" {
    fn NtSetInformationThread(
        ThreadHandle: winapi::um::winnt::HANDLE,
        ThreadInformationClass: u32,
        ThreadInformation: *mut winapi::ctypes::c_void,
        ThreadInformationLength: u32,
    ) -> winapi::shared::ntdef::NTSTATUS;
}

const NtCurrentThread: winapi::um::winnt::HANDLE = -2i32 as *mut winapi::ctypes::c_void;
const SYSTEM_KERNEL_DEBUGGER_INFORMATION: ULONG = 0x23;

#[repr(C)]
struct SystemKernelDebuggerInformation {
    DebuggerEnabled: BOOLEAN,
    DebuggerNotPresent: BOOLEAN,
}

extern "system" {
    fn NtQuerySystemInformation(
        SystemInformationClass: ULONG,
        SystemInformation: PVOID,
        SystemInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
}

const ProcessDebugPort: ULONG = 7;


type TNtQueryInformationProcess = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    ProcessInformationClass: ULONG,
    ProcessInformation: PVOID,
    ProcessInformationLength: ULONG,
    ReturnLength: *mut ULONG,
) -> NTSTATUS;
