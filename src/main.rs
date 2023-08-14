extern crate winapi;

mod debug;

fn main() {
    match debug::check_heap() {
        Ok(result) => println!("Check heap for debugger: {}", result),
        Err(e) => println!("Error: {}", e),
    }

    println!("Is Debugged: {}", debug::check_debugger_present());

    println!("Is Remotely Debugged: {}", debug::check_remote_debugger_present());

    println!("Hardware breakpoints: {}",    debug::check_drx_breakpoint());

    println!("Kuser_shared_data modified: {}", debug::check_kuser_shared_data_structure());
    //println!("Is Debugged Test: {}", debug::is_debugged_test());
    println!("Kernel debugger: {}", debug::check_kernel_debugger());

    println!("Check kernel debug object: {}", debug::query_kernel_debug_object());

    debug::create_debugger_hidden_thread();
}
