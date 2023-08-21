
mod bsod;
mod debug;
mod dump;
mod ekko;
mod attach;
mod privesc;

use iat_unhook_lib::{self, unhook_iat, unhook_exports};

fn main() {

    //Run unhooking:
    unhook_iat();
    unhook_exports();

    //Run anti dumping (breaks iat unhooking)
    //dump::run_anti_dump(); 

    //Run hidden thread from debugger and starts all anti-debug checks
    debug::create_debugger_hidden_thread();

}
