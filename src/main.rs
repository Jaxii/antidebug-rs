mod attach;
mod bsod;
mod debug;
mod dump;
mod ekko;
mod privesc;
mod util;

use iat_unhook_lib::{self, unhook_exports, unhook_iat};

fn main() {
    //test
    //util::test_get_currentprocess_modules();

    //Run unhooking:
    unhook_iat();
    unhook_exports();

    //Run anti dumping (breaks iat unhooking)
    //dump::run_anti_dump();

    //Run hidden thread from debugger and starts all anti-debug checks
    debug::create_debugger_hidden_thread();
}
