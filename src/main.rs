extern crate winapi;

mod debug;
mod bsod;
mod ekko;

fn main() {
    debug::create_debugger_hidden_thread();
}
