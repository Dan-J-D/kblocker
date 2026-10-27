// Prevents an extra console window on Windows release builds
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    kblocker_gui_lib::run()
}
