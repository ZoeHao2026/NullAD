//! NullAD desktop entry point.
//!
//! All logic lives in the library so that the same code can be reused for a
//! mobile target, where the entry point differs but the command surface does not.

// Windows release builds must not open a console window; the tray provides the
// only visible affordance.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    std::process::exit(nullad_desktop_lib::run());
}
