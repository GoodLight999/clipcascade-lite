#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(windows)]
mod clipboard;
#[cfg(windows)]
mod credentials;
#[cfg(windows)]
mod desktop;
mod diagnostic;
mod network;
mod protocol;
mod relay;

fn main() {
    #[cfg(windows)]
    desktop::run();
}
