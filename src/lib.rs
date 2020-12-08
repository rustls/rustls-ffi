#![crate_type = "staticlib"]

extern crate rustls;
use rustls::ALL_CIPHERSUITES;

#[no_mangle]
pub extern "C" fn print_ciphersuites() {
    println!("Supported ciphersuites in rustls:");
    for cs in ALL_CIPHERSUITES.iter() {
        println!("  {:?}", cs.suite);
    }
    ()
}
