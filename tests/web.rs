//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate libzeropool_wasm;
extern crate wasm_bindgen_test;

use libzeropool::native::params::PoolBN256;
use libzeropool_wasm::UserAccount;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn account_derive_new_address() {
    let acc = UserAccount::from_seed(b"12300000000000000000000000000000").unwrap();
    let result = acc.derive_new_address();
    assert!(result.is_ok());
}

#[wasm_bindgen_test]
fn parse_address() {
    let acc = UserAccount::from_seed(b"12300000000000000000000000000000").unwrap();
    let addr = acc.derive_new_address().unwrap();
    libzeropool_wasm::parse_address::<PoolBN256>(addr).unwrap();
}
