#![no_main]

use libfuzzer_sys::fuzz_target;

// Alimenta bytes arbitrários no decodificador de token. `decrypt` devolve
// Result e nunca deve entrar em panic com entrada adversarial.
fuzz_target!(|data: &[u8]| {
    let texto = String::from_utf8_lossy(data);
    let _ = criptografia_rust::core::criptografia::decrypt(&texto);
});
