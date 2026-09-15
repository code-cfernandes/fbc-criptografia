#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::Once;

// Alimenta bytes arbitrários no decodificador de token. `decrypt` devolve
// Result e nunca deve entrar em panic com entrada adversarial.
//
// IMPORTANTE: sem FBC_KEY definida, TODA entrada com prefixo "FBC" falha na
// checagem de tamanho de chave antes de tocar em base64/checksum/parsing -
// o fuzzer nunca chegaria na lógica que interessa. Fixamos a chave aqui
// dentro (não só no script externo) para que rodar `cargo fuzz run decrypt`
// diretamente, sem passar pelo script, também funcione corretamente.
static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        std::env::set_var("FBC_KEY", "chave-fixa-de-32-bytes-p-fuzz!!0");
    });

    let texto = String::from_utf8_lossy(data);
    let _ = criptografia_rust::core::criptografia::decrypt(&texto);
});
