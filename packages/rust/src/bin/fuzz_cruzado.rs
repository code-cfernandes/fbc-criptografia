//! Runner de fuzzing cruzado: gera keystreams e checksums brutos a partir de
//! fuzz/casos.txt para comparação com as demais implementações.
//!
//! uso: cargo run --quiet --bin fuzz_cruzado -- <entrada> <saida>

use std::fs;
use std::process;

use criptografia_rust::seguranca::alvo_criptografico::AlvoCriptografico;
use criptografia_rust::seguranca::criptografia_alvo::CriptografiaAlvo;

fn valor_hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let alto = valor_hex(bytes[i]).expect("hex inválido");
        let baixo = valor_hex(bytes[i + 1]).expect("hex inválido");
        out.push((alto << 4) | baixo);
        i += 2;
    }
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITOS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITOS[(b >> 4) as usize] as char);
        out.push(DIGITOS[(b & 0x0f) as usize] as char);
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("uso: fuzz_cruzado <entrada> <saida>");
        process::exit(1);
    }
    let caminho_entrada = &args[1];
    let caminho_saida = &args[2];

    let conteudo = fs::read_to_string(caminho_entrada).unwrap_or_else(|_| {
        eprintln!("Não foi possível ler: {}", caminho_entrada);
        process::exit(1);
    });

    let alvo = CriptografiaAlvo::new();
    let mut linhas_saida: Vec<String> = Vec::new();

    for (indice, linha) in conteudo
        .lines()
        .map(|linha| linha.trim())
        .filter(|linha| !linha.is_empty())
        .enumerate()
    {
        let partes: Vec<&str> = linha.split('|').collect();
        if partes.len() < 4 {
            eprintln!("Linha malformada no índice {}: {}", indice, linha);
            process::exit(1);
        }

        let chave = hex_decode(partes[0]);
        let iv = hex_decode(partes[1]);
        let proposito = partes[2];
        let plaintext = hex_decode(partes[3]);

        let ks = alvo.gerar_keystream_bruto(&chave, &iv, proposito, plaintext.len());
        let mac = alvo.checksum_bruto(&plaintext, &chave);

        linhas_saida.push(format!("{}|{}|{}", indice, hex_encode(&ks), hex_encode(&mac)));
    }

    fs::write(caminho_saida, linhas_saida.join("\n") + "\n").unwrap_or_else(|_| {
        eprintln!("Não foi possível escrever: {}", caminho_saida);
        process::exit(1);
    });
}
