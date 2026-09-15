//! Cifra caseira educacional — porte de `Criptografia.php`/`Criptografia.ts`.
//!
//! Estrutura do token: `FBC` + base64url( integridade[32] . ciphertext[n] . iv[16] )
//!
//! Replica a lógica byte a byte, sem "melhorias" — qualquer mudança de
//! comportamento aqui quebraria a compatibilidade com os tokens gerados pelas
//! outras linguagens.

use std::fmt;

pub const TAM_BLOCO: usize = 32;

/// Mesmas distâncias da versão PHP (Fibonacci -> N-ésimo primo, pulando o 2).
const DISTANCIAS_DIFUSAO: [usize; 10] = [3, 5, 11, 19, 41, 3, 5, 11, 19, 41];

const DIGITOS_PI: &str =
    "31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679";

const ALFABETO_B64URL: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Erro da cifra (mensagens equivalentes às das outras linguagens).
#[derive(Debug, Clone)]
pub struct CriptoError(pub String);

impl CriptoError {
    pub fn new(mensagem: &str) -> Self {
        CriptoError(mensagem.to_string())
    }
}

impl fmt::Display for CriptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CriptoError {}

fn rot_esquerda8(byte: u8, n: u32) -> u8 {
    byte.rotate_left(n & 7)
}

fn rot_esquerda32(val: u32, n: u32) -> u32 {
    val.rotate_left(n & 31)
}

fn rotacao_do_round(round_idx: usize) -> u32 {
    let digitos = DIGITOS_PI.as_bytes();
    let d = (digitos[round_idx % digitos.len()] - b'0') as u32;
    (d % 7) + 1
}

/// Um passo da recorrência tipo-Fibonacci pra uma posição do bloco.
fn passo(
    a: u8,
    b: u8,
    key: &[u8],
    proposito: &[u8],
    pos_fib: usize,
    round_idx: usize,
) -> (u8, u8) {
    let n = rotacao_do_round(round_idx);

    let mut soma = a.wrapping_add(b);
    soma = rot_esquerda8(soma, n);
    soma ^= proposito[pos_fib % proposito.len()];
    // A chave participa de CADA rodada, não só do estado inicial.
    soma ^= key[(pos_fib + round_idx) % key.len()];
    soma = soma.wrapping_mul(131);

    (b, soma) // novo a = b antigo; novo b = soma
}

/// Gera `tamanho` bytes de keystream a partir de KEY + IV + propósito.
pub fn gerar_keystream(key: &[u8], iv: &[u8], proposito: &str, tamanho: usize) -> Vec<u8> {
    let bloco = TAM_BLOCO;
    let proposito_bytes = proposito.as_bytes();

    let mut a = vec![0u8; bloco];
    let mut b = vec![0u8; bloco];
    for pos in 0..bloco {
        a[pos] = key[pos % key.len()] ^ iv[pos % iv.len()];
        b[pos] = key[(pos + 1) % key.len()] ^ iv[(pos + 1) % iv.len()];
    }

    let mut saida: Vec<u8> = Vec::new();
    let mut round_idx: usize = 0;
    let mut pos_fib_base: usize = 0;

    while saida.len() < tamanho {
        for &dist in DISTANCIAS_DIFUSAO.iter() {
            let mut novo_b = vec![0u8; bloco];
            for pos in 0..bloco {
                let (novo_a, novo_bb) = passo(
                    a[pos],
                    b[pos],
                    key,
                    proposito_bytes,
                    pos_fib_base + pos,
                    round_idx,
                );
                a[pos] = novo_a;
                novo_b[pos] = novo_bb;
            }

            // Combinação ASSIMÉTRICA: rotaciona só o valor próprio antes do XOR.
            let mut misturado = vec![0u8; bloco];
            for pos in 0..bloco {
                let vizinho = novo_b[(pos + dist) % bloco];
                misturado[pos] = rot_esquerda8(novo_b[pos], 1) ^ vizinho;
            }
            b = misturado;
            round_idx += 1;
        }

        pos_fib_base += bloco;
        saida.extend_from_slice(&b);
    }

    saida.truncate(tamanho);
    saida
}

fn xor_bytes(dados: &[u8], keystream: &[u8]) -> Vec<u8> {
    dados
        .iter()
        .zip(keystream.iter())
        .map(|(d, k)| d ^ k)
        .collect()
}

/// "MAC" caseiro: 8 rodadas de um checksum estilo FNV, concatenadas -> 32 bytes.
pub fn checksum(dados: &[u8], key: &[u8]) -> [u8; 32] {
    let mut saida = [0u8; 32];
    let key_len = key.len();

    for rodada in 0..8usize {
        let mut acumulador = 0x811c9dc5u32 ^ (rodada as u32).wrapping_mul(0x01000193);

        for (i, &byte_dado) in dados.iter().enumerate() {
            let byte = byte_dado ^ key[(i + rodada) % key_len];
            acumulador ^= byte as u32;
            acumulador = acumulador.wrapping_mul(16777619);
            acumulador = rot_esquerda32(acumulador, ((i % 13) + 1) as u32);
        }

        // Finalização: sem isso, o último byte processado sofre avalanche fraca.
        for _ in 0..3 {
            acumulador ^= acumulador >> 16;
            acumulador = acumulador.wrapping_mul(16777619);
            acumulador = rot_esquerda32(acumulador, 13);
        }

        saida[rodada * 4] = (acumulador >> 24) as u8;
        saida[rodada * 4 + 1] = (acumulador >> 16) as u8;
        saida[rodada * 4 + 2] = (acumulador >> 8) as u8;
        saida[rodada * 4 + 3] = acumulador as u8;
    }

    saida
}

fn valor_b64(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

pub fn base64url_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALFABETO_B64URL[((n >> 18) & 63) as usize] as char);
        out.push(ALFABETO_B64URL[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALFABETO_B64URL[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALFABETO_B64URL[(n & 63) as usize] as char);
        }
    }
    out
}

pub fn base64url_decode(data: &str) -> Result<Vec<u8>, CriptoError> {
    if !data.is_empty() && !data.bytes().all(|c| valor_b64(c).is_some()) {
        return Err(CriptoError::new("Token contém caracteres inválidos."));
    }

    if data.len() % 4 == 1 {
        return Err(CriptoError::new("Comprimento de token inválido."));
    }

    let bytes = data.as_bytes();
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let n = ((valor_b64(bytes[i]).unwrap() as u32) << 18)
            | ((valor_b64(bytes[i + 1]).unwrap() as u32) << 12)
            | ((valor_b64(bytes[i + 2]).unwrap() as u32) << 6)
            | (valor_b64(bytes[i + 3]).unwrap() as u32);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
        i += 4;
    }

    let restante = bytes.len() - i;
    if restante == 2 {
        let n = ((valor_b64(bytes[i]).unwrap() as u32) << 18)
            | ((valor_b64(bytes[i + 1]).unwrap() as u32) << 12);
        out.push((n >> 16) as u8);
    } else if restante == 3 {
        let n = ((valor_b64(bytes[i]).unwrap() as u32) << 18)
            | ((valor_b64(bytes[i + 1]).unwrap() as u32) << 12)
            | ((valor_b64(bytes[i + 2]).unwrap() as u32) << 6);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
    }

    // Canonicidade: reencoda e compara — pega bits não-canônicos no último grupo.
    if base64url_encode(&out) != data {
        return Err(CriptoError::new("Token não está em forma canônica."));
    }

    Ok(out)
}

pub fn get_key() -> Result<Vec<u8>, CriptoError> {
    let key = std::env::var("FBC_KEY").unwrap_or_default();
    if key.len() != 32 {
        return Err(CriptoError::new("Chave deve ter 32 bytes."));
    }
    Ok(key.into_bytes())
}

/// N bytes aleatórios (equivalente ao `random_bytes` do PHP/Node).
pub fn random_bytes(n: usize) -> Vec<u8> {
    use std::io::Read;

    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let mut buf = vec![0u8; n];
        if f.read_exact(&mut buf).is_ok() {
            return buf;
        }
    }

    // Fallback: xorshift semeado com tempo + pid.
    let mut estado = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15);
    estado ^= std::process::id() as u64;

    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        estado ^= estado << 13;
        estado ^= estado >> 7;
        estado ^= estado << 17;
        out.push((estado & 0xff) as u8);
    }
    out
}

/// `encrypt` a partir de bytes arbitrários (equivalente ao `encrypt(Buffer)`).
pub fn encrypt_bytes(texto: &[u8]) -> Result<String, CriptoError> {
    let key = get_key()?;
    let iv = random_bytes(16);

    let enc_keystream = gerar_keystream(&key, &iv, "enc", texto.len());
    let ciphertext = xor_bytes(texto, &enc_keystream);

    let mac_key = gerar_keystream(&key, &iv, "mac", TAM_BLOCO);
    let mut dados_mac = iv.clone();
    dados_mac.extend_from_slice(&ciphertext);
    let integridade = checksum(&dados_mac, &mac_key);

    let mut corpo = Vec::with_capacity(32 + ciphertext.len() + 16);
    corpo.extend_from_slice(&integridade);
    corpo.extend_from_slice(&ciphertext);
    corpo.extend_from_slice(&iv);

    Ok(format!("FBC{}", base64url_encode(&corpo)))
}

/// `encrypt` de uma string UTF-8.
pub fn encrypt(texto: &str) -> Result<String, CriptoError> {
    encrypt_bytes(texto.as_bytes())
}

/// Comparação em tempo constante (equivalente ao `timingSafeEqual`).
fn iguais_tempo_constante(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub fn decrypt(token: &str) -> Result<String, CriptoError> {
    if token.as_bytes().get(0..3) != Some(b"FBC") {
        return Err(CriptoError::new("Invalid text. Text must start with FBC."));
    }

    let key = get_key()?;
    let decoded = base64url_decode(&token[3..])?;

    if decoded.len() < TAM_BLOCO + 16 {
        return Err(CriptoError::new("Token adulterado ou chave incorreta."));
    }

    let integridade_recebida = &decoded[0..TAM_BLOCO];
    let iv = &decoded[decoded.len() - 16..];
    let ciphertext = &decoded[TAM_BLOCO..decoded.len() - 16];

    let mac_key = gerar_keystream(&key, iv, "mac", TAM_BLOCO);
    let mut dados_mac = iv.to_vec();
    dados_mac.extend_from_slice(ciphertext);
    let integridade_esperada = checksum(&dados_mac, &mac_key);

    if !iguais_tempo_constante(&integridade_esperada, integridade_recebida) {
        return Err(CriptoError::new("Token adulterado ou chave incorreta."));
    }

    let enc_keystream = gerar_keystream(&key, iv, "enc", ciphertext.len());
    let plaintext = xor_bytes(ciphertext, &enc_keystream);
    Ok(String::from_utf8_lossy(&plaintext).into_owned())
}
