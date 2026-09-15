//! Funções utilitárias compartilhadas pelos ataques.
#![allow(dead_code)]

use crate::core::criptografia::random_bytes as core_random_bytes;

/// Inteiro aleatório em [min, max], inclusivo (equivalente ao `random_int` do PHP).
pub fn random_int(min: i64, max: i64) -> i64 {
    if max <= min {
        return min;
    }
    let intervalo = (max - min + 1) as u64;
    let bytes = core_random_bytes(8);
    let mut valor = 0u64;
    for (i, b) in bytes.iter().enumerate() {
        valor |= (*b as u64) << (i * 8);
    }
    min + (valor % intervalo) as i64
}

/// N bytes aleatórios (equivalente ao `random_bytes` do PHP/Node).
pub fn random_bytes(n: usize) -> Vec<u8> {
    core_random_bytes(n)
}

/// Codifica bytes como hexadecimal minúsculo.
pub fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decodifica uma string hexadecimal (retorna `None` se inválida).
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    fn valor(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = valor(bytes[i])?;
        let lo = valor(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

/// Popcount de um byte (0-255).
pub fn contar_bits1(byte: u8) -> u32 {
    byte.count_ones()
}

/// Popcount total de um buffer.
pub fn contar_bits_buffer(buf: &[u8]) -> u32 {
    buf.iter().map(|&b| contar_bits1(b)).sum()
}

/// Conta quantos bits diferem entre dois buffers de mesmo tamanho.
pub fn bits_diferentes(a: &[u8], b: &[u8]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| contar_bits1(x ^ y))
        .sum()
}

/// Fisher-Yates: embaralha uma cópia do vetor.
pub fn shuffle<T: Clone>(array: &[T]) -> Vec<T> {
    let mut out = array.to_vec();
    if out.is_empty() {
        return out;
    }
    for i in (1..out.len()).rev() {
        let j = random_int(0, i as i64) as usize;
        out.swap(i, j);
    }
    out
}
