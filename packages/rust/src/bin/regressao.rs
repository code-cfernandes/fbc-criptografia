//! Harness de regressão histórica.
//!
//! Prova que a suíte ainda detecta os bugs reais que já corrigimos: para cada
//! bug, um snapshot reintroduz a falha e o ataque pareado PRECISA acusá-la
//! (`vulneravel=true`). Em seguida o mesmo ataque roda contra o código atual e
//! PRECISA resistir (`vulneravel=false`).

use std::any::Any;

use criptografia_rust::core::criptografia::{
    base64url_decode, base64url_encode, gerar_keystream, random_bytes, CriptoError, TAM_BLOCO,
};
use criptografia_rust::seguranca::alvo_criptografico::{AlvoCriptografico, CamposToken};
use criptografia_rust::seguranca::ataque::Ataque;
use criptografia_rust::seguranca::ataques::ataque_avalanche_checksum::AtaqueAvalancheChecksum;
use criptografia_rust::seguranca::ataques::ataque_canonicalizacao_token::AtaqueCanonicalizacaoToken;
use criptografia_rust::seguranca::ataques::ataque_correlacao_mesmo_plaintext::AtaqueCorrelacaoMesmoPlaintext;
use criptografia_rust::seguranca::ataques::ataque_fold_estrutural::AtaqueFoldEstrutural;
use criptografia_rust::seguranca::ataques::ataque_integral::AtaqueIntegral;
use criptografia_rust::seguranca::ataques::ataque_separacao_chave_iv::AtaqueSeparacaoChaveIV;
use criptografia_rust::seguranca::criptografia_alvo::CriptografiaAlvo;

const DIGITOS_PI: &str =
    "31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679";

fn rot_esquerda8(byte: u8, n: u32) -> u8 {
    byte.rotate_left(n & 7)
}

fn rotacao_do_round(round_idx: usize) -> u32 {
    let digitos = DIGITOS_PI.as_bytes();
    let d = (digitos[round_idx % digitos.len()] - b'0') as u32;
    (d % 7) + 1
}

// passo com mutações: bug 5 remove a reinserção da chave em cada rodada.
fn passo_com_bug(
    bug: u8,
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
    if bug != 5 {
        soma ^= key[(pos_fib + round_idx) % key.len()];
    }
    soma = soma.wrapping_mul(131);
    (b, soma)
}

// gerar_keystream com mutações: bugs 1, 2, 4, 5.
fn gerar_keystream_com_bug(
    bug: u8,
    key: &[u8],
    iv: &[u8],
    proposito: &str,
    tamanho: usize,
) -> Vec<u8> {
    if bug == 1 {
        // bug 1: keystream ignora o IV (vaza o mesmo fluxo para o mesmo plaintext).
        let iv_zero = vec![0u8; iv.len()];
        return gerar_keystream(key, &iv_zero, proposito, tamanho);
    }

    let bloco = TAM_BLOCO;
    // bug 2: o colapso de metades só acontece quando a distância é exatamente
    // metade do bloco (16) — reproduzimos a condição histórica.
    let distancias: Vec<usize> = match bug {
        4 => vec![3],
        2 => vec![3, 5, 11, 19, 41, 16],
        _ => vec![3, 5, 11, 19, 41, 3, 5, 11, 19, 41],
    };
    let proposito_bytes = proposito.as_bytes();
    let key_len = key.len();
    let iv_len = iv.len();

    let mut a = vec![0u8; bloco];
    let mut b = vec![0u8; bloco];
    for pos in 0..bloco {
        a[pos] = key[pos % key_len] ^ iv[pos % iv_len];
        b[pos] = key[(pos + 1) % key_len] ^ iv[(pos + 1) % iv_len];
    }

    let mut saida: Vec<u8> = Vec::new();
    let mut round_idx = 0usize;
    let mut pos_fib_base = 0usize;

    while saida.len() < tamanho {
        for &dist in distancias.iter() {
            let mut novo_b = vec![0u8; bloco];
            for pos in 0..bloco {
                let (novo_a, novo_bb) = passo_com_bug(
                    bug,
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

            let mut misturado = vec![0u8; bloco];
            for pos in 0..bloco {
                let vizinho = novo_b[(pos + dist) % bloco];
                misturado[pos] = if bug == 2 {
                    // bug 2: combinador SIMÉTRICO (colapsa metades do bloco).
                    rot_esquerda8(novo_b[pos] ^ vizinho, 1)
                } else {
                    rot_esquerda8(novo_b[pos], 1) ^ vizinho
                };
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

// checksum com mutação: bug 3 remove a finalização.
fn checksum_com_bug(bug: u8, dados: &[u8], key: &[u8]) -> Vec<u8> {
    let mut saida = vec![0u8; 32];
    let key_len = key.len();

    for rodada in 0..8usize {
        let mut acumulador = 0x811c9dc5u32 ^ (rodada as u32).wrapping_mul(0x01000193);

        for (i, &byte_dado) in dados.iter().enumerate() {
            let byte = byte_dado ^ key[(i + rodada) % key_len];
            acumulador ^= byte as u32;
            acumulador = acumulador.wrapping_mul(16777619);
            acumulador = acumulador.rotate_left(((i % 13) + 1) as u32);
        }

        if bug != 3 {
            for _ in 0..3 {
                acumulador ^= acumulador >> 16;
                acumulador = acumulador.wrapping_mul(16777619);
                acumulador = acumulador.rotate_left(13);
            }
        }

        saida[rodada * 4] = (acumulador >> 24) as u8;
        saida[rodada * 4 + 1] = (acumulador >> 16) as u8;
        saida[rodada * 4 + 2] = (acumulador >> 8) as u8;
        saida[rodada * 4 + 3] = acumulador as u8;
    }

    saida
}

fn valor_b64_loose(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

// Decodificador base64 padrão, tolerante a lixo (equivalente ao
// `Buffer.from(s, 'base64')` do Node).
fn b64_decode_loose(s: &str) -> Vec<u8> {
    let bytes: Vec<u8> = s
        .bytes()
        .filter(|&c| valor_b64_loose(c).is_some())
        .collect();
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let n = ((valor_b64_loose(bytes[i]).unwrap() as u32) << 18)
            | ((valor_b64_loose(bytes[i + 1]).unwrap() as u32) << 12)
            | ((valor_b64_loose(bytes[i + 2]).unwrap() as u32) << 6)
            | (valor_b64_loose(bytes[i + 3]).unwrap() as u32);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
        i += 4;
    }
    let restante = bytes.len() - i;
    if restante == 2 {
        let n = ((valor_b64_loose(bytes[i]).unwrap() as u32) << 18)
            | ((valor_b64_loose(bytes[i + 1]).unwrap() as u32) << 12);
        out.push((n >> 16) as u8);
    } else if restante == 3 {
        let n = ((valor_b64_loose(bytes[i]).unwrap() as u32) << 18)
            | ((valor_b64_loose(bytes[i + 1]).unwrap() as u32) << 12)
            | ((valor_b64_loose(bytes[i + 2]).unwrap() as u32) << 6);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
    }
    out
}

// base64url decode com mutação: bug 6 aceita alfabeto padrão e lixo.
fn base64url_decode_com_bug(bug: u8, data: &str) -> Result<Vec<u8>, CriptoError> {
    if bug != 6 {
        return base64url_decode(data);
    }
    let mut s: String = data
        .chars()
        .filter_map(|c| match c {
            '-' => Some('+'),
            '_' => Some('/'),
            '+' | '/' | '=' => Some(c),
            c if c.is_ascii_alphanumeric() => Some(c),
            _ => None,
        })
        .collect();
    let resto = s.len() % 4;
    if resto != 0 {
        s.push_str(&"=".repeat(4 - resto));
    }
    Ok(b64_decode_loose(&s))
}

// Alvo que aponta para a cifra com o bug selecionado. Reutiliza a infra do
// alvo real e sobrescreve só os métodos com bug. `as_any` delega para o alvo
// embutido para que os ataques que exigem `CriptografiaAlvo` (correlação e
// canonicalização) não pulem o snapshot.
struct SnapshotAlvo {
    base: CriptografiaAlvo,
    bug: u8,
}

impl SnapshotAlvo {
    fn new(bug: u8) -> Self {
        SnapshotAlvo {
            base: CriptografiaAlvo::new(),
            bug,
        }
    }
}

impl AlvoCriptografico for SnapshotAlvo {
    fn encrypt(&self, texto: &[u8]) -> Result<String, CriptoError> {
        let key = self.base.chave_de_teste().into_bytes();
        let iv = random_bytes(16);
        let enc_keystream = gerar_keystream_com_bug(self.bug, &key, &iv, "enc", texto.len());
        let ciphertext: Vec<u8> = texto
            .iter()
            .zip(enc_keystream.iter())
            .map(|(t, k)| t ^ k)
            .collect();

        let mac_key = gerar_keystream_com_bug(self.bug, &key, &iv, "mac", TAM_BLOCO);
        let mut dados_mac = iv.clone();
        dados_mac.extend_from_slice(&ciphertext);
        let integridade = checksum_com_bug(self.bug, &dados_mac, &mac_key);

        let mut corpo = integridade;
        corpo.extend_from_slice(&ciphertext);
        corpo.extend_from_slice(&iv);
        Ok(format!("FBC{}", base64url_encode(&corpo)))
    }

    fn decrypt(&self, token: &str) -> Result<String, CriptoError> {
        if token.as_bytes().get(0..3) != Some(b"FBC") {
            return Err(CriptoError::new("Invalid text. Text must start with FBC."));
        }

        let key = self.base.chave_de_teste().into_bytes();
        let decoded = self.base64url_decode(&token[3..])?;
        if decoded.len() < TAM_BLOCO + 16 {
            return Err(CriptoError::new("Token adulterado ou chave incorreta."));
        }

        let integridade_recebida = &decoded[0..TAM_BLOCO];
        let iv = &decoded[decoded.len() - 16..];
        let ciphertext = &decoded[TAM_BLOCO..decoded.len() - 16];

        let mac_key = gerar_keystream_com_bug(self.bug, &key, iv, "mac", TAM_BLOCO);
        let mut dados_mac = iv.to_vec();
        dados_mac.extend_from_slice(ciphertext);
        let integridade_esperada = checksum_com_bug(self.bug, &dados_mac, &mac_key);

        if integridade_esperada != integridade_recebida {
            return Err(CriptoError::new("Token adulterado ou chave incorreta."));
        }

        let enc_keystream = gerar_keystream_com_bug(self.bug, &key, iv, "enc", ciphertext.len());
        let plaintext: Vec<u8> = ciphertext
            .iter()
            .zip(enc_keystream.iter())
            .map(|(c, k)| c ^ k)
            .collect();
        Ok(String::from_utf8_lossy(&plaintext).into_owned())
    }

    fn prefixo(&self) -> &str {
        self.base.prefixo()
    }

    fn decompor(&self, token_decodificado: &[u8]) -> CamposToken {
        self.base.decompor(token_decodificado)
    }

    fn recompor(&self, campos: &CamposToken) -> Vec<u8> {
        self.base.recompor(campos)
    }

    fn gerar_keystream_bruto(
        &self,
        key: &[u8],
        iv: &[u8],
        proposito: &str,
        tamanho: usize,
    ) -> Vec<u8> {
        gerar_keystream_com_bug(self.bug, key, iv, proposito, tamanho)
    }

    fn checksum_bruto(&self, dados: &[u8], key: &[u8]) -> Vec<u8> {
        checksum_com_bug(self.bug, dados, key)
    }

    fn chave_de_teste(&self) -> String {
        self.base.chave_de_teste()
    }

    fn tamanho_iv(&self) -> usize {
        self.base.tamanho_iv()
    }

    fn base64url_encode(&self, data: &[u8]) -> String {
        self.base.base64url_encode(data)
    }

    fn base64url_decode(&self, data: &str) -> Result<Vec<u8>, CriptoError> {
        base64url_decode_com_bug(self.bug, data)
    }

    fn as_any(&self) -> &dyn Any {
        // Deixa os ataques enxergarem o alvo real embutido (checagem de
        // capacidade), sem quebrar o despacho para os métodos com bug.
        self.base.as_any()
    }
}

fn main() {
    let casos: Vec<(u8, &str, Box<dyn Ataque>)> = vec![
        (
            1,
            "keystream ignora o IV",
            Box::new(AtaqueCorrelacaoMesmoPlaintext::new()),
        ),
        (
            2,
            "combinador simétrico (metades colapsam)",
            Box::new(AtaqueFoldEstrutural::new()),
        ),
        (
            3,
            "checksum sem finalização",
            Box::new(AtaqueAvalancheChecksum::new()),
        ),
        (4, "cinco rodadas de difusão", Box::new(AtaqueIntegral::new())),
        (
            5,
            "chave só no estado inicial",
            Box::new(AtaqueSeparacaoChaveIV::new()),
        ),
        (
            6,
            "base64 não estrito",
            Box::new(AtaqueCanonicalizacaoToken),
        ),
    ];

    let barra = "=".repeat(72);
    println!("{}", barra);
    println!("REGRESSÃO HISTÓRICA");
    println!("{}", barra);

    let mut falhas = 0usize;
    for (bug, descricao, ataque) in &casos {
        let snapshot = SnapshotAlvo::new(*bug);
        let real = CriptografiaAlvo::new();

        let r_snapshot = ataque.executar(&snapshot);
        let r_real = ataque.executar(&real);

        let (r_snapshot, r_real) = match (r_snapshot, r_real) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e), _) | (_, Err(e)) => {
                println!(
                    "  ❌ bug {} ({}): erro — {:?}",
                    bug, descricao, e
                );
                falhas += 1;
                continue;
            }
        };

        let detectou = r_snapshot.vulneravel;
        let resistiu = !r_real.vulneravel;
        let ok = detectou && resistiu;
        if !ok {
            falhas += 1;
        }

        println!(
            "  {} bug {} ({}): snapshot {} | atual {}",
            if ok { "✅" } else { "❌" },
            bug,
            descricao,
            if detectou { "detectado" } else { "NÃO detectado" },
            if resistiu { "resistiu" } else { "ACUSOU" },
        );
        if !ok {
            println!("       snapshot: {}", r_snapshot.linha_resumo());
            println!("       atual:    {}", r_real.linha_resumo());
        }
    }

    println!("{}", barra);
    if falhas == 0 {
        println!(
            "RESUMO: {} bugs históricos detectados; código atual resiste a todos.",
            casos.len()
        );
    } else {
        println!("RESUMO: {} caso(s) falharam.", falhas);
    }
    println!("{}", barra);

    std::process::exit(if falhas == 0 { 0 } else { 1 });
}
