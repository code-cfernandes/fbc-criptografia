//! Vetores de referência (Known Answer Tests) e interoperabilidade.
//!
//! A mesma cifra é implementada em PHP, Node, TypeScript, Python, Bash e Rust.
//! Este ataque fixa keystreams e tokens conhecidos: se QUALQUER implementação
//! divergir, ela não reproduz estes valores e o ataque acusa.
//!
//! Os tokens foram gerados com a chave de teste padrão
//! (`pfi5j8M17ZYHohQBdutGJ5UvxWcYv4Lf`); o IV é aleatório, mas fica embutido no
//! token, então a decifragem é determinística.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::{hex_decode, hex_encode};

/// (iv_hex, proposito, tamanho, esperado_hex)
const VETORES: &[(&str, &str, usize, &str)] = &[
    (
        "00000000000000000000000000000000",
        "enc",
        32,
        "219a73a5bdb588b63187fa656d1492e0728c73ef526f6c525cf37cfb0f125249",
    ),
    (
        "00000000000000000000000000000000",
        "enc",
        64,
        "219a73a5bdb588b63187fa656d1492e0728c73ef526f6c525cf37cfb0f125249a9b8fa2ec5a08abdae48729fe50aa1def4d6af963ecb11a46d1a4604046741a7",
    ),
    (
        "00000000000000000000000000000000",
        "mac",
        32,
        "ebaec6df127deb7dac57d584f86a13c53cfc74974da9f6594fd831acf3d07bb1",
    ),
    (
        "000102030405060708090a0b0c0d0e0f",
        "enc",
        32,
        "0c8c9ba9ee81e6b9d00bd84b22c4180afd2a0c595f35a6be05b9d0a3ba37baf9",
    ),
    (
        "000102030405060708090a0b0c0d0e0f",
        "mac",
        64,
        "2173c8774d071e983d895aeaa0cc2dd22d5da18b8427a98ee9ad89297eb03e0e961303b58b65bf2b6f48b7cfb2a04b1a7a9406f8a45605a1774d6fb8ddeda30d",
    ),
    (
        "ffffffffffffffffffffffffffffffff",
        "enc",
        32,
        "c2e2551794dea9cd8904550745adcc28baaf0179773eb0db171dc77701edae28",
    ),
    (
        "30313233343536373839616263646566",
        "enc",
        64,
        "ca36c5f105ea153f4dc6a591e97f7098bbc7c3aef2491423d9fb2ce612c84b7232009cb847d44cd2f72b47d0a293dd6227b96ce6cd2ba825e951b98e12819c0c",
    ),
    (
        "30313233343536373839616263646566",
        "mac",
        32,
        "22aec48f7ec4731e402cc64a1b31955d7757c75c5ce606e28eb47c8ad936af3f",
    ),
];

/// (texto, token)
const TOKENS: &[(&str, &str)] = &[
    (
        "",
        "FBCbBmERldK0rQ3SAu1PxJ7drr2ie-jwhDLefEaGiBsJ_2autyPG4oSs6DXEM_w6-6x",
    ),
    (
        "A",
        "FBCo5OnvHbHG6nILqXCjGzVYo32jIC9I_PAqQ9CvRxggyiYKwhedK4ynN65_SSrE_mezQ",
    ),
    (
        "TESTE",
        "FBCn7T3VBZFYnvG41Dx4VYn-tyKKd3QheLJ1kw7oDb9EhSUEfnTtlEN2Rxp1xaskppvmGSmeTI",
    ),
    (
        "mensagem de interoperabilidade entre linguagens",
        "FBCqgHvQ_SGLjte-SDNMHt3LyNB8qGUfMxn_N1PqWGdQmyE4iHtA3k45aAygQnBpqAXYxlwIxkDumz3ln33vAttxUwIuYExCrG-LaYLBUVEyuX49X86mScMpOd3isnqYhU",
    ),
];

pub struct AtaqueInteroperabilidade;

impl Ataque for AtaqueInteroperabilidade {
    fn nome(&self) -> String {
        "Interoperabilidade e vetores conhecidos (KAT)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let mut falhas: Vec<String> = Vec::new();
        let chave_fixa = "K".repeat(32);

        for &(iv_hex, proposito, tamanho, esperado) in VETORES {
            let iv = match hex_decode(iv_hex) {
                Some(v) => v,
                None => {
                    falhas.push(format!("IV inválido no vetor: {}", iv_hex));
                    continue;
                }
            };
            let ks = alvo.gerar_keystream_bruto(chave_fixa.as_bytes(), &iv, proposito, tamanho);
            if hex_encode(&ks) != esperado {
                falhas.push(format!(
                    "keystream iv={} prop={} tam={}",
                    iv_hex, proposito, tamanho
                ));
            }
        }

        for &(texto, token) in TOKENS {
            match alvo.decrypt(token) {
                Ok(decifrado) => {
                    if decifrado != texto {
                        falhas.push(format!("token não decifrou para {:?}", texto));
                    }
                }
                Err(_) => falhas.push(format!("token rejeitado: {:?}", texto)),
            }
        }

        if !falhas.is_empty() {
            let amostra: Vec<String> = falhas.iter().take(5).cloned().collect();
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Alta,
                &format!(
                    "{} divergência(s) de interoperabilidade: {}",
                    falhas.len(),
                    amostra.join("; ")
                ),
            ));
        }

        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &format!(
                "{} vetores de keystream e {} tokens de referência conferem",
                VETORES.len(),
                TOKENS.len()
            ),
        ))
    }
}
