//! Busca dirigida de chaves fracas: chaves degeneradas/estruturadas não devem
//! produzir keystream anômalo (repetição, período curto, viés de bits ou
//! distribuição de bytes distorcida). Complementa o ataque de chaves
//! degeneradas, que só checa a saída do encrypt.

use std::collections::HashSet;

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::{contar_bits_buffer, hex_encode};

pub struct AtaqueChavesFracas {
    pub tamanho: usize,
    pub tolerancia_bits: f64,
}

impl AtaqueChavesFracas {
    pub fn new() -> Self {
        AtaqueChavesFracas {
            tamanho: 2048,
            tolerancia_bits: 0.05,
        }
    }
}

impl Default for AtaqueChavesFracas {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueChavesFracas {
    fn nome(&self) -> String {
        "Chaves fracas (busca dirigida)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let len = alvo.chave_de_teste().as_bytes().len();
        let casos: Vec<(&str, Vec<u8>)> = vec![
            ("zeros", vec![0x00u8; len]),
            ("0xFF", vec![0xffu8; len]),
            (
                "alternada AA/55",
                (0..len)
                    .map(|i| if i % 2 == 0 { 0xaa } else { 0x55 })
                    .collect(),
            ),
            ("incremental", (0..len).map(|i| (i & 0xff) as u8).collect()),
            (
                "um bit",
                (0..len).map(|i| if i == 0 { 1 } else { 0 }).collect(),
            ),
            ("byte repetido 0x01", vec![0x01u8; len]),
            (
                "padrão AB",
                (0..len)
                    .map(|i| if i % 2 == 0 { 0x41 } else { 0x42 })
                    .collect(),
            ),
        ];

        let iv_fixo = vec![0u8; alvo.tamanho_iv()];
        let mut anomalias: Vec<String> = Vec::new();

        for (nome, chave) in &casos {
            let ks = alvo.gerar_keystream_bruto(chave, &iv_fixo, "enc", self.tamanho);

            let mut blocos: HashSet<String> = HashSet::new();
            let mut repetidos = 0usize;
            let mut i = 0usize;
            while i + 32 <= ks.len() {
                let hex = hex_encode(&ks[i..i + 32]);
                if blocos.contains(&hex) {
                    repetidos += 1;
                } else {
                    blocos.insert(hex);
                }
                i += 32;
            }

            let fracao_uns = contar_bits_buffer(&ks) as f64 / (ks.len() * 8) as f64;
            let desvio_bits = (fracao_uns - 0.5).abs();

            if repetidos > 0 {
                anomalias.push(format!("{}: {} bloco(s) repetido(s)", nome, repetidos));
            }
            if desvio_bits > self.tolerancia_bits {
                anomalias.push(format!("{}: viés de bits {:.1}%", nome, fracao_uns * 100.0));
            }
        }

        let vulneravel = !anomalias.is_empty();

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Alta
            } else {
                Severidade::Info
            },
            &if vulneravel {
                let amostra: Vec<String> = anomalias.iter().take(5).cloned().collect();
                format!("Anomalias: {}", amostra.join("; "))
            } else {
                format!(
                    "Nenhuma das {} chaves fracas produziu keystream anômalo ({} bytes cada)",
                    casos.len(),
                    self.tamanho
                )
            },
        ))
    }
}
