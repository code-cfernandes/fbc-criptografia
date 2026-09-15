//! Procura linearidade no checksum, que seria fatal para um MAC:
//!  1. cs(a) XOR cs(b) == cs(a XOR b)? (linearidade sobre GF(2))
//!  2. para um delta d fixo, cs(a XOR d) XOR cs(a) deve ser diferente para
//!     cada a; se repetir muito, existe um diferencial de alta probabilidade
//!     que ajuda a forjar MACs.

use std::collections::HashMap;

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::{hex_encode, random_bytes};

pub struct AtaqueLinearidadeChecksum {
    pub amostras_linearidade: usize,
    pub amostras_diferencial: usize,
    pub tamanho_entrada: usize,
}

impl AtaqueLinearidadeChecksum {
    pub fn new() -> Self {
        AtaqueLinearidadeChecksum {
            amostras_linearidade: 5000,
            amostras_diferencial: 500,
            tamanho_entrada: 32,
        }
    }
}

impl Default for AtaqueLinearidadeChecksum {
    fn default() -> Self {
        Self::new()
    }
}

impl AtaqueLinearidadeChecksum {
    fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
        let len = a.len().min(b.len());
        (0..len).map(|i| a[i] ^ b[i]).collect()
    }
}

impl Ataque for AtaqueLinearidadeChecksum {
    fn nome(&self) -> String {
        "Linearidade e diferenciais do checksum".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave_mac = "M".repeat(32);
        let _primeiro = alvo.checksum_bruto(b"teste", chave_mac.as_bytes());

        let mut relacoes_lineares = 0usize;
        for _ in 0..self.amostras_linearidade {
            let a = random_bytes(self.tamanho_entrada);
            let b = random_bytes(self.tamanho_entrada);
            let lhs = Self::xor_bytes(
                &alvo.checksum_bruto(&a, chave_mac.as_bytes()),
                &alvo.checksum_bruto(&b, chave_mac.as_bytes()),
            );
            let rhs = alvo.checksum_bruto(&Self::xor_bytes(&a, &b), chave_mac.as_bytes());
            if lhs == rhs {
                relacoes_lineares += 1;
            }
        }

        let mut max_repeticoes_diferencial = 0usize;
        for _ in 0..5 {
            let delta = random_bytes(self.tamanho_entrada);
            let mut vistos: HashMap<String, usize> = HashMap::new();
            for _ in 0..self.amostras_diferencial {
                let a = random_bytes(self.tamanho_entrada);
                let dif = Self::xor_bytes(
                    &alvo.checksum_bruto(&Self::xor_bytes(&a, &delta), chave_mac.as_bytes()),
                    &alvo.checksum_bruto(&a, chave_mac.as_bytes()),
                );
                *vistos.entry(hex_encode(&dif)).or_insert(0) += 1;
            }
            let max_vistos = vistos.values().copied().max().unwrap_or(0);
            max_repeticoes_diferencial = max_repeticoes_diferencial.max(max_vistos);
        }

        let vulneravel = relacoes_lineares > 0 || max_repeticoes_diferencial > 1;

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Critica
            } else {
                Severidade::Info
            },
            &format!(
                "{}/{} relações lineares; maior repetição de diferencial={} (esperado 1)",
                relacoes_lineares, self.amostras_linearidade, max_repeticoes_diferencial
            ),
        ))
    }
}
