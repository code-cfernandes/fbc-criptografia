//! Ataque de chave relacionada: chaves que diferem por um padrão fixo (1 bit,
//! 0xFF, complemento) não devem gerar keystreams correlacionados. Um key
//! schedule fraco faz `keystream(key)` e `keystream(key ^ delta)` compartilharem
//! estrutura (distância de Hamming baixa).

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::{bits_diferentes, random_bytes};

pub struct AtaqueChaveRelacionada {
    pub tamanho_bloco: usize,
    pub iv_por_delta: usize,
    pub limite_media: f64,
    pub limite_pior: f64,
}

impl AtaqueChaveRelacionada {
    pub fn new() -> Self {
        AtaqueChaveRelacionada {
            tamanho_bloco: 32,
            iv_por_delta: 3,
            limite_media: 0.45,
            limite_pior: 0.3,
        }
    }
}

impl Default for AtaqueChaveRelacionada {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueChaveRelacionada {
    fn nome(&self) -> String {
        "Chave relacionada (related-key)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave_base = alvo.chave_de_teste();
        let chave_base = chave_base.as_bytes();
        let len = chave_base.len();

        let mut deltas: Vec<Vec<u8>> = Vec::new();
        for i in 0..len {
            let mut d = vec![0u8; len];
            d[i] = 0x01;
            deltas.push(d);
        }
        for i in 0..len {
            let mut d = vec![0u8; len];
            d[i] = 0xff;
            deltas.push(d);
        }
        let complemento: Vec<u8> = chave_base.iter().map(|b| b ^ 0xff).collect();
        deltas.push(complemento);

        let mut valores: Vec<f64> = Vec::new();
        let total_bits = self.tamanho_bloco * 8;

        for delta in &deltas {
            let chave_relacionada: Vec<u8> =
                chave_base.iter().zip(delta.iter()).map(|(a, b)| a ^ b).collect();
            for _ in 0..self.iv_por_delta {
                let iv = random_bytes(alvo.tamanho_iv());
                let ks1 =
                    alvo.gerar_keystream_bruto(chave_base, &iv, "enc", self.tamanho_bloco);
                let ks2 = alvo.gerar_keystream_bruto(
                    &chave_relacionada,
                    &iv,
                    "enc",
                    self.tamanho_bloco,
                );
                valores.push(bits_diferentes(&ks1, &ks2) as f64 / total_bits as f64);
            }
        }

        let media = valores.iter().sum::<f64>() / valores.len() as f64;
        let pior = valores.iter().copied().fold(f64::INFINITY, f64::min);
        let vulneravel = media < self.limite_media || pior < self.limite_pior;

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Alta
            } else {
                Severidade::Info
            },
            &format!(
                "média={:.1}%, pior={:.1}% em {} pares (limites: média>={:.0}%, pior>={:.0}%)",
                media * 100.0,
                pior * 100.0,
                valores.len(),
                self.limite_media * 100.0,
                self.limite_pior * 100.0
            ),
        ))
    }
}
