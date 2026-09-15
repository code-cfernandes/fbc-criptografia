//! Um keystream de qualidade deve ter bytes distribuídos uniformemente entre
//! 0-255. Um viés forte (qui-quadrado muito alto) indica que alguns valores
//! de byte saem com mais frequência que outros - sinal de fraqueza estatística
//! na função de mistura.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaqueDistribuicaoBytes {
    pub amostras_de_blocos: usize,
    pub tamanho_bloco: usize,
}

impl AtaqueDistribuicaoBytes {
    pub fn new() -> Self {
        AtaqueDistribuicaoBytes {
            amostras_de_blocos: 500,
            tamanho_bloco: 32,
        }
    }
}

impl Default for AtaqueDistribuicaoBytes {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueDistribuicaoBytes {
    fn nome(&self) -> String {
        "Distribuição de bytes (qui-quadrado)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave = alvo.chave_de_teste();

        let mut contagem = [0u64; 256];
        let mut total = 0u64;
        for _ in 0..self.amostras_de_blocos {
            let ks = alvo.gerar_keystream_bruto(
                chave.as_bytes(),
                &random_bytes(alvo.tamanho_iv()),
                "enc",
                self.tamanho_bloco,
            );
            for &b in &ks {
                contagem[b as usize] += 1;
                total += 1;
            }
        }

        let esperado = total as f64 / 256.0;
        let mut qui2 = 0.0f64;
        for &c in &contagem {
            qui2 += (c as f64 - esperado).powi(2) / esperado;
        }

        // Com 255 graus de liberdade, valores acima de ~330 já são
        // estatisticamente suspeitos (p < 0.01); acima de ~380, bem suspeitos.
        let vulneravel = qui2 > 330.0;

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Media
            } else {
                Severidade::Info
            },
            &format!(
                "qui-quadrado={:.1} sobre {} bytes (255 graus de liberdade; >330 é suspeito)",
                qui2, total
            ),
        ))
    }
}
