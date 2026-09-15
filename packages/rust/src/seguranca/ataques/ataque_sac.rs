//! SAC (Strict Avalanche Criterion): para CADA bit de entrada (IV), ao virar
//! esse bit, CADA bit de saída deve mudar com probabilidade ~0.5. Mede o pior
//! bit de saída; se algum fica longe de 50%, a difusão tem ponto cego.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaqueSAC {
    pub tamanho_bloco: usize,
    pub amostras: usize,
    pub tolerancia: f64,
}

impl AtaqueSAC {
    pub fn new() -> Self {
        AtaqueSAC {
            tamanho_bloco: 32,
            amostras: 40,
            tolerancia: 0.05,
        }
    }
}

impl Default for AtaqueSAC {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueSAC {
    fn nome(&self) -> String {
        "SAC (Strict Avalanche Criterion)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave = alvo.chave_de_teste();
        let total_bits = self.tamanho_bloco * 8;
        let mut flips = vec![0usize; total_bits];
        let tamanho_iv = alvo.tamanho_iv();
        let mut total = 0usize;

        for pos in 0..tamanho_iv {
            for bit in 0..8 {
                for _ in 0..self.amostras {
                    let iv1 = random_bytes(tamanho_iv);
                    let mut iv2 = iv1.clone();
                    iv2[pos] ^= 1u8 << bit;

                    let ks1 = alvo.gerar_keystream_bruto(
                        chave.as_bytes(),
                        &iv1,
                        "enc",
                        self.tamanho_bloco,
                    );
                    let ks2 = alvo.gerar_keystream_bruto(
                        chave.as_bytes(),
                        &iv2,
                        "enc",
                        self.tamanho_bloco,
                    );

                    for j in 0..total_bits {
                        let b1 = (ks1[j >> 3] >> (7 - (j & 7))) & 1;
                        let b2 = (ks2[j >> 3] >> (7 - (j & 7))) & 1;
                        if b1 != b2 {
                            flips[j] += 1;
                        }
                    }
                    total += 1;
                }
            }
        }

        let mut pior = -1i64;
        let mut pior_desvio = 0.0f64;
        let mut pior_p = 0.5f64;
        for j in 0..total_bits {
            let p = flips[j] as f64 / total as f64;
            let desvio = (p - 0.5).abs();
            if desvio > pior_desvio {
                pior_desvio = desvio;
                pior = j as i64;
                pior_p = p;
            }
        }

        let vulneravel = pior_desvio > self.tolerancia;
        let detalhes = format!(
            "pior bit de saída={}: p={:.2}% (esperado 50%, tolerância ±{:.1}%); {} amostras por bit de entrada",
            pior,
            pior_p * 100.0,
            self.tolerancia * 100.0,
            total
        );

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Alta
            } else {
                Severidade::Info
            },
            &detalhes,
        ))
    }
}
