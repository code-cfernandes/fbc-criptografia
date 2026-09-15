//! Criptanálise diferencial no keystream: com uma diferença FIXA (1 bit) no
//! IV, coleta as diferenças de saída entre ks(iv) e ks(iv ^ delta). Numa cifra
//! boa, essas diferenças são uniformes e únicas. Sinaliza:
//!  - bits de saída que NUNCA mudam (ou mudam sempre) para essa diferença;
//!  - diferenças de saída que se REPETEM (diferencial de alta probabilidade),
//!    que é o insumo básico de um ataque diferencial.

use std::collections::HashSet;

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::{hex_encode, random_bytes, random_int};

pub struct AtaqueDiferencialKeystream {
    pub amostras: usize,
    pub tamanho_bloco: usize,
}

impl AtaqueDiferencialKeystream {
    pub fn new() -> Self {
        AtaqueDiferencialKeystream {
            amostras: 2000,
            tamanho_bloco: 32,
        }
    }
}

impl Default for AtaqueDiferencialKeystream {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueDiferencialKeystream {
    fn nome(&self) -> String {
        "Diferencial do keystream (delta fixo no IV)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave = random_bytes(alvo.chave_de_teste().len());
        let tamanho_iv = alvo.tamanho_iv();

        let mut delta = vec![0u8; tamanho_iv];
        delta[random_int(0, tamanho_iv as i64 - 1) as usize] =
            1u8 << (random_int(0, 7) as u32);

        let total_bits = self.tamanho_bloco * 8;
        let mut sempre_zero = vec![true; total_bits];
        let mut sempre_um = vec![true; total_bits];
        let mut deltas: HashSet<String> = HashSet::new();

        for _ in 0..self.amostras {
            let iv = random_bytes(tamanho_iv);
            let iv2: Vec<u8> = iv.iter().zip(delta.iter()).map(|(a, b)| a ^ b).collect();

            let ks1 =
                alvo.gerar_keystream_bruto(&chave, &iv, "enc", self.tamanho_bloco);
            let ks2 =
                alvo.gerar_keystream_bruto(&chave, &iv2, "enc", self.tamanho_bloco);
            let d: Vec<u8> = ks1.iter().zip(ks2.iter()).map(|(a, b)| a ^ b).collect();
            deltas.insert(hex_encode(&d));

            for p in 0..d.len() {
                let byte = d[p];
                for b in 0..8 {
                    let idx = p * 8 + b;
                    if ((byte >> b) & 1) == 1 {
                        sempre_zero[idx] = false;
                    } else {
                        sempre_um[idx] = false;
                    }
                }
            }
        }

        let mut bits_fixos = 0usize;
        for idx in 0..total_bits {
            if sempre_zero[idx] || sempre_um[idx] {
                bits_fixos += 1;
            }
        }
        let colisoes = self.amostras - deltas.len();

        let vulneravel = bits_fixos > 0 || colisoes > 0;

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Alta
            } else {
                Severidade::Info
            },
            &format!(
                "delta de 1 bit no IV: {} bit(s) de saída fixo(s), {} diferencial(is) repetido(s) em {} amostras",
                bits_fixos, colisoes, self.amostras
            ),
        ))
    }
}
