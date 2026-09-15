//! BIC (Bit Independence Criterion): pares de bits de saída não devem estar
//! correlacionados quando a entrada muda. Para cada amostra, vira 1 bit do IV
//! e registra quais bits de saída mudaram; depois mede a correlação (phi) entre
//! cada par de bits de saída. Pares muito correlacionados indicam difusão
//! acoplada (um bit "carrega" informação sobre outro).

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::{random_bytes, random_int};

pub struct AtaqueBIC {
    pub tamanho_bloco: usize,
    pub amostras: usize,
    pub limite: f64,
}

impl AtaqueBIC {
    pub fn new() -> Self {
        AtaqueBIC {
            tamanho_bloco: 32,
            amostras: 300,
            limite: 0.35,
        }
    }
}

impl Default for AtaqueBIC {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueBIC {
    fn nome(&self) -> String {
        "BIC (Bit Independence Criterion)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave = alvo.chave_de_teste();
        let total_bits = self.tamanho_bloco * 8;
        let tamanho_iv = alvo.tamanho_iv();

        let mut amostras_flips: Vec<Vec<u8>> = Vec::with_capacity(self.amostras);
        for _ in 0..self.amostras {
            let iv1 = random_bytes(tamanho_iv);
            let mut iv2 = iv1.clone();
            let pos = random_int(0, tamanho_iv as i64 - 1) as usize;
            iv2[pos] ^= 1u8 << (random_int(0, 7) as u32);

            let ks1 =
                alvo.gerar_keystream_bruto(chave.as_bytes(), &iv1, "enc", self.tamanho_bloco);
            let ks2 =
                alvo.gerar_keystream_bruto(chave.as_bytes(), &iv2, "enc", self.tamanho_bloco);

            let mut flips = vec![0u8; total_bits];
            for j in 0..total_bits {
                let b1 = (ks1[j >> 3] >> (7 - (j & 7))) & 1;
                let b2 = (ks2[j >> 3] >> (7 - (j & 7))) & 1;
                flips[j] = if b1 != b2 { 1 } else { 0 };
            }
            amostras_flips.push(flips);
        }

        let mut pior_phi = 0.0f64;
        let mut pior_par: (i64, i64) = (-1, -1);
        let n = self.amostras;

        for a in 0..total_bits {
            for b in (a + 1)..total_bits {
                let mut n11 = 0usize;
                let mut n10 = 0usize;
                let mut n01 = 0usize;
                let mut n00 = 0usize;
                for flips in &amostras_flips {
                    let fa = flips[a];
                    let fb = flips[b];
                    if fa == 1 && fb == 1 {
                        n11 += 1;
                    } else if fa == 1 && fb == 0 {
                        n10 += 1;
                    } else if fa == 0 && fb == 1 {
                        n01 += 1;
                    } else {
                        n00 += 1;
                    }
                }
                let den = (((n11 + n10) * (n01 + n00) * (n11 + n01) * (n10 + n00)) as f64)
                    .sqrt();
                let phi = if den > 0.0 {
                    ((n11 * n00) as f64 - (n10 * n01) as f64) / den
                } else {
                    0.0
                };
                if phi.abs() > pior_phi.abs() {
                    pior_phi = phi;
                    pior_par = (a as i64, b as i64);
                }
            }
        }

        let vulneravel = pior_phi.abs() > self.limite;

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Alta
            } else {
                Severidade::Info
            },
            &format!(
                "maior |phi|={:.3} entre bits de saída [{}, {}] (limite {}); {} amostras",
                pior_phi.abs(),
                pior_par.0,
                pior_par.1,
                self.limite,
                n
            ),
        ))
    }
}
