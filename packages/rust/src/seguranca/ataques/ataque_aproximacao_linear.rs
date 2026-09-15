//! Aproximação linear (criptoanálise de Matsui): procura por correlação entre
//! bits de entrada (IV) e bits de saída do keystream. Uma cifra ideal não tem
//! aproximação linear com viés relevante; bias alto é uma pista explorável.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaqueAproximacaoLinear {
    pub amostras: usize,
    pub tamanho_bloco: usize,
    pub limite_bias: f64,
}

impl AtaqueAproximacaoLinear {
    pub fn new() -> Self {
        AtaqueAproximacaoLinear {
            amostras: 200,
            tamanho_bloco: 32,
            limite_bias: 0.3,
        }
    }
}

impl Default for AtaqueAproximacaoLinear {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueAproximacaoLinear {
    fn nome(&self) -> String {
        "Aproximação linear (viés de Walsh)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let tam_iv = alvo.tamanho_iv();
        let tam_chave = alvo.chave_de_teste().len();
        let bits_entrada = tam_iv * 8;
        let bits_saida = self.tamanho_bloco * 8;

        let mut entradas: Vec<Vec<u8>> = Vec::with_capacity(self.amostras);
        let mut saidas: Vec<Vec<u8>> = Vec::with_capacity(self.amostras);

        for _ in 0..self.amostras {
            let chave = random_bytes(tam_chave);
            let iv = random_bytes(tam_iv);
            let ks = alvo.gerar_keystream_bruto(&chave, &iv, "enc", self.tamanho_bloco);

            let mut in_bits = vec![0u8; bits_entrada];
            for j in 0..bits_entrada {
                in_bits[j] = (iv[j >> 3] >> (7 - (j & 7))) & 1;
            }
            let mut out_bits = vec![0u8; bits_saida];
            for j in 0..bits_saida {
                out_bits[j] = (ks[j >> 3] >> (7 - (j & 7))) & 1;
            }
            entradas.push(in_bits);
            saidas.push(out_bits);
        }

        let mut maior_bias = 0.0f64;
        let mut par: (i64, i64) = (-1, -1);
        for i in 0..bits_entrada {
            for j in 0..bits_saida {
                let iguais = entradas
                    .iter()
                    .zip(saidas.iter())
                    .filter(|(entrada, saida)| entrada[i] == saida[j])
                    .count();
                let bias = (iguais as f64 / self.amostras as f64 - 0.5).abs();
                if bias > maior_bias {
                    maior_bias = bias;
                    par = (i as i64, j as i64);
                }
            }
        }

        let vulneravel = maior_bias > self.limite_bias;

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Alta
            } else {
                Severidade::Info
            },
            &format!(
                "maior viés |p-0.5|={:.4} na aproximação IV[bit {}] -> saída[bit {}] (limite {}); {} amostras",
                maior_bias, par.0, par.1, self.limite_bias, self.amostras
            ),
        ))
    }
}
