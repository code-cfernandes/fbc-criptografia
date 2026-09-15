//! Mudar 1 bit do IV deveria, em média, mudar ~50% dos bits do keystream
//! gerado (efeito avalanche). Números muito abaixo disso indicam difusão
//! fraca - foi o que achamos quando o número de rodadas de mistura era
//! baixo demais numa das versões anteriores.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::{bits_diferentes, random_bytes, random_int};

pub struct AtaqueAvalanche {
    pub amostras: usize,
    pub tamanho_bloco: usize,
    pub limite_media: f64,
    pub limite_pior_caso: f64,
}

impl AtaqueAvalanche {
    pub fn new() -> Self {
        AtaqueAvalanche {
            amostras: 3000,
            tamanho_bloco: 32,
            limite_media: 0.45,
            limite_pior_caso: 0.3,
        }
    }
}

impl Default for AtaqueAvalanche {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueAvalanche {
    fn nome(&self) -> String {
        "Efeito avalanche".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave = alvo.chave_de_teste();
        let tamanho_iv = alvo.tamanho_iv();

        let mut valores: Vec<f64> = Vec::with_capacity(self.amostras);
        for _ in 0..self.amostras {
            let iv1 = random_bytes(tamanho_iv);
            let mut iv2 = iv1.clone();
            let pos = random_int(0, tamanho_iv as i64 - 1) as usize;
            iv2[pos] ^= 1u8 << (random_int(0, 7) as u32);

            let ks1 =
                alvo.gerar_keystream_bruto(chave.as_bytes(), &iv1, "enc", self.tamanho_bloco);
            let ks2 =
                alvo.gerar_keystream_bruto(chave.as_bytes(), &iv2, "enc", self.tamanho_bloco);

            valores.push(bits_diferentes(&ks1, &ks2) as f64 / (self.tamanho_bloco * 8) as f64);
        }

        valores.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let n = valores.len();
        let media: f64 = valores.iter().sum::<f64>() / n as f64;
        let pior_caso = valores[0];

        let vulneravel = media < self.limite_media || pior_caso < self.limite_pior_caso;

        let percentil = valores[(n as f64 * 0.01) as usize];

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Alta
            } else {
                Severidade::Info
            },
            &format!(
                "média={:.1}%, pior caso={:.1}%, percentil 1%={:.1}% (limites: média>={:.0}%, pior>={:.0}%)",
                media * 100.0,
                pior_caso * 100.0,
                percentil * 100.0,
                self.limite_media * 100.0,
                self.limite_pior_caso * 100.0
            ),
        ))
    }
}
