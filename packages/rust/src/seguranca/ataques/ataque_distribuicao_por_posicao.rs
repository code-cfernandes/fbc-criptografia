//! O AtaqueDistribuicaoBytes faz qui-quadrado GLOBAL. Esse faz POR POSIÇÃO do
//! bloco de 32 bytes: uma posição específica pode ter viés forte mesmo que a
//! soma global pareça uniforme (o viés de uma posição se dilui entre as 32).

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaqueDistribuicaoPorPosicao {
    pub amostras_de_blocos: usize,
    pub tamanho_bloco: usize,
}

impl AtaqueDistribuicaoPorPosicao {
    pub fn new() -> Self {
        AtaqueDistribuicaoPorPosicao {
            amostras_de_blocos: 2000,
            tamanho_bloco: 32,
        }
    }
}

impl Default for AtaqueDistribuicaoPorPosicao {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueDistribuicaoPorPosicao {
    fn nome(&self) -> String {
        "Distribuição de bytes por posição do bloco".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave = alvo.chave_de_teste();

        let mut contagens: Vec<[u64; 256]> = vec![[0u64; 256]; self.tamanho_bloco];

        for _ in 0..self.amostras_de_blocos {
            let ks = alvo.gerar_keystream_bruto(
                chave.as_bytes(),
                &random_bytes(alvo.tamanho_iv()),
                "enc",
                self.tamanho_bloco,
            );
            for p in 0..self.tamanho_bloco {
                contagens[p][ks[p] as usize] += 1;
            }
        }

        let esperado = self.amostras_de_blocos as f64 / 256.0;
        let mut problemas: Vec<String> = Vec::new();
        let mut pior = 0.0f64;

        for p in 0..contagens.len() {
            let mut chi2 = 0.0f64;
            for &v in &contagens[p] {
                chi2 += (v as f64 - esperado).powi(2) / esperado;
            }
            pior = pior.max(chi2);
            let z = (chi2 - 255.0) / (510.0f64).sqrt();
            if z > 4.0 {
                problemas.push(format!("posição {} chi2={:.1}", p, chi2));
            }
        }

        if !problemas.is_empty() {
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Media,
                &problemas.join("; "),
            ));
        }

        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &format!(
                "Todas as {} posições uniformes (pior chi2={:.1}, esperado ~255)",
                self.tamanho_bloco, pior
            ),
        ))
    }
}
