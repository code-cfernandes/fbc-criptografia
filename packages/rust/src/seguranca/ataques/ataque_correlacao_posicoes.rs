//! Verifica se posições DIFERENTES dentro do mesmo bloco de 32 bytes saem
//! correlacionadas (ex: posição 0 acompanha posição 16). Uma correlação entre
//! posições de saída é exatamente o tipo de estrutura que o antigo bug da
//! "metade igual" produzia - e que a autocorrelação temporal pode não pegar.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaqueCorrelacaoPosicoes {
    pub amostras: usize,
    pub tamanho_bloco: usize,
    pub limite_correlacao: f64,
}

impl AtaqueCorrelacaoPosicoes {
    pub fn new() -> Self {
        AtaqueCorrelacaoPosicoes {
            amostras: 3000,
            tamanho_bloco: 32,
            limite_correlacao: 0.15,
        }
    }
}

impl Default for AtaqueCorrelacaoPosicoes {
    fn default() -> Self {
        Self::new()
    }
}

impl AtaqueCorrelacaoPosicoes {
    fn pearson(blocos: &[Vec<u8>], a: usize, b: usize) -> f64 {
        let n = blocos.len();
        let mut ma = 0.0f64;
        let mut mb = 0.0f64;
        for d in blocos {
            ma += d[a] as f64;
            mb += d[b] as f64;
        }
        ma /= n as f64;
        mb /= n as f64;

        let mut num = 0.0f64;
        let mut da = 0.0f64;
        let mut db = 0.0f64;
        for d in blocos {
            let xa = d[a] as f64 - ma;
            let xb = d[b] as f64 - mb;
            num += xa * xb;
            da += xa * xa;
            db += xb * xb;
        }

        if da > 0.0 && db > 0.0 {
            num / (da * db).sqrt()
        } else {
            0.0
        }
    }
}

impl Ataque for AtaqueCorrelacaoPosicoes {
    fn nome(&self) -> String {
        "Correlação entre posições do bloco".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave = alvo.chave_de_teste();

        let mut blocos: Vec<Vec<u8>> = Vec::with_capacity(self.amostras);
        for _ in 0..self.amostras {
            blocos.push(alvo.gerar_keystream_bruto(
                chave.as_bytes(),
                &random_bytes(alvo.tamanho_iv()),
                "enc",
                self.tamanho_bloco,
            ));
        }

        let mut suspeitos: Vec<String> = Vec::new();
        let mut pior = 0.0f64;

        for a in 0..self.tamanho_bloco {
            for b in (a + 1)..self.tamanho_bloco {
                let corr = Self::pearson(&blocos, a, b);
                if corr.abs() > pior.abs() {
                    pior = corr;
                }
                if corr.abs() > self.limite_correlacao {
                    suspeitos.push(format!("posições {}-{} (r={:.3})", a, b, corr));
                }
            }
        }

        if !suspeitos.is_empty() {
            let amostra: Vec<String> = suspeitos.iter().take(10).cloned().collect();
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Alta,
                &format!(
                    "{} par(es) correlacionado(s): {}",
                    suspeitos.len(),
                    amostra.join("; ")
                ),
            ));
        }

        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &format!(
                "Nenhum par de posições correlacionado acima de {:.2} (pior |r|={:.3})",
                self.limite_correlacao,
                pior.abs()
            ),
        ))
    }
}
