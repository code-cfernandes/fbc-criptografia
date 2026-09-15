//! Somas cumulativas (cusum), teste do NIST SP800-22. Converte os bits em
//! passos +1/-1 e observa o maior desvio da caminhada aleatória. Um viés
//! pequeno que o monobit quase não vê faz o desvio acumulado crescer.
//! Para uma sequência aleatória, max|S|/sqrt(n) fica tipicamente abaixo de 3.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaqueCusum {
    pub tamanho: usize,
    pub limite_z: f64,
}

impl AtaqueCusum {
    pub fn new() -> Self {
        AtaqueCusum {
            tamanho: 8192,
            limite_z: 4.0,
        }
    }
}

impl Default for AtaqueCusum {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueCusum {
    fn nome(&self) -> String {
        "Somas cumulativas (cusum)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let ks = alvo.gerar_keystream_bruto(
            alvo.chave_de_teste().as_bytes(),
            &random_bytes(alvo.tamanho_iv()),
            "enc",
            self.tamanho,
        );

        let mut soma: i64 = 0;
        let mut max_abs: i64 = 0;
        for &byte in &ks {
            for b in (0..8).rev() {
                soma += if ((byte >> b) & 1) == 1 { 1 } else { -1 };
                max_abs = max_abs.max(soma.abs());
            }
        }
        let n = ks.len() * 8;
        let z = max_abs as f64 / (n as f64).sqrt();
        let vulneravel = z > self.limite_z;

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Media
            } else {
                Severidade::Info
            },
            &format!(
                "max|S|={} sobre {} bits, max|S|/sqrt(n)={:.2} (limite={:.1})",
                max_abs, n, z, self.limite_z
            ),
        ))
    }
}
