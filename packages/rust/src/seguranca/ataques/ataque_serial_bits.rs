//! Teste serial: frequência de padrões SOBREPOSTOS de m bits (m=2,3,4). Um
//! gerador bom distribui todos os 2^m padrões de forma uniforme. Estruturas
//! locais (certos pares/triplas de bits que nunca ou quase nunca ocorrem)
//! aparecem aqui mesmo quando a contagem global de bytes parece uniforme.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaqueSerialBits {
    pub tamanho: usize,
    pub ordens: Vec<usize>,
}

impl AtaqueSerialBits {
    pub fn new() -> Self {
        AtaqueSerialBits {
            tamanho: 4096,
            ordens: vec![2, 3, 4],
        }
    }
}

impl Default for AtaqueSerialBits {
    fn default() -> Self {
        Self::new()
    }
}

impl AtaqueSerialBits {
    fn para_bits(bytes: &[u8]) -> Vec<u8> {
        let mut bits: Vec<u8> = Vec::with_capacity(bytes.len() * 8);
        for &byte in bytes {
            for b in (0..8).rev() {
                bits.push((byte >> b) & 1);
            }
        }
        bits
    }
}

impl Ataque for AtaqueSerialBits {
    fn nome(&self) -> String {
        "Teste serial (padrões de bits sobrepostos)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let ks = alvo.gerar_keystream_bruto(
            alvo.chave_de_teste().as_bytes(),
            &random_bytes(alvo.tamanho_iv()),
            "enc",
            self.tamanho,
        );

        let bits = Self::para_bits(&ks);
        let n = bits.len();

        let mut problemas: Vec<String> = Vec::new();

        for &m in &self.ordens {
            let total = 1usize << m;
            let mut contagem = vec![0usize; total];
            let janelas = n - m + 1;

            for i in 0..janelas {
                let mut v = 0usize;
                for j in 0..m {
                    v = (v << 1) | bits[i + j] as usize;
                }
                contagem[v] += 1;
            }

            let esperado = janelas as f64 / total as f64;
            let mut chi2 = 0.0f64;
            for &c in &contagem {
                chi2 += (c as f64 - esperado).powi(2) / esperado;
            }
            let dof = (total - 1) as f64;
            // Wilson-Hilferty: aproxima chi² por normal de forma bem mais precisa
            // para dof pequeno. O z "ingênuo" (chi2-dof)/sqrt(2*dof) dá ~5% de falso
            // positivo em dof=3 (m=2); este fica em ~0.005%.
            let z = ((chi2 / dof).powf(1.0 / 3.0) - (1.0 - 2.0 / (9.0 * dof)))
                / (2.0 / (9.0 * dof)).sqrt();

            if z > 6.0 {
                problemas.push(format!("m={} chi2={:.1} (z={:.1})", m, chi2, z));
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
            "Padrões sobrepostos de 2/3/4 bits com frequência uniforme",
        ))
    }
}
