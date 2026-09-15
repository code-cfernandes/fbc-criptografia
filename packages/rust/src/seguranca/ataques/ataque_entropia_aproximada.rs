//! Entropia aproximada (ApEn), inspirado no NIST SP800-22. Mede a
//! previsibilidade local: para uma sequência aleatória, a chance de repetir um
//! bloco de m bits deve cair suavemente conforme m cresce. Estruturas
//! periódicas/recorrentes produzem ApEn anômala.
//!
//! O estatístico chi2 = 2n(ln2 - ApEn) tem viés para n finito, então NÃO usamos
//! um valor esperado teórico. Comparamos o keystream com um CONTROLE de
//! random_bytes nas MESMAS condições - se a cifra for boa, os dois devem ser
//! estatisticamente indistinguíveis.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaqueEntropiaAproximada {
    pub tamanho: usize,
    pub m: usize,
    pub controles: usize,
    pub amostras_keystream: usize,
    pub limite_z: f64,
}

impl AtaqueEntropiaAproximada {
    pub fn new() -> Self {
        AtaqueEntropiaAproximada {
            tamanho: 4096,
            m: 8,
            controles: 12,
            amostras_keystream: 3,
            limite_z: 5.0,
        }
    }
}

impl Default for AtaqueEntropiaAproximada {
    fn default() -> Self {
        Self::new()
    }
}

impl AtaqueEntropiaAproximada {
    /// chi2 = 2n(ln2 - ApEn(m)), com ApEn = phi(m) - phi(m+1).
    fn estatistico(&self, bytes: &[u8]) -> f64 {
        let bits = Self::para_bits(bytes);
        let n = bits.len();
        let apen = Self::phi(&bits, self.m, n) - Self::phi(&bits, self.m + 1, n);
        return 2.0 * n as f64 * (std::f64::consts::LN_2 - apen);
    }

    fn phi(bits: &[u8], m: usize, n: usize) -> f64 {
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

        let mut soma = 0.0f64;
        for &c in &contagem {
            if c > 0 {
                let p = c as f64 / janelas as f64;
                soma += p * p.ln();
            }
        }

        soma
    }

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

impl Ataque for AtaqueEntropiaAproximada {
    fn nome(&self) -> String {
        "Entropia aproximada (ApEn vs controle aleatório)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let mut chi_controle: Vec<f64> = Vec::with_capacity(self.controles);
        for _ in 0..self.controles {
            chi_controle.push(self.estatistico(&random_bytes(self.tamanho)));
        }
        let media_controle = chi_controle.iter().sum::<f64>() / chi_controle.len() as f64;
        let mut variancia = 0.0f64;
        for v in &chi_controle {
            variancia += (v - media_controle).powi(2);
        }
        let desvio_controle =
            (variancia / (chi_controle.len() as f64 - 1.0).max(1.0)).sqrt();

        let mut chi_keystream: Vec<f64> = Vec::with_capacity(self.amostras_keystream);
        for _ in 0..self.amostras_keystream {
            let ks = alvo.gerar_keystream_bruto(
                alvo.chave_de_teste().as_bytes(),
                &random_bytes(alvo.tamanho_iv()),
                "enc",
                self.tamanho,
            );
            chi_keystream.push(self.estatistico(&ks));
        }
        let media_keystream = chi_keystream.iter().sum::<f64>() / chi_keystream.len() as f64;

        let z = if desvio_controle > 0.0 {
            (media_keystream - media_controle) / desvio_controle
        } else {
            0.0
        };
        let vulneravel = z.abs() > self.limite_z;

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Media
            } else {
                Severidade::Info
            },
            &format!(
                "chi2 keystream={:.1}, controle={:.1} (sd={:.1}), z={:.2} (limite={:.1})",
                media_keystream, media_controle, desvio_controle, z, self.limite_z
            ),
        ))
    }
}
