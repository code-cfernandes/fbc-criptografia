//! Estatística só do CIPHERTEXT (não do keystream): distribuição de bytes
//! (qui-quadrado), teste de runs nos bits e autocorrelação lag-1. Um ciphertext
//! de cifra sólida deve parecer ruído mesmo com plaintext variado.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaqueCiphertextEstatistico {
    pub amostras: usize,
    pub tamanho_texto: usize,
    pub z_limite: f64,
}

impl AtaqueCiphertextEstatistico {
    pub fn new() -> Self {
        AtaqueCiphertextEstatistico {
            amostras: 200,
            tamanho_texto: 64,
            z_limite: 4.0,
        }
    }
}

impl Default for AtaqueCiphertextEstatistico {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueCiphertextEstatistico {
    fn nome(&self) -> String {
        "Estatística do ciphertext (chi²/runs/autocorrelação)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let mut contagem = [0u64; 256];
        let mut bytes: Vec<u8> = Vec::new();

        for _ in 0..self.amostras {
            let texto = random_bytes(self.tamanho_texto);
            let token = alvo
                .encrypt(&texto)
                .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
            let decodificado = alvo
                .base64url_decode(&token[alvo.prefixo().len()..])
                .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
            let campos = alvo.decompor(&decodificado);
            for b in campos.ciphertext {
                contagem[b as usize] += 1;
                bytes.push(b);
            }
        }

        let total = bytes.len();
        let esperado = total as f64 / 256.0;
        let mut chi2 = 0.0f64;
        for &c in &contagem {
            let d = c as f64 - esperado;
            chi2 += d * d / esperado;
        }

        // runs test nos bits do ciphertext
        let mut uns = 0usize;
        let mut bits: Vec<u8> = Vec::with_capacity(total * 8);
        for &b in &bytes {
            for k in (0..8).rev() {
                let bit = (b >> k) & 1;
                bits.push(bit);
                uns += bit as usize;
            }
        }
        let n = bits.len();
        let pi = uns as f64 / n as f64;
        let mut runs = 1usize;
        for i in 1..n {
            if bits[i] != bits[i - 1] {
                runs += 1;
            }
        }
        let esperado_runs = 2.0 * n as f64 * pi * (1.0 - pi);
        let desvio_runs = 2.0 * (2.0 * n as f64).sqrt() * pi * (1.0 - pi);
        let z_runs = if desvio_runs > 0.0 {
            (runs as f64 - esperado_runs).abs() / desvio_runs
        } else {
            0.0
        };

        // autocorrelação lag-1
        let media = bytes.iter().map(|&b| b as f64).sum::<f64>() / total as f64;
        let mut num = 0.0f64;
        let mut den = 0.0f64;
        for &b in &bytes {
            den += (b as f64 - media).powi(2);
        }
        for i in 0..total.saturating_sub(1) {
            num += (bytes[i] as f64 - media) * (bytes[i + 1] as f64 - media);
        }
        let autocorr = if den > 0.0 { num / den } else { 0.0 };

        let mut problemas: Vec<String> = Vec::new();
        if chi2 > 330.0 {
            problemas.push(format!("qui-quadrado={:.1} (>330 suspeito)", chi2));
        }
        if z_runs > self.z_limite {
            problemas.push(format!("runs z={:.2}", z_runs));
        }
        if autocorr.abs() > 0.1 {
            problemas.push(format!("autocorrelação={:.3}", autocorr));
        }

        let vulneravel = !problemas.is_empty();

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Media
            } else {
                Severidade::Info
            },
            &if vulneravel {
                problemas.join("; ")
            } else {
                format!(
                    "qui-quadrado={:.1} sobre {} bytes, runs z={:.2}, autocorrelação={:.3} - todos dentro do esperado",
                    chi2, total, z_runs, autocorr
                )
            },
        ))
    }
}
