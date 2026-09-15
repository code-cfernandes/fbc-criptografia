//! Bateria estatística no keystream (inspirada em NIST SP800-22): frequência
//! global (monobit), frequência por posição de bit, teste de runs e frequência
//! por bloco. Diferente do qui-quadrado de bytes, aqui o foco é o nível de BIT
//! e a estrutura de sequência - vieses que a contagem de bytes pode mascarar.
//!
//! Usa z-scores com limite conservador (4 desvios) em vez de p-valores exatos,
//! pra não depender de funções numéricas especiais.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaqueBateriaEstatistica {
    pub tamanho: usize,
    pub z_limite: f64,
}

impl AtaqueBateriaEstatistica {
    pub fn new() -> Self {
        AtaqueBateriaEstatistica {
            tamanho: 16384,
            z_limite: 4.0,
        }
    }
}

impl Default for AtaqueBateriaEstatistica {
    fn default() -> Self {
        Self::new()
    }
}

impl AtaqueBateriaEstatistica {
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

impl Ataque for AtaqueBateriaEstatistica {
    fn nome(&self) -> String {
        "Bateria estatística de bits (monobit/runs/blocos)".to_string()
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

        // 1) Monobit: soma +1/-1
        let mut soma: i64 = 0;
        for &b in &bits {
            soma += if b == 1 { 1 } else { -1 };
        }
        let z_monobit = soma.unsigned_abs() as f64 / (n as f64).sqrt();
        if z_monobit > self.z_limite {
            problemas.push(format!("monobit z={:.2}", z_monobit));
        }

        // 2) Frequência por posição de bit
        let mut uns_por_pos = [0usize; 8];
        let mut conta_por_pos = [0usize; 8];
        for &byte in &ks {
            for b in 0..8 {
                if ((byte >> b) & 1) == 1 {
                    uns_por_pos[b] += 1;
                }
                conta_por_pos[b] += 1;
            }
        }
        let mut pos_viesadas: Vec<usize> = Vec::new();
        for b in 0..8 {
            let frac = uns_por_pos[b] as f64 / conta_por_pos[b] as f64;
            let z = (frac - 0.5).abs() / (0.5 / (conta_por_pos[b] as f64).sqrt());
            if z > self.z_limite {
                pos_viesadas.push(b);
            }
        }
        if !pos_viesadas.is_empty() {
            let lista: Vec<String> = pos_viesadas.iter().map(|b| b.to_string()).collect();
            problemas.push("viés por posição de bit: ".to_string() + &lista.join(", "));
        }

        // 3) Runs test
        let mut runs_z: Option<f64> = None;
        let pi = bits.iter().map(|&b| b as usize).sum::<usize>() as f64 / n as f64;
        if (pi - 0.5).abs() < 2.0 / (n as f64).sqrt() {
            let mut runs = 1usize;
            for i in 1..n {
                if bits[i] != bits[i - 1] {
                    runs += 1;
                }
            }
            let esperado = 2.0 * n as f64 * pi * (1.0 - pi);
            let desvio = 2.0 * (2.0 * n as f64).sqrt() * pi * (1.0 - pi);
            let z_runs = (runs as f64 - esperado).abs() / desvio;
            runs_z = Some(z_runs);
            if z_runs > self.z_limite {
                problemas.push(format!("runs z={:.2}", z_runs));
            }
        }

        // 4) Frequência por bloco (M = 128 bits)
        let mut blocos_chi2: Option<f64> = None;
        let m = 128usize;
        let num_blocos = n / m;
        if num_blocos > 0 {
            let mut chi = 0.0f64;
            for i in 0..num_blocos {
                let mut uns = 0usize;
                for j in 0..m {
                    uns += bits[i * m + j] as usize;
                }
                chi += (uns as f64 / m as f64 - 0.5).powi(2);
            }
            chi *= 4.0 * m as f64;
            let z_blocos = (chi - num_blocos as f64) / (2.0 * num_blocos as f64).sqrt();
            blocos_chi2 = Some(chi);
            if z_blocos > self.z_limite {
                problemas.push(format!("frequência por bloco chi2={:.1}", chi));
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
                "monobit z={:.2}, runs z={:.2}, blocos chi2={:.1} - todos abaixo do limite z={:.0}",
                z_monobit,
                runs_z.unwrap_or(0.0),
                blocos_chi2.unwrap_or(0.0),
                self.z_limite
            ),
        ))
    }
}
