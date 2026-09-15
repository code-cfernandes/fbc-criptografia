//! Ataque integral (square): fixa a chave e percorre TODOS os 256 valores de
//! um byte do IV (e da chave), fazendo XOR de todos os keystreams resultantes.
//!
//! Numa função aleatória, o XOR de 256 saídas é uniforme, então cada byte da
//! soma é zero com probabilidade 1/256. Se a cifra tiver difusão incompleta,
//! a saída como função do byte variado fica "quase bijetiva" e a soma tende a
//! zero MUITO mais que o acaso - um distinguisher clássico.
//!
//! Como uma única (chave, IV) tem variância alta, acumula várias tentativas
//! para estimar o viés de forma estável (comparado a p=1/256).

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaqueIntegral {
    pub tamanho_bloco: usize,
    pub posicoes_iv: usize,
    pub posicoes_chave: usize,
    pub tentativas: usize,
    pub limite_z: f64,
}

impl AtaqueIntegral {
    pub fn new() -> Self {
        AtaqueIntegral {
            tamanho_bloco: 32,
            posicoes_iv: 8,
            posicoes_chave: 8,
            tentativas: 16,
            limite_z: 5.0,
        }
    }
}

impl Default for AtaqueIntegral {
    fn default() -> Self {
        Self::new()
    }
}

impl AtaqueIntegral {
    /// Retorna o XOR de 256 keystreams e quantos bytes deram zero.
    fn somar_variando(
        &self,
        alvo: &dyn AlvoCriptografico,
        chave: &[u8],
        iv_base: &[u8],
        campo: char,
        pos: usize,
    ) -> (Vec<u8>, usize) {
        let mut xor = vec![0u8; self.tamanho_bloco];
        for v in 0..256usize {
            let mut k = chave.to_vec();
            let mut iv = iv_base.to_vec();
            if campo == 'i' {
                iv[pos] = v as u8;
            } else {
                k[pos] = v as u8;
            }
            let ks = alvo.gerar_keystream_bruto(&k, &iv, "enc", self.tamanho_bloco);
            for i in 0..xor.len() {
                xor[i] ^= ks[i];
            }
        }
        let zeros = xor.iter().filter(|&&b| b == 0).count();
        (xor, zeros)
    }
}

impl Ataque for AtaqueIntegral {
    fn nome(&self) -> String {
        "Integral (soma balanceada variando 1 byte de IV/chave)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let tam_iv = alvo.tamanho_iv();
        let tam_chave = alvo.chave_de_teste().as_bytes().len();

        let _primeiro = alvo.gerar_keystream_bruto(
            alvo.chave_de_teste().as_bytes(),
            &random_bytes(tam_iv),
            "enc",
            self.tamanho_bloco,
        );

        let mut distinguidores: Vec<String> = Vec::new();
        let mut zeros_total = 0usize;
        let mut bytes_total = 0usize;

        for _ in 0..self.tentativas {
            let chave = random_bytes(tam_chave);
            let iv_base = random_bytes(tam_iv);

            for pos in 0..self.posicoes_iv.min(tam_iv) {
                let (xor, zeros) = self.somar_variando(alvo, &chave, &iv_base, 'i', pos);
                zeros_total += zeros;
                bytes_total += self.tamanho_bloco;
                if xor.iter().all(|&b| b == 0) {
                    distinguidores.push(format!("iv[{}]", pos));
                }
            }

            for pos in 0..self.posicoes_chave.min(tam_chave) {
                let (xor, zeros) = self.somar_variando(alvo, &chave, &iv_base, 'k', pos);
                zeros_total += zeros;
                bytes_total += self.tamanho_bloco;
                if xor.iter().all(|&b| b == 0) {
                    distinguidores.push(format!("key[{}]", pos));
                }
            }
        }

        let p = 1.0 / 256.0;
        let esperado = bytes_total as f64 * p;
        let desvio = (bytes_total as f64 * p * (1.0 - p)).sqrt();
        let z = if desvio > 0.0 {
            (zeros_total as f64 - esperado) / desvio
        } else {
            0.0
        };

        let vulneravel = !distinguidores.is_empty() || z > self.limite_z;

        if !distinguidores.is_empty() {
            let amostra: Vec<String> = distinguidores.iter().take(10).cloned().collect();
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Critica,
                &format!(
                    "Soma balanceada (XOR zero) encontrada variando: {}",
                    amostra.join(", ")
                ),
            ));
        }

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Media
            } else {
                Severidade::Info
            },
            &format!(
                "bytes de saída zerados={} (esperado ~{:.1}, z={:.2}) em {} amostras; limite z={:.1}",
                zeros_total, esperado, z, bytes_total, self.limite_z
            ),
        ))
    }
}
