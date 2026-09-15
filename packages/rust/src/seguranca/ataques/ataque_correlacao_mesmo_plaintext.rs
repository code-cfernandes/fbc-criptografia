//! O AtaqueColisaoIV já garante que o MESMO plaintext nunca reusa o IV.
//! Esse ataque vai além: verifica se os CIPHERTEXTS resultantes, embora
//! venham do mesmo texto, se comportam como se fossem de textos diferentes
//! (distância de Hamming média ~50%, sem nenhum padrão fixo entre eles).
//!
//! Se o IV está fazendo seu trabalho, cifrar "SEGREDO" 500 vezes deveria
//! parecer, aos olhos de quem só vê o ciphertext, tão aleatório quanto
//! cifrar 500 textos diferentes.

use std::collections::HashSet;

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::criptografia_alvo::CriptografiaAlvo;
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::{contar_bits1, hex_encode, random_int};

pub struct AtaqueCorrelacaoMesmoPlaintext {
    pub amostras: usize,
    pub texto_fixo: String,
}

impl AtaqueCorrelacaoMesmoPlaintext {
    pub fn new() -> Self {
        AtaqueCorrelacaoMesmoPlaintext {
            amostras: 300,
            texto_fixo: "MENSAGEM_SEMPRE_IGUAL_PARA_TESTAR".to_string(),
        }
    }
}

impl Default for AtaqueCorrelacaoMesmoPlaintext {
    fn default() -> Self {
        Self::new()
    }
}

impl AtaqueCorrelacaoMesmoPlaintext {
    fn distancia_hamming_relativa(a: &[u8], b: &[u8]) -> f64 {
        let len = a.len().min(b.len());
        if len == 0 {
            return 0.5;
        }
        let mut diff = 0u32;
        for i in 0..len {
            diff += contar_bits1(a[i] ^ b[i]);
        }
        diff as f64 / (len * 8) as f64
    }
}

impl Ataque for AtaqueCorrelacaoMesmoPlaintext {
    fn nome(&self) -> String {
        "Correlação entre ciphertexts do mesmo plaintext".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        if alvo.as_any().downcast_ref::<CriptografiaAlvo>().is_none() {
            return Err(ErroAtaque::Skip(
                "Precisa de base64url_decode do alvo.".to_string(),
            ));
        }

        let mut ciphertexts: Vec<Vec<u8>> = Vec::with_capacity(self.amostras);
        for _ in 0..self.amostras {
            let token = alvo
                .encrypt(self.texto_fixo.as_bytes())
                .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
            let decodificado = alvo
                .base64url_decode(&token[alvo.prefixo().len()..])
                .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
            ciphertexts.push(alvo.decompor(&decodificado).ciphertext);
        }

        // Compara pares aleatórios de ciphertexts (não todos contra todos,
        // pra manter o custo baixo) e mede a distância de Hamming média.
        let comparacoes = ((self.amostras * (self.amostras - 1)) / 2).min(500);
        let mut distancias: Vec<f64> = Vec::new();
        for _ in 0..comparacoes {
            let i = random_int(0, self.amostras as i64 - 1) as usize;
            let j = random_int(0, self.amostras as i64 - 1) as usize;
            if i == j {
                continue;
            }
            distancias.push(Self::distancia_hamming_relativa(
                &ciphertexts[i],
                &ciphertexts[j],
            ));
        }

        let media = distancias.iter().sum::<f64>() / distancias.len() as f64;

        // Também confere que nenhum PAR de ciphertexts é idêntico (o que
        // indicaria reuso de IV+key, capturado de outro ângulo).
        let unicos: HashSet<String> = ciphertexts.iter().map(|b| hex_encode(b)).collect();
        let duplicatas = ciphertexts.len() - unicos.len();

        let vulneravel = media < 0.4 || media > 0.6 || duplicatas > 0;

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Alta
            } else {
                Severidade::Info
            },
            &format!(
                "distância de Hamming média entre ciphertexts do mesmo texto: {:.1}% (esperado ~50%), {} duplicata(s) exata(s) em {} amostras",
                media * 100.0, duplicatas, self.amostras
            ),
        ))
    }
}
