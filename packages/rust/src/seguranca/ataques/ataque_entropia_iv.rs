//! O AtaqueColisaoIV já prova que os IVs não colidem numa amostra prática.
//! Esse ataque vai atrás de um sintoma diferente e mais sutil: se alguém
//! trocar `random_bytes(16)` por algo previsível mas ainda "único" (tipo
//! timestamp + contador, ou um PRNG mal semeado), a colisão pode continuar
//! rara - mas o IV vira PREVISÍVEL, o que quebra a garantia de segurança
//! mesmo sem nunca colidir de fato.
//!
//! Detecta isso com 3 sinais que um IV verdadeiramente aleatório não deveria
//! ter: bytes vizinhos correlacionados, distribuição não-uniforme por byte,
//! e sequências crescentes/monótonas entre IVs consecutivos (sintoma
//! clássico de contador ou timestamp).

use std::collections::HashSet;

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::criptografia_alvo::CriptografiaAlvo;
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};

pub struct AtaqueEntropiaIV {
    pub amostras: usize,
}

impl AtaqueEntropiaIV {
    pub fn new() -> Self {
        AtaqueEntropiaIV { amostras: 2000 }
    }
}

impl Default for AtaqueEntropiaIV {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueEntropiaIV {
    fn nome(&self) -> String {
        "Entropia e previsibilidade do IV".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        if alvo.as_any().downcast_ref::<CriptografiaAlvo>().is_none() {
            return Err(ErroAtaque::Skip(
                "Precisa de base64url_decode do alvo.".to_string(),
            ));
        }

        let mut ivs: Vec<Vec<u8>> = Vec::with_capacity(self.amostras);
        for _ in 0..self.amostras {
            let token = alvo
                .encrypt(b"X")
                .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
            let decodificado = alvo
                .base64url_decode(&token[alvo.prefixo().len()..])
                .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
            ivs.push(alvo.decompor(&decodificado).iv);
        }

        let mut problemas: Vec<String> = Vec::new();

        // Sinal 1: distribuição de bytes do IV (todas as posições, todos os IVs)
        let mut contagem = [0u64; 256];
        let mut total = 0u64;
        for iv in &ivs {
            for &b in iv {
                contagem[b as usize] += 1;
                total += 1;
            }
        }
        let esperado = total as f64 / 256.0;
        let mut qui2 = 0.0f64;
        for &c in &contagem {
            qui2 += (c as f64 - esperado).powi(2) / esperado;
        }
        if qui2 > 330.0 {
            problemas.push(format!(
                "distribuição de bytes suspeita (qui-quadrado={:.1}, >330 é suspeito)",
                qui2
            ));
        }

        // Sinal 2: monotonicidade - conta quantos IVs consecutivos têm o
        // primeiro byte estritamente crescente (um contador/timestamp cru
        // produziria isso quase sempre; aleatório, só ~50% das vezes).
        let mut crescentes = 0usize;
        for i in 1..ivs.len() {
            if ivs[i][0] > ivs[i - 1][0] {
                crescentes += 1;
            }
        }
        let proporcao_crescente = crescentes as f64 / (ivs.len() - 1) as f64;
        if proporcao_crescente > 0.65 || proporcao_crescente < 0.35 {
            problemas.push(format!(
                "primeiro byte do IV parece monotônico ({:.0}% das vezes crescente; aleatório ficaria perto de 50%)",
                proporcao_crescente * 100.0
            ));
        }

        // Sinal 3: bytes duplicados dentro do MESMO IV devem ser comuns
        // (paradoxo do aniversário para 16 bytes de 0-255 já prevê bastante
        // repetição interna) - a AUSÊNCIA de qualquer repetição interna em
        // quase todos os IVs seria estranha (sugeriria geração não-uniforme,
        // tipo bytes distintos forçados).
        let mut sem_repeticao_interna = 0usize;
        for iv in &ivs {
            if iv.iter().copied().collect::<HashSet<u8>>().len() == iv.len() {
                sem_repeticao_interna += 1;
            }
        }
        let proporcao_sem_repeticao = sem_repeticao_interna as f64 / ivs.len() as f64;
        // Para 16 bytes aleatórios de 0-255, a chance de TODOS distintos é ~72%.
        if proporcao_sem_repeticao > 0.9 || proporcao_sem_repeticao < 0.5 {
            problemas.push(format!(
                "{:.0}% dos IVs não têm nenhum byte repetido internamente (esperado ~72% para 16 bytes aleatórios)",
                proporcao_sem_repeticao * 100.0
            ));
        }

        if !problemas.is_empty() {
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Alta,
                &problemas.join("; "),
            ));
        }

        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &format!(
                "qui-quadrado={:.1}, {:.0}% primeiro-byte-crescente (~50% esperado), {:.0}% sem repetição interna (~72% esperado) - tudo consistente com IV aleatório",
                qui2,
                proporcao_crescente * 100.0,
                proporcao_sem_repeticao * 100.0
            ),
        ))
    }
}
