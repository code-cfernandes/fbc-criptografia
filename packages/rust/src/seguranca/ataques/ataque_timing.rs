//! Se a comparação de integridade não for de tempo constante (ex: usar ===
//! em vez de hash_equals()), um atacante consegue medir QUANTOS bytes
//! iniciais do campo de integridade batem, comparando o tempo de resposta -
//! e reconstruir a integridade correta byte a byte, sem nunca saber a chave.
//!
//! Esse teste gera um token válido, cria versões adulteradas onde o campo
//! de integridade erra em posições DIFERENTES (início vs. fim do campo), e
//! compara o tempo médio de decrypt() entre os grupos. Uma diferença
//! estatisticamente clara entre "erra logo no primeiro byte" e "erra só no
//! último byte" indica uma comparação vulnerável a timing.
//!
//! IMPORTANTE: testes de timing têm MUITO ruído (garbage collector, JIT,
//! agendamento do SO). Isso é uma checagem heurística grosseira, não uma
//! prova formal.

use std::time::Instant;

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::criptografia_alvo::CriptografiaAlvo;
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};

pub struct AtaqueTiming {
    pub repeticoes_por_grupo: usize,
}

impl AtaqueTiming {
    pub fn new() -> Self {
        AtaqueTiming {
            repeticoes_por_grupo: 400,
        }
    }
}

impl Default for AtaqueTiming {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueTiming {
    fn nome(&self) -> String {
        "Timing da verificação de integridade".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        if alvo.as_any().downcast_ref::<CriptografiaAlvo>().is_none() {
            return Err(ErroAtaque::Skip(
                "Precisa de base64url_encode/decode do alvo.".to_string(),
            ));
        }

        let token = alvo
            .encrypt(b"MENSAGEM_PARA_TESTE_DE_TIMING")
            .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
        let decodificado = alvo
            .base64url_decode(&token[alvo.prefixo().len()..])
            .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
        let campos = alvo.decompor(&decodificado);
        let tamanho_integridade = campos.integridade.len();

        let medir_grupo = |posicao_erro: usize| -> u128 {
            let mut tempos: Vec<u128> = Vec::with_capacity(self.repeticoes_por_grupo);
            for _ in 0..self.repeticoes_por_grupo {
                let mut campos_adulterados = campos.clone();
                campos_adulterados.integridade[posicao_erro] ^= 0x01;

                let token_adulterado = format!(
                    "{}{}",
                    alvo.prefixo(),
                    alvo.base64url_encode(&alvo.recompor(&campos_adulterados))
                );

                let inicio = Instant::now();
                let _ = alvo.decrypt(&token_adulterado);
                tempos.push(inicio.elapsed().as_nanos());
            }
            tempos.sort_unstable();
            tempos[tempos.len() / 2]
        };

        // Grupo A: erro logo no primeiro byte do campo de integridade.
        // Grupo B: erro no último byte.
        // Repete várias rodadas intercaladas pra diluir variação de carga
        // da máquina ao longo do tempo (evita viés de "a máquina esquentou").
        let mut medianas_a: Vec<u128> = Vec::new();
        let mut medianas_b: Vec<u128> = Vec::new();
        for _ in 0..8 {
            medianas_a.push(medir_grupo(0));
            medianas_b.push(medir_grupo(tamanho_integridade - 1));
        }

        let mediana_a = medianas_a.iter().sum::<u128>() as f64 / medianas_a.len() as f64;
        let mediana_b = medianas_b.iter().sum::<u128>() as f64 / medianas_b.len() as f64;
        let diferenca_relativa =
            (mediana_a - mediana_b).abs() / mediana_a.max(mediana_b).max(1.0);

        // Limite arbitrário e conservador: só marca como suspeito se a
        // diferença for grande o bastante pra não ser só ruído de máquina.
        let vulneravel = diferenca_relativa > 0.15;

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Media
            } else {
                Severidade::Info
            },
            &format!(
                "mediana erro-no-início={:.0}ns, mediana erro-no-fim={:.0}ns, diferença relativa={:.1}% (limite=15%). {}",
                mediana_a,
                mediana_b,
                diferenca_relativa * 100.0,
                if vulneravel {
                    "Diferença suspeita - investigar se a comparação usa hash_equals()."
                } else {
                    "Sem diferença clara nesse experimento (lembrando: teste heurístico, não prova formal)."
                }
            ),
        ))
    }
}
