//! Verifica, byte a byte, se toda posição de SAÍDA depende de toda posição
//! de ENTRADA (mudando 1 byte da chave, com várias perturbações diferentes
//! pra evitar falso-positivo por coincidência de valor). Uma dependência
//! ausente indica que a mistura não se propagou completamente - um atacante
//! poderia isolar e atacar aquele par de posições separadamente do resto.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::{random_bytes, random_int};

pub struct AtaqueCoberturaDependencia {
    pub tamanho_bloco: usize,
    pub perturbacoes_por_par: usize,
}

impl AtaqueCoberturaDependencia {
    pub fn new() -> Self {
        AtaqueCoberturaDependencia {
            tamanho_bloco: 32,
            perturbacoes_por_par: 5,
        }
    }
}

impl Default for AtaqueCoberturaDependencia {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueCoberturaDependencia {
    fn nome(&self) -> String {
        "Cobertura de dependência (matriz entrada x saída)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let tamanho = self.tamanho_bloco;
        let chave_base = vec![0u8; tamanho];
        let iv = random_bytes(alvo.tamanho_iv());

        let ks_base = alvo.gerar_keystream_bruto(&chave_base, &iv, "enc", tamanho);

        if chave_base.len() != tamanho {
            // A chave precisa ter o mesmo tamanho do bloco pra esse teste
            // isolar 1 posição de cada vez sem wraparound. Se a cifra usa
            // chave de outro tamanho, pula esse ataque.
            return Err(ErroAtaque::Skip(
                "Teste requer chave do mesmo tamanho do bloco.".to_string(),
            ));
        }

        let mut pares_independentes: Vec<String> = Vec::new();

        for pos_entrada in 0..tamanho {
            let mut afetou_alguma_saida = vec![false; tamanho];

            for _ in 0..self.perturbacoes_por_par {
                let mut chave_teste = chave_base.clone();
                chave_teste[pos_entrada] = random_int(1, 255) as u8;
                let ks = alvo.gerar_keystream_bruto(&chave_teste, &iv, "enc", tamanho);

                for pos_saida in 0..tamanho {
                    if ks[pos_saida] != ks_base[pos_saida] {
                        afetou_alguma_saida[pos_saida] = true;
                    }
                }
            }

            for (pos_saida, &afetou) in afetou_alguma_saida.iter().enumerate() {
                if !afetou {
                    pares_independentes.push(format!(
                        "entrada[{}] -> saída[{}]",
                        pos_entrada, pos_saida
                    ));
                }
            }
        }

        if !pares_independentes.is_empty() {
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Media,
                &format!(
                    "{} par(es) sem dependência detectável em {} tentativas cada",
                    pares_independentes.len(),
                    self.perturbacoes_por_par
                ),
            ));
        }

        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &format!(
                "Todos os {} pares (entrada, saída) mostraram dependência",
                tamanho * tamanho
            ),
        ))
    }
}
