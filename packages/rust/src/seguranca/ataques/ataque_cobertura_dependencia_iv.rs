//! Complemento do AtaqueCoberturaDependencia (que varia a CHAVE): aqui varia
//! o IV. Toda posição do IV precisa influenciar toda posição de saída; uma
//! posição "morta" do IV reduziria a entropia efetiva que o IV injeta.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_int;

pub struct AtaqueCoberturaDependenciaIV {
    pub tamanho_bloco: usize,
    pub perturbacoes_por_posicao: usize,
}

impl AtaqueCoberturaDependenciaIV {
    pub fn new() -> Self {
        AtaqueCoberturaDependenciaIV {
            tamanho_bloco: 32,
            perturbacoes_por_posicao: 5,
        }
    }
}

impl Default for AtaqueCoberturaDependenciaIV {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueCoberturaDependenciaIV {
    fn nome(&self) -> String {
        "Cobertura de dependência do IV (entrada x saída)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave = alvo.chave_de_teste();
        let tamanho_iv = alvo.tamanho_iv();
        let iv_base = vec![0u8; tamanho_iv];

        let ks_base =
            alvo.gerar_keystream_bruto(chave.as_bytes(), &iv_base, "enc", self.tamanho_bloco);

        let mut pares_independentes: Vec<String> = Vec::new();

        for pos_iv in 0..tamanho_iv {
            let mut afetou = vec![false; self.tamanho_bloco];

            for _ in 0..self.perturbacoes_por_posicao {
                let mut iv = iv_base.clone();
                iv[pos_iv] = random_int(1, 255) as u8;
                let ks = alvo.gerar_keystream_bruto(chave.as_bytes(), &iv, "enc", self.tamanho_bloco);

                for pos_saida in 0..self.tamanho_bloco {
                    if ks[pos_saida] != ks_base[pos_saida] {
                        afetou[pos_saida] = true;
                    }
                }
            }

            for (pos_saida, &ok) in afetou.iter().enumerate() {
                if !ok {
                    pares_independentes
                        .push(format!("iv[{}] -> saida[{}]", pos_iv, pos_saida));
                }
            }
        }

        if !pares_independentes.is_empty() {
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Alta,
                &format!(
                    "{} par(es) sem dependência detectável em {} tentativas cada",
                    pares_independentes.len(),
                    self.perturbacoes_por_posicao
                ),
            ));
        }

        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &format!(
                "Todas as {} posições do IV influenciam todas as {} posições de saída",
                tamanho_iv, self.tamanho_bloco
            ),
        ))
    }
}
