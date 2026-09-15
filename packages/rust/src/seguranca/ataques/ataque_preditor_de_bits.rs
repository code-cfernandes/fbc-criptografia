//! Previsibilidade: treina um preditor por contexto (os k bits anteriores) na
//! primeira metade do keystream e mede a taxa de acerto na segunda metade.
//! Para um gerador sem memória/correlação local, a taxa fica em ~50% (chute).
//! Qualquer coisa acima disso indica que os bits carregam dependência
//! explorável - o embrião de um ataque de predição de estado.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaquePreditorDeBits {
    pub tamanho: usize,
    pub contexto: usize,
    pub limite_taxa: f64,
}

impl AtaquePreditorDeBits {
    pub fn new() -> Self {
        AtaquePreditorDeBits {
            tamanho: 16384,
            contexto: 8,
            limite_taxa: 0.55,
        }
    }
}

impl Default for AtaquePreditorDeBits {
    fn default() -> Self {
        Self::new()
    }
}

impl AtaquePreditorDeBits {
    fn contexto_de(bits: &[u8], i: usize, k: usize) -> usize {
        let mut ctx = 0usize;
        for &bit in bits.iter().take(i).skip(i - k) {
            ctx = (ctx << 1) | bit as usize;
        }
        ctx
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

impl Ataque for AtaquePreditorDeBits {
    fn nome(&self) -> String {
        "Previsibilidade de bits (preditor por contexto)".to_string()
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
        let k = self.contexto;
        let total = 1usize << k;
        let metade = n / 2;

        let mut uns = vec![0u64; total];
        let mut cont = vec![0u64; total];
        for i in k..metade {
            let ctx = Self::contexto_de(&bits, i, k);
            uns[ctx] += bits[i] as u64;
            cont[ctx] += 1;
        }

        let mut acertos = 0u64;
        let mut testes = 0u64;
        for i in metade..n {
            let ctx = Self::contexto_de(&bits, i, k);
            if cont[ctx] == 0 {
                continue;
            }
            let predicao = if uns[ctx] * 2 > cont[ctx] { 1 } else { 0 };
            if predicao == bits[i] {
                acertos += 1;
            }
            testes += 1;
        }

        let taxa = if testes > 0 {
            acertos as f64 / testes as f64
        } else {
            0.5
        };
        let vulneravel = taxa > self.limite_taxa;

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Alta
            } else {
                Severidade::Info
            },
            &format!(
                "taxa de acerto={:.2}% com contexto de {} bits (esperado ~50%, limite={:.0}%) sobre {} testes",
                taxa * 100.0,
                k,
                self.limite_taxa * 100.0,
                testes
            ),
        ))
    }
}
