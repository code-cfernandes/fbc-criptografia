//! Berlekamp-Massey: calcula a complexidade linear (tamanho do menor LFSR que
//! reproduz a sequência de bits). Para uma sequência aleatória de N bits, a
//! complexidade fica perto de N/2. Se a cifra esconder estrutura linear (tipo
//! um LFSR disfarçado), a complexidade cai MUITO abaixo disso - e aí a cifra
//! seria atacável resolvendo um sistema linear em vez de força bruta.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaqueComplexidadeLinear {
    pub bits_por_amostra: usize,
    pub amostras: usize,
    pub limite_relativo: f64,
}

impl AtaqueComplexidadeLinear {
    pub fn new() -> Self {
        AtaqueComplexidadeLinear {
            bits_por_amostra: 1024,
            amostras: 5,
            limite_relativo: 0.4,
        }
    }
}

impl Default for AtaqueComplexidadeLinear {
    fn default() -> Self {
        Self::new()
    }
}

impl AtaqueComplexidadeLinear {
    fn para_bits(bytes: &[u8], limite: usize) -> Vec<u8> {
        let mut bits: Vec<u8> = Vec::new();
        let mut i = 0;
        while i < bytes.len() && bits.len() < limite {
            let byte = bytes[i];
            for b in (0..8).rev() {
                bits.push((byte >> b) & 1);
            }
            i += 1;
        }
        bits.truncate(limite);
        bits
    }

    /// Algoritmo de Berlekamp-Massey sobre GF(2).
    fn berlekamp_massey(s: &[u8]) -> usize {
        let n = s.len();
        let mut c = vec![0u8; n];
        c[0] = 1;
        let mut b = vec![0u8; n];
        b[0] = 1;
        let mut l = 0usize;
        let mut m: i64 = -1;

        for i in 0..n {
            let mut d = s[i];
            for j in 1..=l {
                d ^= c[j] & s[i - j];
            }

            if d == 1 {
                let t = c.clone();
                let shift = (i as i64 - m) as usize;
                for j in 0..n.saturating_sub(shift) {
                    c[j + shift] ^= b[j];
                }
                if l <= i / 2 {
                    l = i + 1 - l;
                    m = i as i64;
                    b = t;
                }
            }
        }

        l
    }
}

impl Ataque for AtaqueComplexidadeLinear {
    fn nome(&self) -> String {
        "Complexidade linear (Berlekamp-Massey)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave = alvo.chave_de_teste();

        let mut relativos: Vec<f64> = Vec::with_capacity(self.amostras);
        let mut pior = 1.0f64;
        for _ in 0..self.amostras {
            let bytes = alvo.gerar_keystream_bruto(
                chave.as_bytes(),
                &random_bytes(alvo.tamanho_iv()),
                "enc",
                self.bits_por_amostra / 8,
            );
            let bits = Self::para_bits(&bytes, self.bits_por_amostra);
            let relativo = Self::berlekamp_massey(&bits) as f64 / self.bits_por_amostra as f64;
            relativos.push(relativo);
            pior = pior.min(relativo);
        }

        let media = relativos.iter().sum::<f64>() / relativos.len() as f64;
        let vulneravel = pior < self.limite_relativo;

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Critica
            } else {
                Severidade::Info
            },
            &format!(
                "complexidade linear relativa: média={:.1}%, pior={:.1}% de {} bits (esperado ~50%; limite>={:.0}%)",
                media * 100.0,
                pior * 100.0,
                self.bits_por_amostra,
                self.limite_relativo * 100.0
            ),
        ))
    }
}
