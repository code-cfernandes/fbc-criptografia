//! Testa se o keystream depende de key e iv APENAS pela combinação key XOR iv.
//! Nessa cifra o estado inicial é `a[pos] = key[pos] ^ iv[pos]`, então, se o
//! resto do gerador não reintroduzir key/iv separadamente, vale exatamente:
//!
//!     keystream(key, iv) == keystream(key ^ d, iv ^ d)
//!
//! para qualquer máscara d (com o devido alinhamento key/iv). Isso é uma
//! propriedade estrutural relevante: significa que key e iv não entram de
//! forma independente na cifra, o que enfraquece o modelo de segurança (o IV
//! deveria contribuir com entropia própria, não só deslocar a chave por XOR).

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaqueSeparacaoChaveIV {
    pub tentativas: usize,
    pub tamanho_bloco: usize,
}

impl AtaqueSeparacaoChaveIV {
    pub fn new() -> Self {
        AtaqueSeparacaoChaveIV {
            tentativas: 50,
            tamanho_bloco: 32,
        }
    }
}

impl Default for AtaqueSeparacaoChaveIV {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueSeparacaoChaveIV {
    fn nome(&self) -> String {
        "Separação chave/IV (invariância a key XOR iv)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let tam_chave = alvo.chave_de_teste().len();
        let tam_iv = alvo.tamanho_iv();

        let _primeiro = alvo.gerar_keystream_bruto(
            alvo.chave_de_teste().as_bytes(),
            &random_bytes(tam_iv),
            "enc",
            self.tamanho_bloco,
        );

        let mut confirmacoes = 0usize;
        for _ in 0..self.tentativas {
            let chave = random_bytes(tam_chave);
            let iv = random_bytes(tam_iv);
            let d = random_bytes(tam_iv);

            let chave2: Vec<u8> = (0..tam_chave).map(|p| chave[p] ^ d[p % tam_iv]).collect();
            let iv2: Vec<u8> = (0..tam_iv).map(|p| iv[p] ^ d[p]).collect();

            let ks1 = alvo.gerar_keystream_bruto(&chave, &iv, "enc", self.tamanho_bloco);
            let ks2 = alvo.gerar_keystream_bruto(&chave2, &iv2, "enc", self.tamanho_bloco);

            if ks1 == ks2 {
                confirmacoes += 1;
            }
        }

        let invariante = confirmacoes == self.tentativas;

        Ok(ResultadoAtaque::new(
            &self.nome(),
            invariante,
            if invariante {
                Severidade::Media
            } else {
                Severidade::Info
            },
            &if invariante {
                format!(
                    "Confirmado em {0}/{0}: keystream(key,iv) == keystream(key^d, iv^d). \
                     O IV só desloca a chave por XOR antes da difusão - não injeta entropia independente no key schedule.",
                    self.tentativas
                )
            } else {
                format!(
                    "Invariância não se confirmou ({}/{}); key e iv entram de forma independente.",
                    confirmacoes, self.tentativas
                )
            },
        ))
    }
}
