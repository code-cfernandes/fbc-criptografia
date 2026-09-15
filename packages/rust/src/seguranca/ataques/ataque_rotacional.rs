//! Ataque rotacional/slide: se a cifra for simétrica a deslocamentos circulares
//! de key/iv, então `keystream(rot(key), rot(iv))` seria uma rotação de
//! `keystream(key, iv)` - uma estrutura explorável. Testa todas as rotações de
//! byte e também coincidência direta do keystream.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaqueRotacional {
    pub tamanho: usize,
}

impl AtaqueRotacional {
    pub fn new() -> Self {
        AtaqueRotacional { tamanho: 64 }
    }
}

impl Default for AtaqueRotacional {
    fn default() -> Self {
        Self::new()
    }
}

impl AtaqueRotacional {
    fn rotacionar(buf: &[u8], k: usize) -> Vec<u8> {
        let n = buf.len();
        (0..n).map(|i| buf[(i + k) % n]).collect()
    }
}

impl Ataque for AtaqueRotacional {
    fn nome(&self) -> String {
        "Rotacional/slide (simetria por rotação)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave = alvo.chave_de_teste();
        let chave = chave.as_bytes();
        let iv = random_bytes(alvo.tamanho_iv());
        let ks1 = alvo.gerar_keystream_bruto(chave, &iv, "enc", self.tamanho);

        let mut coincidencias: Vec<String> = Vec::new();
        for k in 1..chave.len() {
            let ks2 = alvo.gerar_keystream_bruto(
                &Self::rotacionar(chave, k),
                &Self::rotacionar(&iv, k),
                "enc",
                self.tamanho,
            );

            if ks2 == ks1 {
                coincidencias.push(format!("rotação {}: keystream idêntico", k));
                continue;
            }
            // metade inicial de ks1 rotacionada deve bater com ks2 se houver simetria
            let alvo_rot = Self::rotacionar(&ks1[..32], k);
            if ks2[..32] == alvo_rot[..] {
                coincidencias.push(format!("rotação {}: keystream rotacionado", k));
            }
        }

        let vulneravel = !coincidencias.is_empty();

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Critica
            } else {
                Severidade::Info
            },
            &if vulneravel {
                let amostra: Vec<String> = coincidencias.iter().take(5).cloned().collect();
                format!("Simetria rotacional encontrada: {}", amostra.join("; "))
            } else {
                format!(
                    "Nenhuma das {} rotações de byte reproduziu o keystream",
                    chave.len() - 1
                )
            },
        ))
    }
}
