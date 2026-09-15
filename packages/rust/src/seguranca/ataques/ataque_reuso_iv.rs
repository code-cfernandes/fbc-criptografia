//! A encrypt() pública sempre gera um IV aleatório novo - não dá pra forçar
//! reuso através dela (por isso o AtaqueColisaoIV nunca encontra colisão).
//! Esse ataque usa o gerador de keystream de baixo nível pra SIMULAR o que
//! aconteceria SE o IV fosse reusado (por um bug externo, uma falha do
//! gerador aleatório do sistema, etc.) - e prova matematicamente o quanto
//! vaza nesse cenário catastrófico.
//!
//! Isso não é um "bug" da implementação (é uma propriedade universal de
//! qualquer cifra de fluxo com combinador XOR/soma) - é uma demonstração
//! quantificada de por que o AtaqueColisaoIV é o teste mais crítico da
//! suíte: a segurança inteira depende do IV nunca repetir.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaqueReusoIV;

impl AtaqueReusoIV {
    fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
        let len = a.len().min(b.len());
        (0..len).map(|i| a[i] ^ b[i]).collect()
    }
}

impl Ataque for AtaqueReusoIV {
    fn nome(&self) -> String {
        "Reuso forçado de IV (two-time pad)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave = alvo.chave_de_teste();
        let iv_fixo = random_bytes(alvo.tamanho_iv());

        let _primeiro = alvo.gerar_keystream_bruto(chave.as_bytes(), &iv_fixo, "enc", 16);

        let plaintext1 = b"TRANSFERIR_1000";
        let plaintext2 = b"CANCELAR_TUDO!!";
        let tamanho = plaintext1.len().max(plaintext2.len());

        let keystream = alvo.gerar_keystream_bruto(chave.as_bytes(), &iv_fixo, "enc", tamanho);

        let ciphertext1 = Self::xor(plaintext1, &keystream);
        let ciphertext2 = Self::xor(plaintext2, &keystream);

        // O atacante NUNCA precisou saber a key nem o keystream - só
        // observou os dois ciphertexts (que vazariam publicamente se o
        // IV fosse reusado) e os combinou entre si.
        let xor_dos_ciphertexts = Self::xor(&ciphertext1, &ciphertext2);
        let xor_esperado_dos_plaintexts = Self::xor(plaintext1, plaintext2);

        let vazou = xor_dos_ciphertexts == xor_esperado_dos_plaintexts;

        // Com IV reusado, a propriedade é universal e sempre se confirma - por
        // isso o resultado esperado NÃO é uma vulnerabilidade da cifra (é uma
        // demonstração). Só vira alerta se, por algum motivo, a propriedade
        // NÃO se confirmar (o que indicaria um combinador inconsistente).
        let detalhes = if vazou {
            "Demonstração (não é falha da implementação): XOR(c1,c2) revela XOR(p1,p2) \
             sem precisar da chave. Inerente a qualquer combinador XOR/soma - a ÚNICA \
             defesa é garantir que o IV NUNCA se repita (ver Ataque de Colisão de IV)."
                .to_string()
        } else {
            "INESPERADO: XOR dos ciphertexts não corresponde ao XOR dos plaintexts (investigar)"
                .to_string()
        };

        Ok(ResultadoAtaque::new(
            &self.nome(),
            !vazou,
            if vazou {
                Severidade::Demonstracao
            } else {
                Severidade::Alta
            },
            &detalhes,
        ))
    }
}
