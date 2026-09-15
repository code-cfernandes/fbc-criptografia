//! Com KEY e IV fixos, o keystream precisa ser 100% determinístico.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::hex_encode;

pub struct AtaqueVetorDeterministico;

impl Ataque for AtaqueVetorDeterministico {
    fn nome(&self) -> String {
        "Determinismo (vetor de referência key/iv fixos)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave_fixa = "K".repeat(alvo.chave_de_teste().as_bytes().len());
        let iv_fixo = vec![0u8; alvo.tamanho_iv()];

        let ks1 = alvo.gerar_keystream_bruto(chave_fixa.as_bytes(), &iv_fixo, "enc", 32);
        let ks2 = alvo.gerar_keystream_bruto(chave_fixa.as_bytes(), &iv_fixo, "enc", 32);
        let ks3 = alvo.gerar_keystream_bruto(chave_fixa.as_bytes(), &iv_fixo, "enc", 32);

        let deterministico = ks1 == ks2 && ks2 == ks3;
        let hex1 = hex_encode(&ks1);

        let detalhes = if deterministico {
            format!(
                "Determinístico em 3 chamadas. Vetor de referência (key=64x\"K\", iv=zeros, prop=enc, 32 bytes): {}",
                hex1
            )
        } else {
            format!(
                "NÃO determinístico! 3 chamadas com a mesma entrada deram resultados diferentes: {} / {} / {}",
                hex1,
                hex_encode(&ks2),
                hex_encode(&ks3)
            )
        };

        Ok(ResultadoAtaque::new(
            &self.nome(),
            !deterministico,
            if deterministico {
                Severidade::Info
            } else {
                Severidade::Critica
            },
            &detalhes,
        ))
    }
}
