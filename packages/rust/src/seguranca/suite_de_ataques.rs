//! Runner da suíte de ataques.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};

pub struct SuiteDeAtaques {
    ataques: Vec<Box<dyn Ataque>>,
}

impl SuiteDeAtaques {
    pub fn new() -> Self {
        SuiteDeAtaques {
            ataques: Vec::new(),
        }
    }

    pub fn adicionar(&mut self, ataque: Box<dyn Ataque>) -> &mut Self {
        self.ataques.push(ataque);
        self
    }

    pub fn rodar(&self, alvo: &dyn AlvoCriptografico) -> Vec<ResultadoAtaque> {
        let mut resultados = Vec::new();
        for ataque in &self.ataques {
            let nome = ataque.nome();
            match ataque.executar(alvo) {
                Ok(resultado) => resultados.push(resultado),
                Err(ErroAtaque::Skip(mensagem)) => resultados.push(ResultadoAtaque::new(
                    &nome,
                    false,
                    Severidade::Pulado,
                    &format!("Pulado: {}", mensagem),
                )),
                Err(ErroAtaque::Falha(mensagem)) => resultados.push(ResultadoAtaque::new(
                    &nome,
                    true,
                    Severidade::Erro,
                    &format!("Erro ao executar: {}", mensagem),
                )),
            }
        }
        resultados
    }

    /// Roda e imprime um relatório direto no console.
    pub fn rodar_e_imprimir(&self, alvo: &dyn AlvoCriptografico) -> bool {
        let resultados = self.rodar(alvo);
        let mut vulnerabilidades = 0usize;

        let barra = "=".repeat(70);
        println!("{}", barra);
        println!("RELATÓRIO DA SUÍTE DE ATAQUES");
        println!("{}", barra);
        println!();

        for r in &resultados {
            println!("{}", r.linha_resumo());
            if r.vulneravel
                && r.severidade != Severidade::Pulado
                && r.severidade != Severidade::Demonstracao
            {
                vulnerabilidades += 1;
            }
        }

        println!();
        println!("{}", barra);
        if vulnerabilidades == 0 {
            println!(
                "RESUMO: nenhuma vulnerabilidade encontrada em {} ataque(s).",
                resultados.len()
            );
        } else {
            println!(
                "RESUMO: {} vulnerabilidade(s) encontrada(s) de {} ataque(s) rodados!",
                vulnerabilidades,
                resultados.len()
            );
        }
        println!("{}", barra);

        vulnerabilidades == 0
    }
}

impl Default for SuiteDeAtaques {
    fn default() -> Self {
        Self::new()
    }
}
