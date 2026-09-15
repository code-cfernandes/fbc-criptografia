import type { AlvoCriptografico } from './AlvoCriptografico.ts';
import type { AtaqueInterface } from './AtaqueInterface.ts';
import { ResultadoAtaque } from './ResultadoAtaque.ts';
import { SkipAtaqueException } from './SkipAtaqueException.ts';

export class SuiteDeAtaques {
  private readonly ataques: AtaqueInterface[] = [];

  adicionar(ataque: AtaqueInterface): this {
    this.ataques.push(ataque);
    return this;
  }

  rodar(alvo: AlvoCriptografico): ResultadoAtaque[] {
    const resultados: ResultadoAtaque[] = [];
    for (const ataque of this.ataques) {
      try {
        resultados.push(ataque.executar(alvo));
      } catch (e) {
        if (e instanceof SkipAtaqueException) {
          resultados.push(
            new ResultadoAtaque(ataque.nome(), false, 'pulado', 'Pulado: ' + e.message),
          );
        } else {
          const mensagem = e instanceof Error ? e.message : String(e);
          resultados.push(
            new ResultadoAtaque(ataque.nome(), true, 'erro', 'Erro ao executar: ' + mensagem),
          );
        }
      }
    }
    return resultados;
  }

  /** Roda e imprime um relatório direto no console. */
  rodarEImprimir(alvo: AlvoCriptografico): boolean {
    const resultados = this.rodar(alvo);
    let vulnerabilidades = 0;

    console.log('='.repeat(70));
    console.log('RELATÓRIO DA SUÍTE DE ATAQUES');
    console.log('='.repeat(70));
    console.log();

    for (const r of resultados) {
      console.log(r.linhaResumo());
      if (r.vulneravel && r.severidade !== 'pulado' && r.severidade !== 'demonstracao') {
        vulnerabilidades++;
      }
    }

    console.log();
    console.log('='.repeat(70));
    if (vulnerabilidades === 0) {
      console.log(`RESUMO: nenhuma vulnerabilidade encontrada em ${resultados.length} ataque(s).`);
    } else {
      console.log(
        `RESUMO: ${vulnerabilidades} vulnerabilidade(s) encontrada(s) de ${resultados.length} ataque(s) rodados!`,
      );
    }
    console.log('='.repeat(70));

    return vulnerabilidades === 0;
  }
}
