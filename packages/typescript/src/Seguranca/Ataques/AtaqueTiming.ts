import type { AlvoCriptografico, CamposToken } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';
import { CriptografiaAlvo } from '../CriptografiaAlvo.ts';
import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { SkipAtaqueException } from '../SkipAtaqueException.ts';

interface OpcoesTiming {
  repeticoesPorGrupo?: number;
}

/**
 * Se a comparação de integridade não for de tempo constante (ex: usar ===
 * em vez de hash_equals()), um atacante consegue medir QUANTOS bytes
 * iniciais do campo de integridade batem, comparando o tempo de resposta -
 * e reconstruir a integridade correta byte a byte, sem nunca saber a chave.
 *
 * Esse teste gera um token válido, cria versões adulteradas onde o campo
 * de integridade erra em posições DIFERENTES (início vs. fim do campo), e
 * compara o tempo médio de decrypt() entre os grupos. Uma diferença
 * estatisticamente clara entre "erra logo no primeiro byte" e "erra só no
 * último byte" indica uma comparação vulnerável a timing.
 *
 * IMPORTANTE: testes de timing têm MUITO ruído (garbage collector, JIT,
 * agendamento do SO). Isso é uma checagem heurística grosseira, não uma
 * prova formal - trate qualquer resultado "vulnerável" como um convite pra
 * investigar o código-fonte diretamente, e um resultado "resistiu" como
 * "não detectei nesse experimento", não como garantia.
 */
export class AtaqueTiming implements AtaqueInterface {
  private readonly repeticoesPorGrupo: number;

  constructor({ repeticoesPorGrupo = 400 }: OpcoesTiming = {}) {
    this.repeticoesPorGrupo = repeticoesPorGrupo;
  }

  nome(): string {
    return 'Timing da verificação de integridade';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    if (!(alvo instanceof CriptografiaAlvo)) {
      throw new SkipAtaqueException('Precisa de base64url_encode/decode do alvo.');
    }

    const token = alvo.encrypt('MENSAGEM_PARA_TESTE_DE_TIMING');
    const decodificado = alvo.base64urlDecode(token.slice(alvo.prefixo().length));
    const campos = alvo.decompor(decodificado);
    const tamanhoIntegridade = campos.integridade.length;

    const medirGrupo = (posicaoErro: number): number => {
      const tempos: number[] = [];
      for (let r = 0; r < this.repeticoesPorGrupo; r++) {
        const camposAdulterados: CamposToken = { ...campos };
        const integ = Buffer.from(campos.integridade);
        integ[posicaoErro] = integ[posicaoErro] ^ 0x01;
        camposAdulterados.integridade = integ;

        const tokenAdulterado =
          alvo.prefixo() + alvo.base64urlEncode(alvo.recompor(camposAdulterados));

        const inicio = process.hrtime.bigint();
        try {
          alvo.decrypt(tokenAdulterado);
        } catch (e) {
          // esperado
        }
        tempos.push(Number(process.hrtime.bigint() - inicio));
      }
      tempos.sort((a, b) => a - b);
      // usa a mediana em vez da média - muito mais robusta a outliers
      // de agendamento do SO, comum em testes de timing em ambiente
      // compartilhado.
      return tempos[Math.floor(tempos.length / 2)];
    };

    // Grupo A: erro logo no primeiro byte do campo de integridade.
    // Grupo B: erro no último byte.
    // Repete várias rodadas intercaladas pra diluir variação de carga
    // da máquina ao longo do tempo (evita viés de "a máquina esquentou").
    const medianasA: number[] = [];
    const medianasB: number[] = [];
    for (let rodada = 0; rodada < 8; rodada++) {
      medianasA.push(medirGrupo(0));
      medianasB.push(medirGrupo(tamanhoIntegridade - 1));
    }

    const medianaA = medianasA.reduce((s, x) => s + x, 0) / medianasA.length;
    const medianaB = medianasB.reduce((s, x) => s + x, 0) / medianasB.length;
    const diferencaRelativa = Math.abs(medianaA - medianaB) / Math.max(medianaA, medianaB);

    // Limite arbitrário e conservador: só marca como suspeito se a
    // diferença for grande o bastante pra não ser só ruído de máquina
    // (na prática, comparações vulneráveis costumam mostrar diferenças
    // bem mais óbvias que isso quando o campo é curto).
    const vulneravel = diferencaRelativa > 0.15;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'media' : 'info',
      `mediana erro-no-início=${medianaA.toFixed(0)}ns, mediana erro-no-fim=${medianaB.toFixed(0)}ns, diferença relativa=${(diferencaRelativa * 100).toFixed(1)}% (limite=15%). ` +
        (vulneravel
          ? 'Diferença suspeita - investigar se a comparação usa hash_equals().'
          : 'Sem diferença clara nesse experimento (lembrando: teste heurístico, não prova formal).'),
      { mediana_inicio_ns: medianaA, mediana_fim_ns: medianaB },
    );
  }
}
