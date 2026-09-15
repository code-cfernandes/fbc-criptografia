import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';
import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { SkipAtaqueException } from '../SkipAtaqueException.ts';
import { randomInt } from '../Util.ts';

/**
 * Complemento do AtaqueCoberturaDependencia (que varia a CHAVE): aqui varia
 * o IV. Toda posição do IV precisa influenciar toda posição de saída; uma
 * posição "morta" do IV reduziria a entropia efetiva que o IV injeta.
 */
export class AtaqueCoberturaDependenciaIV implements AtaqueInterface {
  private readonly tamanhoBloco: number;
  private readonly perturbacoesPorPosicao: number;

  constructor({ tamanhoBloco = 32, perturbacoesPorPosicao = 5 }: { tamanhoBloco?: number; perturbacoesPorPosicao?: number } = {}) {
    this.tamanhoBloco = tamanhoBloco;
    this.perturbacoesPorPosicao = perturbacoesPorPosicao;
  }

  nome(): string {
    return 'Cobertura de dependência do IV (entrada x saída)';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    const chave = alvo.chaveDeTeste();
    const tamanhoIv = alvo.tamanhoIv();
    const ivBase = Buffer.alloc(tamanhoIv);

    const ksBase: Buffer | null = alvo.gerarKeystreamBruto(chave, ivBase, 'enc', this.tamanhoBloco);
    if (ksBase == null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }

    const paresIndependentes: string[] = [];

    for (let posIv = 0; posIv < tamanhoIv; posIv++) {
      const afetou = new Array<boolean>(this.tamanhoBloco).fill(false);

      for (let p = 0; p < this.perturbacoesPorPosicao; p++) {
        const iv = Buffer.from(ivBase);
        iv[posIv] = randomInt(1, 255);
        const ks = alvo.gerarKeystreamBruto(chave, iv, 'enc', this.tamanhoBloco);

        for (let posSaida = 0; posSaida < this.tamanhoBloco; posSaida++) {
          if (ks[posSaida] !== ksBase[posSaida]) {
            afetou[posSaida] = true;
          }
        }
      }

      afetou.forEach((ok, posSaida) => {
        if (!ok) {
          paresIndependentes.push(`iv[${posIv}] -> saida[${posSaida}]`);
        }
      });
    }

    if (paresIndependentes.length > 0) {
      return new ResultadoAtaque(
        this.nome(),
        true,
        'alta',
        `${paresIndependentes.length} par(es) sem dependência detectável em ${this.perturbacoesPorPosicao} tentativas cada`,
        { pares: paresIndependentes.slice(0, 20) },
      );
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `Todas as ${tamanhoIv} posições do IV influenciam todas as ${this.tamanhoBloco} posições de saída`,
    );
  }
}
