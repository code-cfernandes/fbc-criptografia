import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';
import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { SkipAtaqueException } from '../SkipAtaqueException.ts';
import { randomBytes, randomInt } from '../Util.ts';

/**
 * Verifica, byte a byte, se toda posição de SAÍDA depende de toda posição
 * de ENTRADA (mudando 1 byte da chave, com várias perturbações diferentes
 * pra evitar falso-positivo por coincidência de valor). Uma dependência
 * ausente indica que a mistura não se propagou completamente - um atacante
 * poderia isolar e atacar aquele par de posições separadamente do resto.
 */
export class AtaqueCoberturaDependencia implements AtaqueInterface {
  private readonly tamanhoBloco: number;
  private readonly perturbacoesPorPar: number;

  constructor({ tamanhoBloco = 32, perturbacoesPorPar = 5 }: { tamanhoBloco?: number; perturbacoesPorPar?: number } = {}) {
    this.tamanhoBloco = tamanhoBloco;
    this.perturbacoesPorPar = perturbacoesPorPar;
  }

  nome(): string {
    return 'Cobertura de dependência (matriz entrada x saída)';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    const tamanho = this.tamanhoBloco;
    const chaveBase = Buffer.alloc(tamanho);
    const iv = randomBytes(alvo.tamanhoIv());

    const ksBase: Buffer | null = alvo.gerarKeystreamBruto(chaveBase, iv, 'enc', tamanho);
    if (ksBase == null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }
    if (chaveBase.length !== tamanho) {
      // A chave precisa ter o mesmo tamanho do bloco pra esse teste
      // isolar 1 posição de cada vez sem wraparound. Se a cifra usa
      // chave de outro tamanho, pula esse ataque.
      throw new SkipAtaqueException('Teste requer chave do mesmo tamanho do bloco.');
    }

    const paresIndependentes: string[] = [];

    for (let posEntrada = 0; posEntrada < tamanho; posEntrada++) {
      const afetouAlgumaSaida = new Array<boolean>(tamanho).fill(false);

      for (let p = 0; p < this.perturbacoesPorPar; p++) {
        const chaveTeste = Buffer.from(chaveBase);
        chaveTeste[posEntrada] = randomInt(1, 255);
        const ks = alvo.gerarKeystreamBruto(chaveTeste, iv, 'enc', tamanho);

        for (let posSaida = 0; posSaida < tamanho; posSaida++) {
          if (ks[posSaida] !== ksBase[posSaida]) {
            afetouAlgumaSaida[posSaida] = true;
          }
        }
      }

      afetouAlgumaSaida.forEach((afetou, posSaida) => {
        if (!afetou) {
          paresIndependentes.push(`entrada[${posEntrada}] -> saída[${posSaida}]`);
        }
      });
    }

    if (paresIndependentes.length > 0) {
      return new ResultadoAtaque(
        this.nome(),
        true,
        'media',
        `${paresIndependentes.length} par(es) sem dependência detectável em ${this.perturbacoesPorPar} tentativas cada`,
        { pares: paresIndependentes.slice(0, 20) },
      );
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `Todos os ${tamanho * tamanho} pares (entrada, saída) mostraram dependência`,
    );
  }
}
