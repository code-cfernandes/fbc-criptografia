import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';
import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { SkipAtaqueException } from '../SkipAtaqueException.ts';

/**
 * Análogo ao AtaqueIVsDegenerados, mas para a CHAVE. Chaves especiais
 * (tudo zero, tudo 0xFF, padrões alternados, baixa entropia) não podem
 * produzir keystream degenerado - e aqui testamos no pior cenário, com IV
 * zerado junto, pra isolar a contribuição da chave.
 */
export class AtaqueChavesDegeneradas implements AtaqueInterface {
  private readonly tamanhoBloco: number;

  constructor({ tamanhoBloco = 32 }: { tamanhoBloco?: number } = {}) {
    this.tamanhoBloco = tamanhoBloco;
  }

  nome(): string {
    return 'Chaves degeneradas (zero, 0xFF, alternada, baixa entropia)';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    const tamChave = Buffer.byteLength(alvo.chaveDeTeste(), 'utf8');
    const ivZero = Buffer.alloc(alvo.tamanhoIv());

    const primeiro: Buffer | null = alvo.gerarKeystreamBruto(
      alvo.chaveDeTeste(),
      ivZero,
      'enc',
      this.tamanhoBloco,
    );
    if (primeiro == null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }

    const seqCrescente = Buffer.alloc(512);
    for (let i = 0; i < 512; i++) {
      seqCrescente[i] = i % 256;
    }

    const casos: Record<string, Buffer> = {
      zero: Buffer.alloc(tamChave),
      '0xFF': Buffer.alloc(tamChave, 0xff),
      'alternada 0xAA': Buffer.alloc(tamChave, 0xaa),
      'alternada 0x55': Buffer.alloc(tamChave, 0x55),
      'repetida "A"': Buffer.alloc(tamChave, 0x41),
      crescente: seqCrescente.subarray(0, tamChave),
    };

    const problemas: Record<string, { periodico: boolean; bytes_unicos: number }> = {};
    for (const nome of Object.keys(casos)) {
      const chave = casos[nome];
      const ks = alvo.gerarKeystreamBruto(chave, ivZero, 'enc', this.tamanhoBloco);

      const metade = Math.floor(this.tamanhoBloco / 2);
      const periodico = ks.subarray(0, metade).equals(ks.subarray(metade, metade + metade));
      const bytesUnicos = new Set(ks).size;

      if (periodico || bytesUnicos < this.tamanhoBloco * 0.5) {
        problemas[nome] = { periodico, bytes_unicos: bytesUnicos };
      }
    }

    if (Object.keys(problemas).length > 0) {
      const detalhe = Object.keys(problemas)
        .map((nome) => {
          const info = problemas[nome];
          return `${nome} (periódico=${info.periodico ? 'sim' : 'não'}, bytes únicos=${info.bytes_unicos}/${this.tamanhoBloco})`;
        })
        .join('; ');
      return new ResultadoAtaque(this.nome(), true, 'alta', detalhe, problemas);
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `Nenhuma das ${Object.keys(casos).length} chaves degeneradas testadas produziu saída anômala`,
    );
  }
}
