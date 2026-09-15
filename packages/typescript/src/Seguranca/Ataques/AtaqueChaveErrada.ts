import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';
import { CriptografiaAlvo } from '../CriptografiaAlvo.ts';
import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { SkipAtaqueException } from '../SkipAtaqueException.ts';
import { randomBytes } from '../Util.ts';

/**
 * Garante que um token só decifra com a chave correta: com qualquer outra
 * chave de 32 bytes, decrypt() tem que lançar. Verifica também que a chave
 * errada não "quase funciona" (ex: aceitar às vezes por MAC fraco).
 *
 * Cuidado: CriptografiaAlvo escreve a chave no ambiente do processo; a chave
 * original é restaurada no final pra não afetar os outros ataques.
 */
export class AtaqueChaveErrada implements AtaqueInterface {
  private readonly tentativas: number;

  constructor({ tentativas = 30 }: { tentativas?: number } = {}) {
    this.tentativas = tentativas;
  }

  nome(): string {
    return 'Rejeição de chave incorreta';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    if (!(alvo instanceof CriptografiaAlvo)) {
      throw new SkipAtaqueException('Precisa de CriptografiaAlvo para trocar a chave.');
    }

    const chaveOriginal = alvo.chaveDeTeste();

    const tokens: string[] = [];
    for (let i = 0; i < this.tentativas; i++) {
      tokens.push(alvo.encrypt(`MENSAGEM_SECRETA_${i}`));
    }

    const aceitos: string[] = [];
    try {
      tokens.forEach((token, i) => {
        new CriptografiaAlvo(randomBytes(16).toString('hex'));
        try {
          const r = alvo.decrypt(token);
          aceitos.push(`tentativa ${i} aceitou (retornou ${r})`);
        } catch (e) {
          // esperado
        }
      });
    } finally {
      process.env.FBC_KEY = chaveOriginal;
    }

    if (aceitos.length > 0) {
      return new ResultadoAtaque(
        this.nome(),
        true,
        'critica',
        `${aceitos.length} de ${this.tentativas} tokens foram aceitos com a chave errada`,
        { exemplos: aceitos.slice(0, 5) },
      );
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `Nenhum dos ${this.tentativas} tokens foi aceito com chave incorreta`,
    );
  }
}
