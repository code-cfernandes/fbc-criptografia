package fbc;

import fbc.Seguranca.CriptografiaAlvo;
import fbc.Seguranca.SuiteDeAtaques;
import fbc.Seguranca.Ataques.AtaqueAdulteracao;
import fbc.Seguranca.Ataques.AtaqueBytesFixos;
import fbc.Seguranca.Ataques.AtaqueChaveErrada;
import fbc.Seguranca.Ataques.AtaqueColisaoIV;
import fbc.Seguranca.Ataques.AtaqueIdaEVolta;
import fbc.Seguranca.Ataques.AtaqueInteroperabilidade;
import fbc.Seguranca.Ataques.AtaqueValidacaoChave;
import fbc.Seguranca.Ataques.AtaqueVetorDeterministico;

/** Runner da suíte de ataques da implementação Java da cifra FBC. */
public final class Main {
    private Main() {
    }

    public static void main(String[] args) {
        CriptografiaAlvo alvo = new CriptografiaAlvo();

        SuiteDeAtaques suite = new SuiteDeAtaques();
        suite.adicionar(new AtaqueIdaEVolta())
                .adicionar(new AtaqueAdulteracao())
                .adicionar(new AtaqueVetorDeterministico())
                .adicionar(new AtaqueInteroperabilidade())
                .adicionar(new AtaqueColisaoIV())
                .adicionar(new AtaqueBytesFixos())
                .adicionar(new AtaqueChaveErrada())
                .adicionar(new AtaqueValidacaoChave());

        boolean passou = suite.rodarEImprimir(alvo);
        System.exit(passou ? 0 : 1);
    }
}
