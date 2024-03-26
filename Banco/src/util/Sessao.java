package util;

import util.Seguranca.RSA;

public class Sessao {
    
    private Boolean logado;

    private RSA rsa;
    
    public Sessao(Boolean logado) {
        this.logado = logado;
        this.rsa = new RSA();
    }
    
    public RSA getRsa() {
        return rsa;
    }

    public void setRsa(RSA rsa) {
        this.rsa = rsa;
    }

    public Boolean getLogado() {
        return logado;
    }

    public void setLogado(Boolean logado) {
        this.logado = logado;
    }

}
