package model;

import java.io.Serializable;

public class ContaCorrente implements Serializable {

    // ID
    private String cpf;
    
    private String nome;

    private String endereco;

    private String telefone;

    private String senha;

    private Double saldo;

    private Boolean logado;

    public ContaCorrente(String nome, String cpf, String endereco, String telefone, String senha, Double saldo) {
        this.nome = nome;
        this.cpf = cpf;
        this.endereco = endereco;
        this.telefone = telefone;
        this.senha = senha;
        this.saldo = saldo;
        this.logado = false;
    }

    public ContaCorrente(String nome, String cpf, String endereco, String telefone, String senha) {
        this.nome = nome;
        this.cpf = cpf;
        this.endereco = endereco;
        this.telefone = telefone;
        this.senha = senha;
        this.saldo = .0d;
        this.logado = false;
    }

    public Boolean getLogado() {
        return logado;
    }

    public void setLogado(Boolean logado) {
        this.logado = logado;
    }

    public Double getSaldo() {
        return saldo;
    }

    public void setSaldo(Double investimento) {
        this.saldo = investimento;
    }

    public String getNome() {
        return nome;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }

    public String getSenha() {
        return senha;
    }

    public void setSenha(String senha) {
        this.senha = senha;
    }

    public String getCpf() {
        return cpf;
    }

    public void setCpf(String cpf) {
        this.cpf = cpf;
    }

    public String getEndereco() {
        return endereco;
    }

    public void setEndereco(String endereco) {
        this.endereco = endereco;
    }

    public String getTelefone() {
        return telefone;
    }

    public void setTelefone(String telefone) {
        this.telefone = telefone;
    }

    public void saque(Double quantia){
        if(quantia > this.saldo) return;
        else this.saldo -= quantia;
    }

    public void deposito(Double quantia){
        this.saldo += quantia;
    }

    @Override
    public String toString() {
        return "ContaCorrente [cpf=" + cpf + ", nome=" + nome + ", endereco=" + endereco + ", telefone=" + telefone
                + ", senha=" + senha + ", saldo=" + saldo + ", logado=" + logado + "]";
    }

}
