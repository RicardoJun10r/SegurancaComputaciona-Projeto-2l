package util.HashTable;

import java.text.DecimalFormat;

public class Table<V, K> {
    
    private Node<V, K>[] tabela;

    private int M;

    private Integer size;

    private DecimalFormat decimalFormat;

    private Boolean isResize;

    @SuppressWarnings("unchecked")
    public Table(){
        this.M = 10;
        this.tabela = new Node[this.M];
        this.size = 0;
        this.isResize = true;
        this.decimalFormat = new DecimalFormat("0.00");
    }

    private Integer Hash(Integer chave){
        return chave % this.M;
    }

    private Integer ProximoPrimo(Integer num){
        for (int i = num + 1; i < num*2; i++) {
            if(isPrime(i)) return i;
        }
        return -1;
    }

    private Boolean isPrime(Integer num){
        int cont = 0;
        for (int i = num; i >= 1; i--) {
            if((num % i) == 0) cont++;
        }

        if(cont == 2) return true;
        else return false;
    }

    public void Adicionar(V valor, K chave){

        Integer posicao = Hash((Integer) chave);

        if(this.tabela[posicao] == null){
            this.tabela[posicao] = new Node<>(valor, chave);
        } else {

            Node<V, K> noHash = this.tabela[posicao];
    
            Node<V, K> no_ant = noHash;
    
            while(noHash != null){
                if(noHash.getValor().equals(valor)) break;
                no_ant = noHash;
                noHash = noHash.getProx();
            }
    
            if(noHash == null){
                noHash = new Node<>(valor, chave);
                no_ant.setProx(noHash);
                noHash.setAnt(no_ant);
            } else return;

        }

        this.size++;

        if(this.isResize){

            Double fator = FatorDeCarga();
    
            System.out.println();
    
            System.out.println("Fator de carga = " + this.decimalFormat.format(fator));
    
            System.out.println();
    
            System.out.println("Posição = " + posicao + " Valor = " + valor.toString());
    
            System.out.println();
    
            if(fator >= 0.7d){
                Redimensionar();
            }

        } else {
            this.isResize = true;
        }


    }

    @SuppressWarnings("unchecked")
    private void Redimensionar(){
        
        this.M = ProximoPrimo(this.M*2);
        
        Node<V, K>[] velha_tabela = this.tabela;

        this.tabela = new Node[this.M];

        this.isResize = false;

        for (int i = 0; i < velha_tabela.length; i++) {

            if(velha_tabela[i] != null){

                Adicionar(velha_tabela[i].getValor(), velha_tabela[i].getChave());

            }
            
        }

    }

    public Node<V, K> BuscarCF(K chave){
        Integer posicao = Hash((Integer)chave);
        Node<V, K> noHash = this.tabela[posicao];
        System.out.println("Buscando");
        while (noHash != null) {
            if(noHash.getChave().equals(chave)) break;
            noHash = noHash.getProx();
        }
        
        if(noHash != null){
            noHash.setFrequencia(noHash.getFrequencia()+1);
            CF(noHash, posicao);
            return noHash;
        }
        return null;
    }

    private void CF(Node<V, K> no, Integer posicao){
        if(this.tabela[posicao].equals(no)) return;
        else{
            while(no.getFrequencia() > no.getAnt().getFrequencia()){
                V temp = no.getAnt().getValor();
                Integer freq = no.getAnt().getFrequencia();
                K chave = no.getAnt().getChave();
                no.getAnt().setValor( no.getValor() );
                no.getAnt().setFrequencia( no.getFrequencia() );
                no.getAnt().setChave(no.getChave());
                no.setChave( chave );
                no.setValor( temp );
                no.setFrequencia( freq );
                if(no.getAnt() != null) no = no.getAnt();
                if(this.tabela[posicao].equals(no)) return;
            }
            return;
        }
    }

    private Boolean ProxNull(Node<V, K> no){
        if(no.getProx() == null) return true;
        else return false;
    }

    private Boolean AntNull(Node<V, K> no){
        if(no.getAnt() == null) return true;
        else return false;
    }

    public void Atualizar(V valor, K chave) throws Exception{

        Integer posicao = Hash((Integer) chave);

        Node<V, K> noHash = this.tabela[posicao];

        while(noHash != null){
            if(noHash.getChave().equals(chave)) break;
            noHash = noHash.getProx();
        }

        if(noHash != null){
            System.out.println("Atualizando");
            noHash.setValor(valor);
        } else throw new Exception("Erro: não encontrado");

    }

    public Double FatorDeCarga(){
        int total = 0;
        Node<V, K> index;
        for(int i = 0; i < this.M; i++){
            index = this.tabela[i];
            while (index != null) {
                index = index.getProx();
                total++;
            }
        }
        return (double) total / this.M;
    }

    public void Remover(Integer chave) throws Exception{
        Integer posicao = Hash((Integer)chave);
        
        if(this.tabela[posicao] == null) throw new Exception("Erro: não encontrado");
        
        Node<V, K> noHash = this.tabela[posicao];
        System.out.println("Removendo");

        while(noHash != null) {
            if(noHash.getChave().equals(chave)) break;
            noHash = noHash.getProx();
        }

        if(noHash == null) throw new Exception("Erro: não encontrado");

        if(AntNull(noHash)){
            this.tabela[posicao] = noHash.getProx();
        }
        else if(ProxNull(noHash)){
            noHash.getAnt().setProx(null);
        } else {
            noHash.getProx().setAnt(noHash.getAnt());
            noHash.getAnt().setProx(noHash.getProx());
        }
        

        noHash.setProx(null);
        noHash.setAnt(null);
        noHash = null;

        this.size--;
        System.out.println("Fator de carga = " + this.decimalFormat.format(FatorDeCarga()));
    }

    public String Print(){
        StringBuffer res = new StringBuffer();
        Node<V, K> index;
        for(int i = 0; i < this.M; i++){
            index = this.tabela[i];
            res.append(i);
            while (index != null) {
                res.append(" --> "); 
                res.append(index.getValor());
                index = index.getProx();
            }
            res.append("\n");
        }

        return res.toString();
    }

    public Integer Tamanho(){
        return this.M;
    }

    public Integer Quantidade(){
        return this.size;
    }

}
