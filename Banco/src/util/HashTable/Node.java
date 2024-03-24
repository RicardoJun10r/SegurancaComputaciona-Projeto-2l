package util.HashTable;

public class Node<V, K> {

    private Node<V, K> prox;

    private Node<V, K> ant;

    private V valor;

    private K chave;

    private Integer frequencia;

    public Node(V valor, K chave) {
        this.valor = valor;
        this.chave = chave;
        this.ant = null;
        this.prox = null;
        this.frequencia = 0;
    }

    public Node<V, K> getProx() {
        return prox;
    }

    public void setProx(Node<V, K> prox) {
        this.prox = prox;
    }

    public Node<V, K> getAnt() {
        return ant;
    }

    public void setAnt(Node<V, K> ant) {
        this.ant = ant;
    }

    public V getValor() {
        return valor;
    }

    public void setValor(V valor) {
        this.valor = valor;
    }

    public K getChave() {
        return chave;
    }

    public void setChave(K chave) {
        this.chave = chave;
    }

    public Integer getFrequencia() {
        return frequencia;
    }

    public void setFrequencia(Integer frequencia) {
        this.frequencia = frequencia;
    }
    
}

