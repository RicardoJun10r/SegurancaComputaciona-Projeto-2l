package server;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.LinkedList;
import java.util.List;

import model.ContaCorrente;
import util.ClientSocket;
import util.Seguranca;
import util.HashTable.Table;

public class BancoServer {

    public final int PORTA = 1025;

    private ServerSocket serverSocket;

    private final List<ClientSocket> USUARIOS = new LinkedList<>();

    private Table<ContaCorrente, Integer> tabela;

    public static final Seguranca seguranca = new Seguranca(192);

    private final Double POUPANCA = 0.5d;

    private final Double RENDA_FIXA = 1.5d;

    public BancoServer() {
        this.tabela = new Table<>();
        this.tabela.Adicionar(
                new ContaCorrente("João Silva", "123", "Rua A, 123", "987654321", "senha123", 100.0),
                Integer.parseInt("123"));
        this.tabela.Adicionar(
                new ContaCorrente("Maria Oliveira", "456", "Rua B, 456", "123456789", "senha456", 100.0),
                Integer.parseInt("456"));
        this.tabela.Adicionar(
                new ContaCorrente("Carlos Santos", "789", "Rua C, 789", "456789012", "senha789", 100.0),
                Integer.parseInt("789"));
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket(PORTA);
        System.out.println("Iniciando servidor na porta = " + PORTA);
        clientConnectionLoop();
    }

    private void clientConnectionLoop() throws IOException {
        while (true) {
            ClientSocket clientSocket = new ClientSocket(this.serverSocket.accept());
            USUARIOS.add(clientSocket);
            new Thread(() -> {
                try {
                    clientMessageLoop(clientSocket);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();
        }
    }

    private void clientMessageLoop(ClientSocket clientSocket) throws IOException {
        String mensagem;
        String hmac = "";
        try {
            while ((mensagem = clientSocket.getMessage()) != null) {
                if (!mensagem.split(";")[0].equals("1") && !mensagem.split(";")[0].equals("2")) {
                    hmac = mensagem.split(";")[1];
                    mensagem = seguranca.decifrar(mensagem.split(";")[0]);
                }
                switch (mensagem.split(";")[0]) {
                    case "sair": {
                        // SAIR
                        System.out.println(
                                "[sair] Mensagem de " + clientSocket.getSocketAddress() + ": " + mensagem);
                        break;
                    }
                    case "1": {
                        // AUTENTICAR
                        System.out.println(
                                "[1] Mensagem de " + clientSocket.getSocketAddress() + ": " + mensagem);
                                try {
                                    ContaCorrente contaCorrente = this.tabela.BuscarCF(Integer.parseInt(mensagem.split(";")[1]))
                                            .getValor();
                                    if (contaCorrente != null) {
                                        if (mensagem.split(";")[2].equals(contaCorrente.getSenha())) {
                                            unicast(clientSocket, "status true " + seguranca.getChaveVernan());
                                            try {
                                                Thread.sleep(100);
                                            } catch (InterruptedException e) {
                                                e.printStackTrace();
                                            }
                                            clientSocket.enviarObjeto(seguranca.getChave());
                                        } else {
                                            unicast(clientSocket, "status false");
                                        }
                                    } else {
                                        unicast(clientSocket, "status false");
                                    }
                                    
                                } catch (NullPointerException e) {
                                    e.printStackTrace();
                                }
                        break;
                    }
                    case "2": {
                        // CRIAR CONTA
                        System.out.println(
                                "[2] Mensagem de " + clientSocket.getSocketAddress() + ": " + mensagem);
                        String[] msg = mensagem.split(";");
                        try {
                            this.tabela.Adicionar(new ContaCorrente(msg[2], msg[1], msg[3], msg[4], msg[5]),
                                    Integer.parseInt(msg[1]));
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        unicast(clientSocket, "Criado!");
                        break;
                    }
                    case "3": {
                        // SAQUE
                        if (autenticarMensagem(mensagem, hmac)) {
                            System.out.println(
                                    "[3] Mensagem de " + clientSocket.getSocketAddress() + ": " + mensagem);
                            ContaCorrente contaCorrente = this.tabela.BuscarCF(Integer.parseInt(mensagem.split(";")[1]))
                                    .getValor();
                            contaCorrente.saque(Double.valueOf(mensagem.split(";")[2]));
                            try {
                                this.tabela.Atualizar(contaCorrente, Integer.parseInt(mensagem.split(";")[1]));
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                            unicast(clientSocket, "Quantia Retirada");
                        }
                        break;
                    }
                    case "4": {
                        // DEPÓSITO
                        if (autenticarMensagem(mensagem, hmac)) {
                            System.out.println(
                                    "[4] Mensagem de " + clientSocket.getSocketAddress() + ": " + mensagem);
                            ContaCorrente contaCorrente = this.tabela.BuscarCF(Integer.parseInt(mensagem.split(";")[1]))
                                    .getValor();
                            contaCorrente.deposito(Double.valueOf(mensagem.split(";")[2]));
                            try {
                                this.tabela.Atualizar(contaCorrente, Integer.parseInt(mensagem.split(";")[1]));
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                            unicast(clientSocket, "Quantia Adicionada");
                        }
                        break;
                    }
                    case "5": {
                        // TRANSFERÊNCIA
                        if (autenticarMensagem(mensagem, hmac)) {
                            System.out.println(
                                    "[5] Mensagem de " + clientSocket.getSocketAddress() + ": " + mensagem);
                            ContaCorrente contaCorrenteEmissor = this.tabela
                                    .BuscarCF(Integer.parseInt(mensagem.split(";")[1])).getValor();
                            contaCorrenteEmissor.saque(Double.valueOf(mensagem.split(";")[3]));
                            try {
                                this.tabela.Atualizar(contaCorrenteEmissor, Integer.parseInt(mensagem.split(";")[1]));
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                            ContaCorrente contaCorrenteDestino = this.tabela
                                    .BuscarCF(Integer.parseInt(mensagem.split(";")[2])).getValor();
                            contaCorrenteDestino.deposito(Double.valueOf(mensagem.split(";")[3]));
                            try {
                                this.tabela.Atualizar(contaCorrenteDestino, Integer.parseInt(mensagem.split(";")[2]));
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                        break;
                    }
                    case "6": {
                        // SALDO
                        if (autenticarMensagem(mensagem, hmac)) {
                            System.out.println("MENSAGEM APROVADA");
                            System.out.println(
                                    "[6] Mensagem de " + clientSocket.getSocketAddress() + ": " + mensagem);
                            ContaCorrente contaCorrente = this.tabela.BuscarCF(Integer.parseInt(mensagem.split(";")[1]))
                                    .getValor();
                            unicast(clientSocket, "Saldo = R$ [ " + contaCorrente.getSaldo() + " ]");
                        }
                        break;
                    }
                    case "7": {
                        // POUPANÇA
                        if (autenticarMensagem(mensagem, hmac)) {
                            System.out.println(
                                    "[7] Mensagem de " + clientSocket.getSocketAddress() + ": " + mensagem);
                            ContaCorrente contaCorrente = this.tabela.BuscarCF(Integer.parseInt(mensagem.split(";")[1]))
                                    .getValor();
                            if (Double.parseDouble(mensagem.split(";")[2]) > contaCorrente.getSaldo()) {
                                unicast(clientSocket, "Saldo INSUFICIENTE");
                            } else {
                                Double saldoAnt = contaCorrente.getSaldo();
                                contaCorrente.setSaldo(calcularJurosCompostos(contaCorrente.getSaldo(), POUPANCA,
                                        Integer.parseInt(mensagem.split(";")[3])));
                                try {
                                    this.tabela.Atualizar(contaCorrente, Integer.parseInt(contaCorrente.getCpf()));
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                                unicast(clientSocket, "INVESTIMENTO APROVADO\nSALDO ANTES: R$ " + saldoAnt
                                        + "\nSALDO AGORA DE: R$ " + contaCorrente.getSaldo());
                            }
                        }
                        break;
                    }
                    case "8": {
                        // RENDA FIXA
                        if (autenticarMensagem(mensagem, hmac)) {
                            System.out.println(
                                    "[7] Mensagem de " + clientSocket.getSocketAddress() + ": " + mensagem);
                            ContaCorrente contaCorrente = this.tabela.BuscarCF(Integer.parseInt(mensagem.split(";")[1]))
                                    .getValor();
                            if (Double.parseDouble(mensagem.split(";")[2]) > contaCorrente.getSaldo()) {
                                unicast(clientSocket, "Saldo INSUFICIENTE");
                            } else {
                                Double saldoAnt = contaCorrente.getSaldo();
                                contaCorrente.setSaldo(calcularJurosCompostos(contaCorrente.getSaldo(), RENDA_FIXA,
                                        Integer.parseInt(mensagem.split(";")[3])));
                                try {
                                    this.tabela.Atualizar(contaCorrente, Integer.parseInt(contaCorrente.getCpf()));
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                                unicast(clientSocket, "INVESTIMENTO APROVADO\nSALDO ANTES: R$ " + saldoAnt
                                        + "\nSALDO AGORA DE: R$ " + contaCorrente.getSaldo());
                            }
                        }
                        break;
                    }
                    case "9": {
                        // SIMULAÇÃO POUPANÇA
                        if (autenticarMensagem(mensagem, hmac)) {
                            System.out.println(
                                    "[7] Mensagem de " + clientSocket.getSocketAddress() + ": " + mensagem);
                            ContaCorrente contaCorrente = this.tabela.BuscarCF(Integer.parseInt(mensagem.split(";")[1]))
                                    .getValor();

                            Double simulacao = calcularJurosCompostos(contaCorrente.getSaldo(), POUPANCA,
                                    Integer.parseInt(mensagem.split(";")[3]));
                            unicast(clientSocket, "SIMULAÇÃO DE INVESTIMENTO NA POUPANÇA POR [ "
                                    + mensagem.split(";")[3] + " ] MÊSES, RENDERIA: R$ " + simulacao);
                        }
                        break;
                    }
                    case "10": {
                        // SIMULAÇÃO RENDA FIXA
                        if (autenticarMensagem(mensagem, hmac)) {
                            System.out.println(
                                    "[7] Mensagem de " + clientSocket.getSocketAddress() + ": " + mensagem);
                            ContaCorrente contaCorrente = this.tabela.BuscarCF(Integer.parseInt(mensagem.split(";")[1]))
                                    .getValor();

                            Double simulacao = calcularJurosCompostos(contaCorrente.getSaldo(), RENDA_FIXA,
                                    Integer.parseInt(mensagem.split(";")[3]));
                            unicast(clientSocket, "SIMULAÇÃO DE INVESTIMENTO NA RENDA FIXA POR [ "
                                    + mensagem.split(";")[3] + " ] MÊSES, RENDERIA: R$ " + simulacao);
                        }
                        break;
                    }
                    default:
                        System.out.println(
                                "Mensagem de " + clientSocket.getSocketAddress() + ": " + mensagem);
                        break;
                }
            }
        } finally {
            clientSocket.close();
        }
    }

    private double calcularJurosCompostos(double valorPresente, double taxaJuros, int meses) {

        double taxaDecimal = taxaJuros / 100.0;

        return valorPresente * Math.pow(1 + taxaDecimal, meses);

    }

    private Boolean autenticarMensagem(String mensagem, String hmac_recebido) {
        String hmac = seguranca.hMac(mensagem);
        if (hmac.equals(hmac_recebido))
            return true;
        else
            return false;
    }

    private void unicast(ClientSocket destinario, String mensagem) {
        ClientSocket emissor = this.USUARIOS.stream()
                .filter(user -> user.getSocketAddress().equals(destinario.getSocketAddress()))
                .findFirst().get();
        emissor.sendMessage(mensagem);
    }

}
