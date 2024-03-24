package server;

import java.io.IOException;

public class MainBanco {
    public static void main(String[] args) {
        BancoServer bancoServer = new BancoServer();

        try {
            bancoServer.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
