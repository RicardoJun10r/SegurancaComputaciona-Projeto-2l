package client;

import java.io.IOException;

public class MainUsuario {
    public static void main(String[] args) {
        Usuarios usuarios = new Usuarios();

        try {
            usuarios.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
