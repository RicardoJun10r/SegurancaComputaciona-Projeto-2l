package util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.SocketAddress;

public class ClientSocket {
    
    private String id;

    private final Socket socket;

    private final BufferedReader leitor;

    private final PrintWriter escritor;

    private ObjectOutputStream ObjectOutputStream;

    private ObjectInputStream objectInputStream;

    public ClientSocket(Socket socket) throws IOException{
        this.socket = socket;
        System.out.println("Cliente = " + socket.getRemoteSocketAddress() + " conectado!");
        this.id = socket.getRemoteSocketAddress().toString().split(":")[1];
        this.leitor = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.escritor = new PrintWriter(socket.getOutputStream(), true);
        this.ObjectOutputStream = new ObjectOutputStream(socket.getOutputStream());
        this.objectInputStream = new ObjectInputStream(socket.getInputStream());
    }

    public SocketAddress getSocketAddress(){
        return this.socket.getRemoteSocketAddress();
    }

    public void setId(String id){
        this.id = id;
    }

    public String getId(){
        return this.id;
    }

    public void enviarObjeto(Object object){
        try {
            this.ObjectOutputStream.writeObject(object);
            this.ObjectOutputStream.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public Object receberObjeto(){
        Object object = null;
        try {
            object = this.objectInputStream.readObject();
        } catch (ClassNotFoundException | IOException e) {
            e.printStackTrace();
        }
        return object;
    }

    public void closeInputStream(){
        try {
            this.objectInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void closeOutputStream(){
        try {
            this.objectInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void close(){
        try {
            this.leitor.close();
            this.escritor.close();
            this.socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String getMessage(){
        try {
            return this.leitor.readLine();
        } catch (IOException e) {
            e.printStackTrace();
            return "\nERRO [ NA MENSAGEM ]: " + e.getMessage();
        }
    }

    public boolean sendMessage(String mensagem){
        this.escritor.println(mensagem);
        return !this.escritor.checkError();
    }
    
}
