package util;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class Seguranca implements Serializable {

    public static final String ALG = "HmacSHA256";

    private KeyGenerator geradorDeChaves;

    private SecretKey chave;

    private String vernan;

    private String mensagem;

    private String mensagemCifrada;

    public Seguranca(int num) {
        try {
            gerarChave(num);
            gerarChaveVernan(num);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public Seguranca() {
    }

    public void setChave(SecretKey secretKey) {
        this.chave = secretKey;
    }

    public SecretKey getChave() {
        return chave;
    }

    public void setChaveVernan(String vernan) {
        this.vernan = vernan;
    }

    public String getChaveVernan() {
        return vernan;
    }

    private void gerarChave(int t) throws NoSuchAlgorithmException {
        geradorDeChaves = KeyGenerator.getInstance("AES");
        geradorDeChaves.init(t);
        chave = geradorDeChaves.generateKey();
    }

    private void gerarChaveVernan(int t){
        String chave = "";

        for (int i = 0; i < t; i++) {
            char caractere = (char) ('a' + Math.random() * ('z' - 'a' + 1));
            chave += caractere;
        }
        this.vernan = chave.toString();
    }

    public String cifrar(String textoAberto) {

        String textoCifradoVernan = cifrarVernan(textoAberto);

        byte[] bytesMensagemCifrada = null;

        Cipher cifrador = null;

        mensagem = textoCifradoVernan;
        try {
            cifrador = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cifrador.init(Cipher.ENCRYPT_MODE, chave);
            bytesMensagemCifrada = cifrador.doFinal(mensagem.getBytes());
            mensagemCifrada = codificar(bytesMensagemCifrada);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException
                | InvalidKeyException e) {
            e.printStackTrace();
        }

        return mensagemCifrada;
    }

    private String codificar(byte[] bytesCifrados) {
        String mensagemCodificada = Base64
                .getEncoder()
                .encodeToString(bytesCifrados);
        return mensagemCodificada;
    }

    private byte[] decodificar(String mensagemCodificada) {
        mensagemCodificada = mensagemCodificada.replaceAll("\\s", "");
        byte[] bytesCifrados = Base64
                .getDecoder()
                .decode(mensagemCodificada);
        return bytesCifrados;
    }

    public String decifrar(String textoCifrado) {

        byte[] bytesMensagemCifrada = decodificar(textoCifrado);
        String mensagemDecifrada = "";

        try {
            Cipher decriptador = Cipher.getInstance("AES/ECB/PKCS5Padding");
            decriptador.init(Cipher.DECRYPT_MODE, chave);
            byte[] bytesMensagemDecifrada = decriptador.doFinal(bytesMensagemCifrada);
            mensagemDecifrada = new String(bytesMensagemDecifrada);
            mensagem = mensagemDecifrada;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException
                | InvalidKeyException e) {
            e.printStackTrace();
        }
        return decifrarVernan(mensagem);
    }

    public String hMac(String mensagem) {
        byte[] bytesHMAC = null;
        try {
            Mac shaHMAC = Mac.getInstance(ALG);
            shaHMAC.init(chave);
            bytesHMAC = shaHMAC
                    .doFinal(mensagem.getBytes("UTF-8"));
        } catch (NoSuchAlgorithmException | InvalidKeyException | IllegalStateException
                | UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return Base64.getEncoder().encodeToString(bytesHMAC);
    }

    public String cifrarVernan(String texto_original) {
        
        StringBuilder stringBuilder = new StringBuilder();

        for (int i = 0; i < texto_original.length(); i++) {
            
            char charMensagem = texto_original.charAt(i);
            
            char charKey = this.vernan.charAt(i % this.vernan.length());

            char charCifrado = (char)(charMensagem ^ charKey);

            stringBuilder.append(charCifrado);

        }

        return stringBuilder.toString();

    }

    public String decifrarVernan(String texto_cifrado) { return cifrarVernan(texto_cifrado); }

}
