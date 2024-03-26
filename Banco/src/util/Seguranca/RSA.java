package util.Seguranca;
import java.util.Random;

public class RSA {
    
    private long p;

    private long q;

    private long n;

    // #region USUARIO A

    private long e;

    // #endregion

    // #region USUARIO B

    private long d;

    private long phi;

    private long e_extrangeiro;

    // #endregion

    private Random random;

    public RSA(){
        this.random = new Random();
    }

    public void phi(long p, long q) {
        this.phi = (p - 1) * (q - 1);
    }

    long expMod(long a, long b, long p) {
        if (b == 1)
            return a;
        else
            return (((long) Math.pow(a, b)) % p);
    }

    public void expD(long e, long totiente) {
        long i = 1;
        long d;
        while (true) {
            if (e * i % totiente == 1) {
                d = i;
                break;
            }
            i++;
        }
        this.d = d;
    }

    public String cifragemCliente(String msg) {
        StringBuffer cifrado = new StringBuffer();

        System.out.println("cifrando: " + msg);

        for (int i = 0; i < msg.length(); i++) {
            int str_0xff = expModCifra2(msg.charAt(i), e, n);
            cifrado.append(str_0xff).append(" ");
        }
        
        return cifrado.toString();
    }

    public String cifragemServer(String msg) {
        StringBuffer cifrado = new StringBuffer();

        System.out.println("cifrando: " + msg);

        for (int i = 0; i < msg.length(); i++) {
            int str_0xff = expModCifra2(msg.charAt(i), e_extrangeiro, n);
            cifrado.append(str_0xff).append(" ");
        }
        
        return cifrado.toString();
    }

    String expModCifra(int msg, long e, long n) {
        return String.valueOf((((long) Math.pow(msg, e)) % n));
    }

    int expModCifra2(int msg, long e, long n) {
        long resultado = 1;
        msg = msg % (int)n;
        
        while (e > 0) {
            if (e % 2 == 1) {
                resultado = (resultado * msg) % n;
            }
            e = e >> 1;
            msg = (msg * msg) % (int)n;
        }
        
        return (int)resultado;
    }

    int expModDecifra(long msg, long d, long n) {
        System.out.println("msg = " + msg + " d = " + d + " n = " + n);
        long resultado = (long) (Math.pow(msg, d) % n);
        System.out.println("resultado = " + resultado);
        return (int)resultado;
    }

    int expModDecifra2(long msg, long d, long n) {
        long resultado = 1;
        msg = msg % n;
        
        while (d > 0) {
            if (d % 2 == 1) {
                resultado = (resultado * msg) % n;
            }
            d = d >> 1;
            msg = (msg * msg) % n;
        }
        
        return (int) resultado;
    }

    public String decifragemCliente(String msg) {
        StringBuffer decifrado = new StringBuffer();

        String[] texto_cifrado = msg.split(" ");

        for (int i = 0; i < texto_cifrado.length; i++) {
            char ff_str = (char) expModDecifra2(Long.parseLong(texto_cifrado[i]), this.d, this.n);
            decifrado.append(ff_str);
        }
        
        return decifrado.toString();
    }

    public String decifragemServer(String msg) {
        StringBuffer decifrado = new StringBuffer();

        String[] texto_cifrado = msg.split(" ");

        for (int i = 0; i < texto_cifrado.length; i++) {
            char ff_str = (char) expModDecifra2(Long.parseLong(texto_cifrado[i]), this.d, this.n);
            decifrado.append(ff_str);
        }
        
        return decifrado.toString();
    }

    public void gerarPG(){
        int p, q;

        while(true){
            int i = this.random.nextInt(50);
            if(ehPrimo(i) && i > 9){
                p = i;
                break;
            }
        }

        while(true){
            int i = this.random.nextInt(60);
            if(ehPrimo(i) && i > 9 && i > p){
                q = i;
                break;
            }
        }

        this.p = Integer.toUnsignedLong(p);
        this.q = Integer.toUnsignedLong(q);
    }

    public void gerarE(){
        int e;

        while(true){
            int i = this.random.nextInt(50);
            if(ehPrimo(i) && i > 2){
                e = i;
                break;
            }
        }

        this.e = Integer.toUnsignedLong(e);
    }

    public void gerarE_estrangeiro(){
        int e;

        while(true){
            int i = this.random.nextInt(50);
            if(ehPrimo(i) && i > 2){
                e = i;
                break;
            }
        }

        this.e_extrangeiro = Integer.toUnsignedLong(e);
    }
    
    private boolean ehPrimo(int numero){
        int cont = 0;
        for(int i = 1; i <= numero; i++){
            if((numero%i)==0)cont++;
        }
        if(cont == 2) return true;
        else return false;
    }

    public long getP() {
        return p;
    }

    public void setP(long p) {
        this.p = p;
    }

    public long getQ() {
        return q;
    }

    public void setQ(long q) {
        this.q = q;
    }

    public long getN() {
        return n;
    }

    public void setN(long n) {
        this.n = n;
    }

    public long getE() {
        return e;
    }

    public void setE(long e) {
        this.e = e;
    }

    public long getD() {
        return d;
    }

    public void setD(long d) {
        this.d = d;
    }

    public long getPhi() {
        return phi;
    }

    public void setPhi(long phi) {
        this.phi = phi;
    }

    public long getE_extrangeiro() {
        return e_extrangeiro;
    }

    public void setE_extrangeiro(long e_extrangeiro) {
        this.e_extrangeiro = e_extrangeiro;
    }

}
