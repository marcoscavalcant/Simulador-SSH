import java.net.ServerSocket;
import java.net.Socket;
import java.io.File;
import java.io.FileOutputStream;
import java.net.SocketTimeoutException;
import java.io.IOException;
import java.util.Base64; 
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.io.DataInputStream;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.security.Signature;
import java.util.Scanner;
import java.io.FileWriter;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.security.SecureRandom;

 
public class server { 
         private PrivateKey privateKey;
         private PublicKey publicKey;
  
    public static void main(String[] args) throws Exception 
    { 
        try { 
            int port = 8088, opcao; 
  
            // Server Key 
               int y = 3; 
  
            // Declaração de Variáveis
            double clientP, clientG, clientA, f, K; 
            String fstr, id2, id3, pass2, A, b, C, D, E, F; 
            String Ic, Vc, assina, encc;
            String Is = "Server Hello";
            String Vs = "SSH2";
            

            // Estabelecer a conexão 
            ServerSocket serverSocket = new ServerSocket(port); //Construtor lado Server
            System.out.println("\n");
            System.out.println("----------Bem vindo ao Simulador Server SSH2----------");
            System.out.println("Aguardando client on port " + serverSocket.getLocalPort() + "..."); 
            Socket server = serverSocket.accept(); //Método accept
            System.out.println("--------------------------------------------");
            System.out.println("Conectado ao:" + server.getRemoteSocketAddress()); 
            System.out.println("--------------------------------------------");    
            DataInputStream in = new DataInputStream(server.getInputStream());// 
            OutputStream outToclient = server.getOutputStream(); 
            DataOutputStream out = new DataOutputStream(outToclient); 
           

            //Identificador do simulador
            System.out.println("--------------------------------------------");
            System.out.println("Aguardando usuário...");
            id3 =in.readUTF(); 
            if(id3.equals("ubi")){
                      out.writeUTF("ok");
                      out.flush();
                      System.out.println("Usuário:"  + id3);
                      System.out.println("Conexão estabelecida");
                      System.out.println("----------------------------------");
                 }else{
                      out.writeUTF("Nok");
                      out.flush();
                      out.writeUTF("Usuário ou senha inválido");
                      out.flush();
                      out.writeUTF("Conexão não estabelecida");
                      out.flush();
                      System.out.println("Conexão não estabelecida");
                      System.out.println("Usuário ou senha inválido");
                      serverSocket.close();
                      server.close();
                      System.exit(0);
                      }
            
            String user3 = in.readUTF();
            String user4 = in.readUTF();
                      
            // Server Private Key 
            System.out.println("Server Private Key y = " + y); 
            System.out.println("--------------------------------------------");
            
            // Recebe dados do client                    
            Ic = in.readUTF(); //Recebe mensagem inicial 
            System.out.println("::Client --- > Server: Mensagem Inicial  Ic = " + Ic); 
            Vc = in.readUTF(); //Recebe a versão do protocolo
            System.out.println("::Client --- > Server: Versão do Protocolo Vc = " + Vc); 
            System.out.println("--------------------------------------------");
            clientP = Integer.parseInt(in.readUTF()); //Recebe p do client 
            System.out.println("Server < --- > Client : P = " + clientP);
            clientG = Integer.parseInt(in.readUTF()); //Recebe g do client
            System.out.println("Server < --- > Client:  G = " + clientG); 

            // Calcular  (f = g ^ y mod p)       
            f = ((Math.pow(clientG, y)) % clientP); 
            fstr = Double.toString(f); 
            System.out.println("::Calcula Server Public Key (f = g^y mod p): f = " + fstr);
            System.out.println("--------------------------------------------");
            clientA = Double.parseDouble(in.readUTF()); // recebe   e 
            System.out.println("::Client --- > Server:  Client Public Key  e = " + clientA); 
            System.out.println("--------------------------------------------");

            // Enviar dados client 
            // Valor de f            
            out.writeUTF(fstr);  

            // Menssage inicial e versão do protocolo
            out.writeUTF("Server Hello");
            out.flush();
            out.writeUTF("SSH2");
            out.flush();

            File file = new File("C:/Users/" + user3 + "/Desktop/" + user4 +"/server"); //criar o diretório server
            file.mkdir();
            File file2 = new File("C:/Users/" +user3 + "/Desktop/" + user4 + "/server/keys"); //criar o diretório server keys
            file2.mkdir();


            // Calculo da chave simétrica 
            K = ((Math.pow(clientA, y)) % clientP); 
            System.out.println("::Server calcula (K = e^y mod p) ...");
            System.out.println("Chave secreta K = " + K); 
            System.out.println("\n");
            
            // Gerar chave pública e privada RSA e envia a pública para o client
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");   // Criando o objeto gerador  KeyPair
            keyGen.initialize(1024);   // Inicializando o Generador de chaves
            KeyPair pair = keyGen.generateKeyPair();     // Gera o par de chaves
            PrivateKey privKey = pair.getPrivate();    // Obtendo a chave privada do par de chaves
            PublicKey publicKey = pair.getPublic();    // Obtendo a chave pública do par de chaves
            //rsa keyPairGenerator = new rsa();
            System.out.println(":::Server --- > Client: Chave RSA Pública e Assinatura do Hash..."); 
            System.out.println("-------------BEGIN RSA PUBLIC KEY-------------");
            String pKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            System.out.println(pKey);
            String Ks = pKey;
            //byte[] Ks1 = Ks.getBytes();
            //System.out.println(Ks1);
            // envia a chave pública para o client
            ObjectOutputStream out6 = new ObjectOutputStream(new FileOutputStream("C:/Users/" + user3 +"/Desktop/" + user4 + "/client/keys/public.key"));             
	    out6.writeObject(pair.getPublic()); // escreve a chave pública
	    out6.close();
            out6 = new ObjectOutputStream(new FileOutputStream("C:/Users/" + user3 + "/Desktop/" + user4 + "/client/keys/privada.key"));             	 
	    out6.writeObject(pair.getPrivate()); //escreve a chave privada
	    out6.close();        
            // cria um novo arquivo com um ObjectOutputStream
            ObjectOutputStream out4 = new ObjectOutputStream(new FileOutputStream("C:/Users/" + user3 + "/Desktop/" + user4 + "/server/keys/public.key"));             
	    out4.writeObject(pair.getPublic()); // escreve a chave pública
	    out4.close();
            // cria um novo arquivo com um ObjectOutputStream
            out4 = new ObjectOutputStream(new FileOutputStream("C:/Users/" + user3 + "/Desktop/" + user4 + "/server/keys/privada.key"));             	 
	    out4.writeObject(pair.getPrivate()); //escreve a chave privada
	    out4.close();
            System.out.println("-------------END RSA PUBLIC KEY-------------");
            System.out.println("--------------------------------------------"); 
            //System.out.println("RSA/privateKey::" +Base64.getEncoder().encodeToString(keyPairGenerator.getPrivateKey().getEncoded()));            
            out.writeUTF(Ks);
            //ObjectOutputStream outr = new ObjectOutputStream(new FileOutputStream("public.key")); 
            //outr.writeObject(pair.getPublic()); // envia a chave pública para o client                       

            //Valor de Hash
            String hash = Vc  + Vs + Is + Ic + Ks + clientA + fstr + K;
            MessageDigest md = MessageDigest.getInstance("SHA1"); // Criando o objeto hash
            md.update(hash.getBytes()); // Passando dados para o objeto hash criado
            byte [] mdr = md.digest(); // Calcular o resumo da mensagem
            StringBuffer hexString = new StringBuffer(); // Convertendo a matriz de bytes no formato HexString
            for (int i = 0;i<mdr.length;i++) {
                   hexString.append(Integer.toHexString(0xFF & mdr[i]));
              }
            String HD = hexString.toString();
            FileWriter fw = new FileWriter(new File("C:/Users/" + user3 + "/Desktop/" + user4 +"/server/hash.txt"));
	    fw.write(HD);
	    fw.close();
            //System.out.println(HD);
            System.out.println("Hash = (Vc||Vs||Ic||Is||Ks||e||f||K)");
            System.out.println("Hash = " + hexString.toString());   
            System.out.println("--------------------------------------------");
            
            //Session_id
            id2 = HD; 
            //Assinatura digital do Hash e envia para o client
            // cria um ObjectInputStream para o arquivo que foi criado antes
            ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream("C:/Users/" + user3 + "/Desktop/" + user4 + "/server/keys/privada.key")); 
	    PrivateKey privkey = (PrivateKey) keyIn.readObject();
	    keyIn.close();
            Signature signalg = Signature.getInstance("SHA256withRSA");
	    signalg.initSign(privkey);
            File infile = new File("C:/Users/" + user3 + "/Desktop/" + user4 + "/server/hash.txt");
	    InputStream in1 = new FileInputStream(infile);
	    int length = (int) infile.length();
            byte[] message = new byte[length];
	    in1.read(message, 0, length);
            in1.close();
	    signalg.update(message);
	    byte[] signature = signalg.sign();			
            String beginSignature = "\r\n-----BEGIN PGP SIGNATURE-----\r\n";
	    String endSignature = "\r\n-----END PGP SIGNATURE-----";
            System.out.println("------------BEGIN SIGNATURE------------");                               
            System.out.println(new String(signature, "UTF8"));
            System.out.println("------------END SIGNATURE--------------\n");
            FileOutputStream out5 = new FileOutputStream("C:/Users/" + user3 + "/Desktop/" + user4 + "/server/hashSign.txt");
	    out5.write(message, 0, length);
	    out5.write(beginSignature.getBytes(), 0, beginSignature.length());
	    out5.write(signature, 0, signature.length);
	    out5.write(endSignature.getBytes(), 0, endSignature.length());
	    out5.close();
            assina = new String(signature, "UTF8");
            out.writeUTF(assina);               
                     
            // Gerar chaves
            // INITIAL IV CLIENT TO SERVER
            String hash1 = K + HD + "A" + id2;
            MessageDigest md1 = MessageDigest.getInstance("SHA1"); // Criando o objeto hash
            md1.update(hash1.getBytes()); // Passando dados para o objeto hash criado
            byte [] mdr1 = md1.digest(); // Calcular o resumo da mensagem
            StringBuffer hexString1 = new StringBuffer(); // Convertendo a matriz de bytes no formato HexString
            for (int i = 0;i<mdr1.length;i++) {
                   hexString1.append(Integer.toHexString(0xFF & mdr1[i]));
              }
            System.out.println("::Server calcula as seis chaves de cifras e de autenticação da origem da informação...");                    
            System.out.println("--------------------------------------------");
            System.out.println("------GEN (K||H||string||session_id)--------");
            System.out.println("--------------------------------------------");
            System.out.println("--------Initial IV client to server---------");
            System.out.println("HASH = (k||H||'A'||session_id)");
            System.out.println("HASH = " + hexString1.toString());   
            System.out.println("--------------------------------------------"); 
             
           // INITIAL IV SERVER TO CLIENT
           String hash2 = K + HD + "b" + id2;
           MessageDigest md2 = MessageDigest.getInstance("SHA1"); // Criando o objeto hash
           md2.update(hash2.getBytes()); // Passando dados para o objeto hash criado
           byte [] mdr2 = md2.digest(); // Calcular o resumo da mensagem
           StringBuffer hexString2 = new StringBuffer(); // Convertendo a matriz de bytes no formato HexString
           for (int i = 0;i<mdr2.length;i++) {
                  hexString2.append(Integer.toHexString(0xFF & mdr2[i]));
             }
           System.out.println("-------Initial IV server to client----------");
           System.out.println("HASH = (k||H||'B'||session_id)");
           System.out.println("HASH = " + hexString2.toString());   
           System.out.println("--------------------------------------------"); 


           // ENCRYPTION KEY CLIENT TO SERVER
           String hash3 = K + HD + "C" + id2;
           MessageDigest md3 = MessageDigest.getInstance("SHA1");  // Criando o objeto hash
           md3.update(hash3.getBytes()); // Passando dados para o objeto hash criado
           byte [] mdr3 = md3.digest(); // Calcular o resumo da mensagem
           StringBuffer hexString3 = new StringBuffer(); // Convertendo a matriz de bytes no formato HexString
           for (int i = 0;i<mdr3.length;i++) {
                  hexString3.append(Integer.toHexString(0xFF & mdr3[i]));
             }
           System.out.println("------Encryption key client to server--------");
           System.out.println("HASH = (k||H||'C'||session_id)");
           System.out.println("HASH = " + hexString3.toString());   
           System.out.println("--------------------------------------------"); 

           
           // ENCRYPTION KEY SERVER TO CLIENT
           String hash4 = K + HD + "D" + id2;
           MessageDigest md4 = MessageDigest.getInstance("SHA1"); // Criando o objeto hash
           md4.update(hash4.getBytes()); // Passando dados para o objeto hash criado
           byte [] mdr4 = md4.digest(); // Calcular o resumo da mensagem
           StringBuffer hexString4 = new StringBuffer(); // Convertendo a matriz de bytes no formato HexString
           for (int i = 0;i<mdr4.length;i++) {
                  hexString4.append(Integer.toHexString(0xFF & mdr4[i]));
             }
           System.out.println("------Encryption key server to client--------");
           System.out.println("HASH = (k||H||'D'||session_id)");
           System.out.println("HASH = " + hexString4.toString());   
           System.out.println("--------------------------------------------");


           // INTEGRITY KEY CLIENT TO SERVER
           String hash5 = K + HD + "E" + id2;
           MessageDigest md5 = MessageDigest.getInstance("SHA1"); // Criando o objeto hash
           md5.update(hash5.getBytes()); // Passando dados para o objeto hash criado
           byte [] mdr5 = md5.digest(); // Calcular o resumo da mensagem
           StringBuffer hexString5 = new StringBuffer(); // Convertendo a matriz de bytes no formato HexString
           for (int i = 0;i<mdr5.length;i++) {
                  hexString5.append(Integer.toHexString(0xFF & mdr5[i]));
             }
           System.out.println("------Integrity key client to server--------");
           System.out.println("HASH = (k||H||'E'||session_id)");
           System.out.println("HASH = " + hexString5.toString());   
           System.out.println("--------------------------------------------");

          
           // INTEGRITY KEY SERVER TO CLIENT
           String hash6 = K + HD + "F" + id2;
           MessageDigest md6 = MessageDigest.getInstance("SHA1"); // Criando o objeto hash
           md6.update(hash6.getBytes()); // Passando dados para o objeto hash criado
           byte [] mdr6 = md6.digest(); // Calcular o resumo da mensagem
           StringBuffer hexString6 = new StringBuffer(); // Convertendo a matriz de bytes no formato HexString
           for (int i = 0;i<mdr6.length;i++) {
                  hexString6.append(Integer.toHexString(0xFF & mdr6[i]));
             }
           System.out.println("------Integrity key server to client--------");
           System.out.println("HASH = (k||H||'F'||session_id)");
           System.out.println("HASH = " + hexString6.toString());   
           System.out.println("--------------------------------------------");
           System.out.println("------------fim da simulação----------------");
           }
     
         
           //Tratamento de exceção
           catch (SocketTimeoutException s)
                { 
              System.out.println("Socket timed out!"); 
             } 
           catch (IOException e) { 
            } 
       } 
} 
