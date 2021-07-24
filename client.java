import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.KeyPair;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.util.Scanner;

  
public class client { 
          private PublicKey pubKey;
    public static void main(String[] args) 
    { 
        try { 
            String pstr, gstr, estr; //Declaração de variavéis
            String serverName = "localhost"; 
            int port = 8088, opcao; 
            String Is, Vs, Ks, assina, Is2, Is3, Is4;
            String Ic = "Client Hello";
            String Vc = "SSH2";
            String id, pass, id1;
            
            // Declare p, g, and Key secret of client e mensagem inicial
            int p = 23; //Módulo p
            int g = 7; //Gerador g
            int x = 4; //Chave secreta client
            double K, serverf; 
  
            // Estabelecer uma conexão
            System.out.println("\n");
            System.out.println("-----------Bem-vindo ao  Simulador client SSH2-----------");
            System.out.println("Conectado ao " + serverName + " na porta " + port); 
            Socket client = new Socket(serverName, port); //Construtor lado Client 
            System.out.println("----------------------------------------------");
            System.out.println("IP:Porta " + client.getRemoteSocketAddress()); 
  
            // Envia dados para server
            OutputStream outToServer = client.getOutputStream(); 
            DataOutputStream out = new DataOutputStream(outToServer); 
            // Recebe dados 
            DataInputStream in = new DataInputStream(client.getInputStream());
             
            //Identificador do simulador
            Scanner scan = new Scanner(System.in);
            System.out.println("Usuário do simulador SSH:");
            id = scan.next();
            out.writeUTF(id);
            Is2 = in.readUTF(); 
            if(Is2.equals("ok")){
                  System.out.println("Conexão estabelecida com servidor");
                  System.out.println("---------------------------------------");
                 }else{
                  Is3 = in.readUTF();
                  Is4 = in.readUTF();
                  System.out.println("Server --- > Client:" + Is3);
                  System.out.println("Server --- > Client:" + Is4);
                  System.exit(0);
                }
            System.out.println("Usuário Máquina Client:");
            String user3 = scan.next();
            out.writeUTF(user3);
            out.flush();
            System.out.println("Diretório client:");
            String user4 = scan.next();
            out.writeUTF(user4);
            out.flush();                      
            File file = new File("C:/Users/" + user3 + "/Desktop/"+ user4 + "/client"); //criar o diretório client
            file.mkdir();
            File file2 = new File("C:/Users/" + user3 + "/Desktop/"+ user4 +"/client/keys"); //criar o diretório client keys
            file2.mkdir();
            
            //Mensagem inicial
            out.writeUTF("Client Hello");
            out.flush();
            out.writeUTF("SSH2");
            out.flush();                    
            pstr = Integer.toString(p); 
            out.writeUTF(pstr); // Envia p        
            gstr = Integer.toString(g); 
            out.writeUTF(gstr); // Envia g   
            double e = ((Math.pow(g, x)) % p); // calcular e = g^x mod p
            estr = Double.toString(e); 
            out.writeUTF(estr); // Envia e         
                                  
            // Client Private Key 
            System.out.println("--------------------------------------------");
            System.out.println("Client Private Key x = " + x);                               
            System.out.println("--------------------------------------------");
            System.out.println("Client < --- > Server : P = " + p);//Módulo p
            System.out.println("Client < --- > Server:  G = " + g); //Gerador g
            System.out.println(":: Calcula Client Public Key (e = g^x mod p): e = " + estr);
  
            // Receber dados do server mensagem inicial, versão do protocolo, chave pública RSA
            //DataInputStream in = new DataInputStream(client.getInputStream());  
            serverf = Double.parseDouble(in.readUTF());
            System.out.println("--------------------------------------------"); 
            System.out.println("::Recebendo dados do server..."); 
            System.out.println("::Server --- > Client...");
            System.out.println("Server --- > Client:   Server Public Key  f = " + serverf); 
            //System.out.println("--------------------------------------------");
            Is = in.readUTF(); 
            System.out.println("Server --- > Client: Mensagem Inicial  Is =" + Is); 
            Vs = in.readUTF(); 
            System.out.println("Server --- > Client: Versão do Protocolo  Vs =" + Vs);               
            System.out.println("--------------------------------------------");
            K = ((Math.pow(serverf, x)) % p); // cliente calcula K = f^x mod p
            //System.out.println("--------------------------------------------");
            System.out.println("::Client calcula (K = f^x mod p) ...");
            System.out.println("Chave secreta K= " + K); 
            //System.out.println("\n"); 
            System.out.println("--------------------------------------------\n"); 
            System.out.println("Recebendo dados do server: chave pública RSA e Assinatura digital..."); 
            System.out.println("::Server --- > Client...");
            System.out.println("-------------BEGIN RSA PUBLIC KEY------------");
            Ks = in.readUTF();
            //ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream("public.key"));
	    //PublicKey pubkey = (PublicKey) keyIn.readObject();
            System.out.println(Ks);
            System.out.println("-------------END RSA PUBLIC KEY------------\n");
            
            //Recebe do server a assinatura
            System.out.println("-------------BEGIN SIGNATURE-----------------"); 
            //System.out.println("::Server --- > Client : Assinatura digital do H\n");
            assina = in.readUTF();                                  
            System.out.println(assina);
            System.out.println("-------------END SIGNATURE-------------------");
            System.out.println("\n");

            //Calcula o valor de Hash             
            System.out.println("::Client calcula valor de Hash....");
            String hash = Vc  + Vs + Is + Ic + Ks + estr + serverf + K;
            //System.out.println(hash);
            MessageDigest md = MessageDigest.getInstance("SHA1");  // Criando o objeto hash
            md.update(hash.getBytes()); // Passando dados para o objeto hash criado
            byte [] mdr = md.digest(); // Calcular o resumo da mensagem
            StringBuffer hexString = new StringBuffer(); // Convertendo a matriz de bytes no formato HexString
            for (int i = 0;i<mdr.length;i++) {
                   hexString.append(Integer.toHexString(0xFF & mdr[i]));
              }
            String HD = hexString.toString();
            System.out.println("H = (Vc||Vs||Ic||Is||Ks||e||f||K)");
            System.out.println("H = " + hexString.toString());  
            System.out.println("--------------------------------------------"); 

            //Session_id
            id1 = HD;            

            //Verifica a assinatura digital 
            ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream("C:/Users/" + user3 + "/Desktop/" + user4 +"/client/keys/privada.key"));
	    PrivateKey privkey = (PrivateKey) keyIn.readObject();
	    keyIn.close();
            Signature signalg = Signature.getInstance("SHA256withRSA");
	    signalg.initSign(privkey);             
            byte[] bytes = hash.getBytes();
            signalg.update(bytes);                    
            ObjectInputStream keyIn3= new ObjectInputStream(new FileInputStream("C:/Users/" + user3 + "/Desktop/" + user4 + "/client/keys/public.key"));
            PublicKey pubkey = (PublicKey) keyIn3.readObject();
	    keyIn3.close();
            byte[] signature = signalg.sign();            
            Signature verifyalg = Signature.getInstance("SHA256withRSA");	        		
            verifyalg.initVerify(pubkey);
            verifyalg.update(bytes);
            boolean bool = verifyalg.verify(signature); 
            System.out.println("::Client verifica a assinatura....");     
            if(bool) {
                  System.out.println("::Assinatura OK.\n");   
            } else {
                  System.out.println("::Assinatura não OK:\n");
            }

             
	    //Calcula as chaves de cifras e de autenticação da origem da informação                                 
            // INITIAL IV CLIENT TO SERVER
            String hash1 = K + HD + "A" + id1;
            MessageDigest md1 = MessageDigest.getInstance("SHA1");  // Criando o objeto hash
            md1.update(hash1.getBytes()); // Passando dados para o objeto hash criado
            byte [] mdr1 = md1.digest(); // Calcular o resumo da mensagem
            StringBuffer hexString1 = new StringBuffer(); // Convertendo a matriz de bytes no formato HexString
            for (int i = 0;i<mdr1.length;i++) {
                   hexString1.append(Integer.toHexString(0xFF & mdr1[i]));
              }
            System.out.println("::Client calcula as seis chaves de cifras e de autenticação da origem da informação...");
            System.out.println("--------------------------------------------");
            System.out.println("------GEN (K||H||string||session_id)--------");
            System.out.println("--------------------------------------------");
            System.out.println("--------Initial IV client to server---------");
            System.out.println("HASH = (k||H||'A'||session_id)");
            System.out.println("HASH = " + hexString1.toString());   
            System.out.println("--------------------------------------------"); 
             
           // INITIAL IV SERVER TO CLIENT
           String hash2 = K + HD + "b" + id1;
           MessageDigest md2 = MessageDigest.getInstance("SHA1");  // Criando o objeto hash
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
           String hash3 = K + HD + "C" + id1;
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
           String hashc = hexString3.toString();
           System.out.println("---------------------------------------------"); 

           
           // ENCRYPTION KEY SERVER TO CLIENT
           String hash4 = K + HD + "D" + id1;
           MessageDigest md4 = MessageDigest.getInstance("SHA1");  // Criando o objeto hash
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
           String hash5 = K + HD + "E" + id1;
           MessageDigest md5 = MessageDigest.getInstance("SHA1");  // Criando o objeto hash
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
           String hash6 = K + HD + "F" + id1;
           MessageDigest md6 = MessageDigest.getInstance("SHA1");  // Criando o objeto hash
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
                     




                    
              } //Tratamento de exceção
           catch (Exception e) { 
                e.printStackTrace(); 
          } 
     }
} 
