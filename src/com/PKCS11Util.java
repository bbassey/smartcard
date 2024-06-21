package com;

import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
//import sun.security.pkcs11.SunPKCS11;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

//import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

//import sun.security.pkcs11.*;

public class PKCS11Util {

    static {

       Security.addProvider(new BouncyCastleProvider());
        //Security.addProvider(new BouncyCastleFipsProvider());
    }
    public static void main(String[] args) throws KeyStoreException, NoSuchProviderException {
        try {

            /* 
            String configName = "/Users/bbassey/work/pkcs11/pkcs11.cfg";

            Provider pkcs11Provider = Security.getProvider("SunPKCS11");

            Provider prov = pkcs11Provider.configure(configName);

            System.out.println("Ben " + prov.getInfo());
            Security.addProvider(prov);

            // Load the KeyStore using the PKCS#11 provider
            String pin = "000000";
            KeyStore keyStore = KeyStore.getInstance("PKCS11", prov);
            keyStore.load(null, pin.toCharArray());

            // List all aliases (private keys) in the KeyStore
            List<String> aliases = Collections.list(keyStore.aliases());
            System.out.println("Aliases in the KeyStore:");
            for (String alias : aliases) {
                System.out.println(alias);
            }

            // Use the first alias (for demonstration purposes)
            if (!aliases.isEmpty()) {
                String alias = aliases.get(0);
                System.out.println("Using alias: " + alias);

                // Retrieve the private key
                PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
                System.out.println("Private Key: " + privateKey);
                // System.out.println("Private Key bytes: " + privateKey.getEncoded());

                // testSignature

                Signature sig = Signature.getInstance("MD5withRSA");
                sig.initSign(privateKey);
                sig.update("this is what I want to sign".getBytes());
                byte[] singature = sig.sign();
                System.out.println("verify sig " + sig.verify(singature));

                // Retrieve the certificate (optional)
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                System.out.println("Certificate: " + cert);
            } else {
                System.out.println("No aliases found in the KeyStore.");
            }
*/
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] sign(String algo, PrivateKey privateKey, byte[] dataToSign)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance(algo);
        sig.initSign(privateKey);
        sig.update(dataToSign);
        return sig.sign();
    }

    public static boolean verifySignature(String algo, PublicKey publicKey, byte[] message, byte[] signature)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        Signature sign = Signature.getInstance(algo);
        sign.initVerify(publicKey);
        sign.update(message);
        return sign.verify(signature);
    }

    public static byte[] encrypt(String algorithm, PrivateKey key, byte[] data)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
                Cipher cipher = Cipher.getInstance(algorithm,"BC");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                cipher.update(data);

        return cipher.doFinal(data);
    }

    public static byte[] decrypt(String algorithm, PublicKey key, byte[] data) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

}