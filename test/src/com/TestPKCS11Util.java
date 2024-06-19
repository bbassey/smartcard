package com;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

public class TestPKCS11Util {



    @Test
    public void testMD5withRSA_signature() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            IOException, UnrecoverableKeyException, InvalidKeyException, SignatureException {
        String alias = "Certificate for Key Management";
        String algo = "MD5withRSA";
        String dataToSign = "Hello this is just a test";
        String configName = "/Users/bbassey/work/pkcs11/pkcs11.cfg";
        Provider pkcs11Provider = Security.getProvider("SunPKCS11");
        Provider prov = pkcs11Provider.configure(configName);
        System.out.println("Ben " + prov.getInfo());
        Security.addProvider(prov);
        String pin = "000000";
        KeyStore keyStore = KeyStore.getInstance("PKCS11", prov);
        keyStore.load(null, pin.toCharArray());
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
        byte[] signature = PKCS11Util.sign(algo, privateKey, dataToSign.getBytes());
        assertNotNull(signature);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
        assertTrue(PKCS11Util.verifySignature(algo, cert.getPublicKey(), dataToSign.getBytes(), signature));

    }

    @Test
    public void testBadMD5withRSA_signature() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            IOException, UnrecoverableKeyException, InvalidKeyException, SignatureException {
        String alias = "Certificate for Key Management";
        String algo = "MD5withRSA";
        String dataToSign = "Hello this is just a test";
        String configName = "/Users/bbassey/work/pkcs11/pkcs11.cfg";
        Provider pkcs11Provider = Security.getProvider("SunPKCS11");
        Provider prov = pkcs11Provider.configure(configName);
        System.out.println("Ben " + prov.getInfo());
        Security.addProvider(prov);
        String pin = "000000";
        KeyStore keyStore = KeyStore.getInstance("PKCS11", prov);
        keyStore.load(null, pin.toCharArray());
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
        byte[] signature = PKCS11Util.sign(algo, privateKey, dataToSign.getBytes());
        assertNotNull(signature);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
        dataToSign = "this is not the same signature ";
        assertFalse(PKCS11Util.verifySignature(algo, cert.getPublicKey(), dataToSign.getBytes(), signature));

    }



    @Test
    public void testEncryption() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, NoSuchProviderException {
     //   AES/CFB8/NoPadding
    
   
     String message = "encrypt me";
     String alias = "Certificate for Key Management";
     Provider pkcs11Provider = Security.getProvider("SunPKCS11");
     String configName = "/Users/bbassey/work/pkcs11/pkcs11.cfg";
     Provider prov = pkcs11Provider.configure(configName);
     System.out.println("Ben " + prov.getInfo());
     Security.addProvider(prov);
     String pin = "000000";
     KeyStore keyStore = KeyStore.getInstance("PKCS11", prov);
     keyStore.load(null, pin.toCharArray());
     PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
     byte[] encryptedBytes = PKCS11Util.encrypt("RSA",privateKey, message.getBytes());
     System.out.println("encrypted message " + new String (encryptedBytes));
    }
}
