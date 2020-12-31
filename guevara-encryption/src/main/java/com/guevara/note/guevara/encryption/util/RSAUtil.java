package com.guevara.note.guevara.encryption.util;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Guevara
 * @date 2020/3/19
 */
public class RSAUtil {
    public static final String KEY_ALGORITHM = "RSA";
    private static final int KEY_SIZE = 1024;
    private static final String PUBLIC_KEY = "RSAPublicKey";
    private static final String PRIVATE_KEY = "RSAPrivateKey";

    public RSAUtil() {
    }

    public static Map<String, Object> initKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap();
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }

    public static byte[] encryptByPrivateKey(byte[] data, byte[] key) throws Exception {
        return encryptOrDecryptByPrivateKey(data, key, 1);
    }

    public static byte[] encryptByPublicKey(byte[] data, byte[] key) throws Exception {
        return encryptOrDecryptByPublicKey(data, key, 1);
    }

    public static byte[] decryptByPrivateKey(byte[] data, byte[] key) throws Exception {
        return encryptOrDecryptByPrivateKey(data, key, 2);
    }

    public static byte[] decryptByPublicKey(byte[] data, byte[] key) throws Exception {
        return encryptOrDecryptByPublicKey(data, key, 2);
    }

    public static byte[] getPrivateKey(Map<String, Object> keyMap) {
        Key key = (Key)keyMap.get(PRIVATE_KEY);
        return key.getEncoded();
    }

    public static byte[] getPublicKey(Map<String, Object> keyMap) {
        Key key = (Key)keyMap.get(PUBLIC_KEY);
        return key.getEncoded();
    }

    public static RSAPublicKey getPublicKeyFromStr(String base64PublicKeyStr) throws Exception {
        if (base64PublicKeyStr != null && !base64PublicKeyStr.isEmpty()) {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(SecurityUtil.decodeBase64(base64PublicKeyStr));
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            return (RSAPublicKey)keyFactory.generatePublic(keySpec);
        } else {
            return null;
        }
    }

    public static RSAPrivateKey getPrivateKeyFromStr(String base64PrivateKeyStr) throws Exception {
        if (base64PrivateKeyStr != null && !base64PrivateKeyStr.isEmpty()) {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(SecurityUtil.decodeBase64(base64PrivateKeyStr));
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            return (RSAPrivateKey)keyFactory.generatePrivate(keySpec);
        } else {
            return null;
        }
    }

    private static byte[] encryptOrDecryptByPrivateKey(byte[] data, byte[] key, int mode) throws Exception {
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(mode, privateKey);
        return cipher.doFinal(data);
    }

    private static byte[] encryptOrDecryptByPublicKey(byte[] data, byte[] key, int mode) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(key);
        PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(mode, pubKey);
        return cipher.doFinal(data);
    }
}
