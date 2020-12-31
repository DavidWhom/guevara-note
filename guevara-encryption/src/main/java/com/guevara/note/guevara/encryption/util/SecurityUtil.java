package com.guevara.note.guevara.encryption.util;

import org.apache.commons.codec.Charsets;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @author Guevara
 * @date 2020/3/19
 */
public class SecurityUtil {
    private static final String ALOGRITHM_AES = "AES";
    private static final String AES_TRANSFORMATION = "AES/ECB/PKCS5Padding";

    public SecurityUtil() {
    }

    public static byte[] encodeBase64(byte[] data) {
        return (new Base64()).encode(data);
    }

    public static byte[] encodeBase64(String data) {
        return data != null && !data.isEmpty() ? encodeBase64(data.getBytes(Charsets.UTF_8)) : null;
    }

    public static String encodeBase64ToString(byte[] data) {
        return (new Base64()).encodeToString(data);
    }

    public static String encodeBase64ToString(String data) {
        return data != null && !data.isEmpty() ? encodeBase64ToString(data.getBytes(Charsets.UTF_8)) : null;
    }

    public static byte[] decodeBase64(byte[] data) {
        return (new Base64()).decode(data);
    }

    public static byte[] decodeBase64(String data) {
        return data != null && !data.isEmpty() ? decodeBase64(data.getBytes(Charsets.UTF_8)) : null;
    }

    public static String decodeBase64ToString(byte[] data) {
        return new String(decodeBase64(data), Charsets.UTF_8);
    }

    public static String decodeBase64ToString(String data) {
        return data != null && !data.isEmpty() ? decodeBase64ToString(data.getBytes(Charsets.UTF_8)) : null;
    }

    public static byte[] sha1(String data) {
        return data != null && !data.isEmpty() ? DigestUtils.sha1(data) : null;
    }

    public static byte[] sha1(byte[] data) {
        return data != null && data.length != 0 ? DigestUtils.sha1(data) : null;
    }

    public static String sha1Hex(String data) {
        return data != null && !data.isEmpty() ? DigestUtils.sha1Hex(data) : null;
    }

    public static String sha1Hex(byte[] data) {
        return data != null && data.length != 0 ? DigestUtils.sha1Hex(data) : null;
    }

    public static byte[] sha256(String data) {
        return data != null && !data.isEmpty() ? DigestUtils.sha256(data) : null;
    }

    public static byte[] sha256(byte[] data) {
        return data != null && data.length != 0 ? DigestUtils.sha256(data) : null;
    }

    public static String sha256Hex(String data) {
        return data != null && !data.isEmpty() ? DigestUtils.sha256Hex(data) : null;
    }

    public static String sha256Hex(byte[] data) {
        return data != null && data.length != 0 ? DigestUtils.sha256Hex(data) : null;
    }

    public static byte[] sha512(String data) {
        return data != null && !data.isEmpty() ? DigestUtils.sha512(data) : null;
    }

    public static byte[] sha512(byte[] data) {
        return data != null && data.length != 0 ? DigestUtils.sha512(data) : null;
    }

    public static String sha512Hex(String data) {
        return data != null && !data.isEmpty() ? DigestUtils.sha512Hex(data) : null;
    }

    public static String sha512Hex(byte[] data) {
        return data != null && data.length != 0 ? DigestUtils.sha512Hex(data) : null;
    }

    public static byte[] md5(String data) {
        return data != null && !data.isEmpty() ? DigestUtils.md5(data) : null;
    }

    public static byte[] md5(byte[] data) {
        return data != null && data.length != 0 ? DigestUtils.md5(data) : null;
    }

    public static String md5Hex(String data) {
        return data != null && !data.isEmpty() ? DigestUtils.md5Hex(data) : null;
    }

    public static String md5Hex(byte[] data) {
        return data != null && data.length != 0 ? DigestUtils.md5Hex(data) : null;
    }

    public static String encryptAes(String data, String key) {
        if (data != null && !data.isEmpty() && key != null && !key.isEmpty()) {
            byte[] raw = key.getBytes(Charsets.UTF_8);
            SecretKeySpec secretKeySpec = new SecretKeySpec(raw, "AES");

            try {
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(1, secretKeySpec);
                byte[] encrypted = cipher.doFinal(data.getBytes());
                return (new Base64()).encodeToString(encrypted);
            } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException var6) {
                return data;
            }
        } else {
            return data;
        }
    }

    public static String decryptAes(String data, String key) {
        if (data != null && !data.isEmpty() && key != null && !key.isEmpty()) {
            byte[] raw = key.getBytes(Charsets.UTF_8);
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");

            try {
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(2, skeySpec);
                return new String(cipher.doFinal((new Base64()).decode(data)), Charsets.UTF_8);
            } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException var5) {
                return data;
            }
        } else {
            return data;
        }
    }
}
