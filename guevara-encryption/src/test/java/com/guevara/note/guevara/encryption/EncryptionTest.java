package com.guevara.note.guevara.encryption;

import com.guevara.note.guevara.encryption.util.RSAUtil;
import com.guevara.note.guevara.encryption.util.SecurityUtil;
import org.junit.Test;

import java.util.Map;

/**
 * @author Guevara
 * @date 2020/12/31
 */
public class EncryptionTest {

    @Test
    public void initRsaKay() throws Exception {

        Map<String, Object> keyMap = RSAUtil.initKey();
        //公钥
        byte[] publicKey = RSAUtil.getPublicKey(keyMap);

        //私钥
        byte[] privateKey = RSAUtil.getPrivateKey(keyMap);

        System.out.println("公钥：");
        System.out.println(SecurityUtil.encodeBase64ToString(publicKey));

        System.out.println("私钥：");
        System.out.println(SecurityUtil.encodeBase64ToString(privateKey));
    }
}
