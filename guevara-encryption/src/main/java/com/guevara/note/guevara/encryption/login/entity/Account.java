package com.guevara.note.guevara.encryption.login.entity;

/**
 * @author Guevara
 * @date 2021/1/5
 */
public class Account {

    /**
     * 其他账号的字段省略
     */

    private String salt;

    private String hashedCredential;

    public String getSalt() {
        return salt;
    }

    public Account setSalt(String salt) {
        this.salt = salt;
        return this;
    }

    public String getHashedCredential() {
        return hashedCredential;
    }

    public Account setHashedCredential(String hashedCredential) {
        this.hashedCredential = hashedCredential;
        return this;
    }
}
