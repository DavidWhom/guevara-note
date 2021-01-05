package com.guevara.note.guevara.encryption.login;

import com.guevara.note.guevara.encryption.login.entity.Account;
import com.guevara.note.guevara.encryption.util.SecurityUtil;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * @author Guevara
 * @date 2021/1/5
 */
public class LoginDemo {

    private static Map<String, Account> DB_ACCOUNTS = new HashMap<>();

/**
 * 创建账号
 * @param principle 用户账号
 * @param frontendPassword 用户密码，用户在前端输入的密码以 md5 的形式传到后端
 */
public void createAccount(String principle, String frontendPassword) {

    Account account = md5WithSalt(frontendPassword);

    // 保存账号，模拟数据库保存
    DB_ACCOUNTS.put(principle, account);
}

    /**
     * 登录逻辑
     * @param principle 用户账号
     * @param frontendPassword 用户密码，用户在前端输入的密码以 md5 的形式传到后端
     * @return true-登录成功，false-登录失败
     */
    public Boolean login(String principle, String frontendPassword) {

        Account account = DB_ACCOUNTS.get(principle);
        if (account == null) {
            return false;
        }

        return account.getHashedCredential()
                .equals(SecurityUtil.md5Hex(account.getSalt() + frontendPassword));
    }

    // ~ private
    private Account md5WithSalt(String frontendPassword) {

        Account account = new Account();
        // 随机字符串做盐
        account.setSalt(UUID.randomUUID().toString());
        account.setHashedCredential(SecurityUtil.md5Hex(account.getSalt() + frontendPassword));

        return account;
    }
}
