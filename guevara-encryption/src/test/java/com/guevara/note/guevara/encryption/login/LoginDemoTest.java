package com.guevara.note.guevara.encryption.login;

import com.guevara.note.guevara.encryption.util.SecurityUtil;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author Guevara
 * @date 2021/1/5
 */
public class LoginDemoTest {

    private LoginDemo loginDemo = new LoginDemo();

    @Test
    public void loginTest() {

        String principle = "1300000000";
        String password = SecurityUtil.md5Hex("v123456789");
        String errorPassword = SecurityUtil.md5Hex("123456");

        loginDemo.createAccount(principle, password);

        Assert.assertSame(loginDemo.login(principle, password), true);
        Assert.assertSame(loginDemo.login(principle, errorPassword), false);
    }
}
