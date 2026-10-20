package com.fptaptech.auth.password;

import org.springframework.stereotype.Component;
import java.util.Locale;
import java.util.Optional;

@Component
public class PasswordPolicy {

    public static final int MIN = 12;
    public static final int MAX = 64;

    private final CommonPasswords commonPasswords;

    public PasswordPolicy(CommonPasswords commonPasswords) {
        this.commonPasswords = commonPasswords;
    }

    public Optional<String> validate(String password, String email) {
        if (password == null || password.length() < MIN || password.length() > MAX) {
            return Optional.of("Mật khẩu phải dài từ 12 đến 64 ký tự");
        }
        String lower = password.toLowerCase(Locale.ROOT);
        String mail = email == null ? "" : email.toLowerCase(Locale.ROOT).trim();
        if (!mail.isBlank() && lower.contains(mail)) {
            return Optional.of("Mật khẩu không được chứa email");
        }
        int at = mail.indexOf('@');
        if (at >= 3) {
            String local = mail.substring(0, at);
            if (lower.contains(local)) {
                return Optional.of("Mật khẩu không được chứa username hoặc email");
            }
        }
        if (commonPasswords.contains(lower)) {
            return Optional.of("Mật khẩu nằm trong danh sách mật khẩu phổ biến");
        }
        return Optional.empty();
    }
}
