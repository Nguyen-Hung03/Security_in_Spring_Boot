package com.fptaptech.auth;

import com.fptaptech.auth.config.AppProperties;
import com.fptaptech.auth.password.CommonPasswords;
import com.fptaptech.auth.password.PasswordPolicy;
import com.fptaptech.auth.totp.CryptoService;
import com.fptaptech.auth.totp.Totp;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import static org.assertj.core.api.Assertions.assertThat;

class SecurityPrimitivesTest {

    @Test
    void totpMatchesRfc6238Vector() {
        String secret = Totp.base32("12345678901234567890".getBytes(StandardCharsets.US_ASCII));
        assertThat(Totp.codeAt(secret, Instant.ofEpochSecond(59))).isEqualTo("287082");
        assertThat(Totp.matches(secret, "287082", Instant.ofEpochSecond(59))).isTrue();
        assertThat(Totp.matches(secret, "000000", Instant.ofEpochSecond(59))).isFalse();
    }

    @Test
    void totpSecretIsEncryptedAtRest() {
        AppProperties properties = new AppProperties();
        properties.getCrypto().setKey("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        CryptoService crypto = new CryptoService(properties);
        String first = crypto.encrypt("JBSWY3DPEHPK3PXP");
        String second = crypto.encrypt("JBSWY3DPEHPK3PXP");
        assertThat(first).doesNotContain("JBSWY3DPEHPK3PXP");
        assertThat(second).isNotEqualTo(first);
        assertThat(crypto.decrypt(first)).isEqualTo("JBSWY3DPEHPK3PXP");
    }

    @Test
    void passwordPolicyRejectsShortCommonAndEmailPasswords() throws Exception {
        PasswordPolicy policy = new PasswordPolicy(new CommonPasswords());
        assertThat(policy.validate("short", "stu@example.com")).isPresent();
        assertThat(policy.validate("password123456", "stu@example.com")).contains("Mật khẩu nằm trong danh sách mật khẩu phổ biến");
        assertThat(policy.validate("alice01#Secret1", "alice01@example.com")).isPresent();
        assertThat(policy.validate("Correct#Horse2026", "stu01@example.com")).isEmpty();
        assertThat(new CommonPasswords().size()).isGreaterThanOrEqualTo(10_000);
    }
}
