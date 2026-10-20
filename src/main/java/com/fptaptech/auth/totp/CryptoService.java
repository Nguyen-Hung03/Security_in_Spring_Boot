package com.fptaptech.auth.totp;

import com.fptaptech.auth.config.AppProperties;
import org.springframework.stereotype.Component;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@Component
public class CryptoService {

    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;

    private final SecretKeySpec key;
    private final SecureRandom random = new SecureRandom();

    public CryptoService(AppProperties properties) {
        this.key = new SecretKeySpec(decodeKey(properties.getCrypto().getKey()), "AES");
    }

    public String encrypt(String plaintext) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(encrypted, 0, out, iv.length, encrypted.length);
            return Base64.getEncoder().encodeToString(out);
        } catch (Exception ex) {
            throw new IllegalStateException("Không mã hóa được bí mật", ex);
        }
    }

    public String decrypt(String ciphertext) {
        try {
            byte[] all = Base64.getDecoder().decode(ciphertext);
            byte[] iv = new byte[IV_LENGTH];
            byte[] encrypted = new byte[all.length - IV_LENGTH];
            System.arraycopy(all, 0, iv, 0, IV_LENGTH);
            System.arraycopy(all, IV_LENGTH, encrypted, 0, encrypted.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (Exception ex) {
            throw new IllegalStateException("Không giải mã được bí mật", ex);
        }
    }

    static byte[] decodeKey(String configured) {
        if (configured == null || configured.isBlank()) {
            throw new IllegalStateException("Thiếu khóa mã hóa APP_ENCRYPTION_KEY");
        }
        String value = configured.trim();
        byte[] raw = value.matches("(?i)[0-9a-f]{64}")
                ? HexFormat.of().parseHex(value)
                : Base64.getDecoder().decode(value);
        if (raw.length != 32) {
            throw new IllegalStateException("APP_ENCRYPTION_KEY phải dài đúng 32 byte");
        }
        return raw;
    }
}
