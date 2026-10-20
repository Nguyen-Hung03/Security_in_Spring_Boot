package com.fptaptech.auth.totp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;

public final class Totp {

    public static final int DIGITS = 6;
    public static final int PERIOD_SECONDS = 30;
    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final SecureRandom RANDOM = new SecureRandom();

    private Totp() {
    }

    public static String randomSecret() {
        byte[] bytes = new byte[20];
        RANDOM.nextBytes(bytes);
        return base32(bytes);
    }

    public static boolean matches(String secret, String code, Instant now) {
        if (code == null || !code.matches("\\d{6}")) {
            return false;
        }
        long counter = now.getEpochSecond() / PERIOD_SECONDS;
        for (long offset = -1; offset <= 1; offset++) {
            if (code.equals(codeAt(secret, counter + offset))) {
                return true;
            }
        }
        return false;
    }

    public static String codeAt(String secret, Instant now) {
        return codeAt(secret, now.getEpochSecond() / PERIOD_SECONDS);
    }

    static String codeAt(String secret, long counter) {
        try {
            byte[] key = base32Decode(secret);
            byte[] data = ByteBuffer.allocate(8).putLong(counter).array();
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);
            int offset = hash[hash.length - 1] & 0x0f;
            int binary = ((hash[offset] & 0x7f) << 24)
                    | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8)
                    | (hash[offset + 3] & 0xff);
            int otp = binary % 1_000_000;
            return "%06d".formatted(otp);
        } catch (Exception ex) {
            throw new IllegalStateException("Không tạo được mã TOTP", ex);
        }
    }

    public static String base32(byte[] data) {
        StringBuilder out = new StringBuilder();
        int buffer = 0;
        int bits = 0;
        for (byte value : data) {
            buffer = (buffer << 8) | (value & 0xff);
            bits += 8;
            while (bits >= 5) {
                out.append(BASE32.charAt((buffer >> (bits - 5)) & 31));
                bits -= 5;
            }
        }
        if (bits > 0) {
            out.append(BASE32.charAt((buffer << (5 - bits)) & 31));
        }
        return out.toString();
    }

    static byte[] base32Decode(String secret) {
        String value = secret.trim().replace("=", "").replace(" ", "").toUpperCase();
        int buffer = 0;
        int bits = 0;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < value.length(); i++) {
            int index = BASE32.indexOf(value.charAt(i));
            if (index < 0) {
                throw new IllegalArgumentException("Secret TOTP không hợp lệ");
            }
            buffer = (buffer << 5) | index;
            bits += 5;
            if (bits >= 8) {
                out.write((buffer >> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        return out.toByteArray();
    }
}
