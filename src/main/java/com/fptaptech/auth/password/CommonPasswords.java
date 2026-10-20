package com.fptaptech.auth.password;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

@Component
public class CommonPasswords {

    private static final String[] EXTRA = {
            "password123456",
            "123456789012",
            "qwerty123456",
            "iloveyou1234",
            "passwordpassword"
    };

    private final Set<String> values;

    public CommonPasswords() throws IOException {
        this.values = load();
        if (values.size() < 10_000) {
            throw new IllegalStateException("Danh sách mật khẩu phổ biến phải có ít nhất 10.000 mục");
        }
    }

    public boolean contains(String password) {
        return password != null && values.contains(password.toLowerCase(Locale.ROOT));
    }

    public int size() {
        return values.size();
    }

    private static Set<String> load() throws IOException {
        Set<String> values = new HashSet<>();
        var resource = new ClassPathResource("security/common-passwords.txt");
        try (var reader = new BufferedReader(new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String value = line.trim().toLowerCase(Locale.ROOT);
                if (!value.isEmpty() && !value.startsWith("#")) {
                    values.add(value);
                }
            }
        }
        for (String extra : EXTRA) {
            values.add(extra);
        }
        return Set.copyOf(values);
    }
}
