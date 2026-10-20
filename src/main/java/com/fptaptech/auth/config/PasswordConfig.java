package com.fptaptech.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class PasswordConfig {

    @Bean
    @Profile("!test")
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    @Profile("test")
    @SuppressWarnings("deprecation")
    PasswordEncoder testPasswordEncoder() {
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put("bcrypt", new BCryptPasswordEncoder(4));
        encoders.put("noop", NoOpPasswordEncoder.getInstance());
        DelegatingPasswordEncoder encoder = new DelegatingPasswordEncoder("bcrypt", encoders);
        encoder.setDefaultPasswordEncoderForMatches(encoders.get("bcrypt"));
        return encoder;
    }
}
