package com.fptaptech.auth.config;

import com.fptaptech.auth.user.UserService;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class AdminBootstrap implements ApplicationRunner {

    private final UserService userService;
    private final AppProperties properties;

    public AdminBootstrap(UserService userService, AppProperties properties) {
        this.userService = userService;
        this.properties = properties;
    }

    @Override
    public void run(ApplicationArguments args) {
        var admin = properties.getAdmin();
        userService.createBootstrapAdmin(admin.getEmail(), admin.getFullName(), admin.getPassword());
    }
}
