package com.fptaptech.auth.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@PasswordsMatch
public class ResetPasswordForm implements PasswordConfirmation {

    @NotBlank(message = "{registration.required}")
    private String token;

    @NotBlank(message = "{registration.required}")
    @Size(min = 12, max = 64, message = "{registration.password.size}")
    private String password;

    @NotBlank(message = "{registration.required}")
    private String passwordConfirm;

    public void clearPasswords() {
        this.password = "";
        this.passwordConfirm = "";
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    @Override
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public String getPasswordConfirm() {
        return passwordConfirm;
    }

    public void setPasswordConfirm(String passwordConfirm) {
        this.passwordConfirm = passwordConfirm;
    }

    @Override
    public String toString() {
        return "ResetPasswordForm";
    }
}
