package com.fptaptech.auth.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@PasswordsMatch
public class ChangePasswordForm implements PasswordConfirmation {

    @NotBlank(message = "{registration.required}")
    private String currentPassword;

    @NotBlank(message = "{registration.required}")
    @Size(min = 12, max = 64, message = "{registration.password.size}")
    private String password;

    @NotBlank(message = "{registration.required}")
    private String passwordConfirm;

    public void clearPasswords() {
        this.currentPassword = "";
        this.password = "";
        this.passwordConfirm = "";
    }

    public String getCurrentPassword() {
        return currentPassword;
    }

    public void setCurrentPassword(String currentPassword) {
        this.currentPassword = currentPassword;
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
        return "ChangePasswordForm";
    }
}
