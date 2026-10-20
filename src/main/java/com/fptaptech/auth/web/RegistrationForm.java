package com.fptaptech.auth.web;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@PasswordsMatch
public class RegistrationForm implements PasswordConfirmation {

    @NotBlank(message = "{registration.required}")
    @Email(message = "{registration.email}")
    @Size(max = 254, message = "{registration.email.size}")
    private String email;

    @NotBlank(message = "{registration.required}")
    @Size(max = 100, message = "{registration.fullName.size}")
    private String fullName;

    @NotBlank(message = "{registration.required}")
    @Size(min = 12, max = 64, message = "{registration.password.size}")
    private String password;

    @NotBlank(message = "{registration.required}")
    private String passwordConfirm;

    public void clearPasswords() {
        this.password = "";
        this.passwordConfirm = "";
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
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
        return "RegistrationForm[email=" + email + "]";
    }
}
