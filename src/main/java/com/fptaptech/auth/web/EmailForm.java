package com.fptaptech.auth.web;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class EmailForm {

    @NotBlank(message = "{registration.required}")
    @Email(message = "{registration.email}")
    @Size(max = 254, message = "{registration.email.size}")
    private String email;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
