package com.fptaptech.auth.web;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class InviteForm {

    @NotBlank(message = "{registration.required}")
    @Email(message = "{registration.email}")
    @Size(max = 254, message = "{registration.email.size}")
    private String email;

    @NotBlank(message = "{registration.required}")
    @Size(max = 100, message = "{registration.fullName.size}")
    private String fullName;

    @NotBlank(message = "{registration.required}")
    @Pattern(regexp = "ROLE_LECTURER|ROLE_ADMIN", message = "{invite.role}")
    private String role;

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

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
