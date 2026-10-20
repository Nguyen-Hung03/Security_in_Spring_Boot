package com.fptaptech.auth.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class ProfileForm {

    @NotBlank(message = "{registration.required}")
    @Size(max = 100, message = "{registration.fullName.size}")
    private String fullName;

    @Pattern(regexp = "^$|^[0-9+\\-.\\s]{8,20}$", message = "{registration.phone}")
    private String phone;

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }
}
