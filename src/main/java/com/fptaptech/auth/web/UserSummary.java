package com.fptaptech.auth.web;

public record UserSummary(
        Long id,
        String email,
        String fullName,
        String phone,
        String status,
        String role,
        boolean totpEnabled,
        String createdAt,
        String lockedUntil
) {
}
