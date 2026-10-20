package com.fptaptech.auth.user;

import java.time.Instant;

public record AuthSnapshot(
        Long id,
        String email,
        String passwordHash,
        AccountStatus status,
        Instant lockedUntil,
        boolean totpEnabled,
        boolean enabled
) {
}
