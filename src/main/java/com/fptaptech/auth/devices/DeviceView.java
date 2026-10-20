package com.fptaptech.auth.devices;

import java.time.Instant;

public record DeviceView(
        String sessionId,
        String loggedInAt,
        String ip,
        String userAgent,
        boolean current
) {
}
