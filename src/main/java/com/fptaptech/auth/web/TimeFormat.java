package com.fptaptech.auth.web;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public final class TimeFormat {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")
            .withZone(ZoneId.of("Asia/Ho_Chi_Minh"));

    private TimeFormat() {
    }

    public static String format(Instant instant) {
        return instant == null ? "" : FORMATTER.format(instant);
    }
}
