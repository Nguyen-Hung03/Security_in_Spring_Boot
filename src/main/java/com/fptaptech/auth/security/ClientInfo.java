package com.fptaptech.auth.security;

import jakarta.servlet.http.HttpServletRequest;

public final class ClientInfo {

    private ClientInfo() {
    }

    public static String ip(HttpServletRequest request) {
        if (request == null || request.getRemoteAddr() == null) {
            return "";
        }
        String ip = request.getRemoteAddr();
        return ip.length() > 45 ? ip.substring(0, 45) : ip;
    }

    public static String userAgent(HttpServletRequest request) {
        if (request == null) {
            return "";
        }
        String userAgent = request.getHeader("User-Agent");
        if (userAgent == null || userAgent.isBlank()) {
            return "";
        }
        return userAgent.length() > 512 ? userAgent.substring(0, 512) : userAgent;
    }
}
