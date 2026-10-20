package com.fptaptech.auth.security;

import com.fptaptech.auth.audit.AuditEventType;
import com.fptaptech.auth.audit.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

public class AuditLogoutHandler implements LogoutHandler {

    private final AuditService audit;

    public AuditLogoutHandler(AuditService audit) {
        this.audit = audit;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (authentication != null) {
            audit.record(AuditEventType.LOGOUT, authentication.getName(), authentication.getName(), request, "Đăng xuất");
        }
    }
}
